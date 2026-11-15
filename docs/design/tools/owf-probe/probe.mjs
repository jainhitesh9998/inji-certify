#!/usr/bin/env node
/*
 * Paradym-equivalent check of an mDL's status list (M-11f; owner decision D-M11-8 (b)).
 *
 * Paradym Wallet verifies an mDL with @owf/mdoc 0.9.1 and, without dedicated status certificates, requires the status
 * list's validated certificate chain to equal the mDL's issuance chain (Credo `assertMdocStatusListChainsMatchIssuanceChain`,
 * mdocUtil.ts:76-115; Paradym's `paradym.ts:63-67` hands `[certificateChain[last]]` in as `{issuance: [...]}`). That is
 * the failure the demo saw (G23): a list signed outside the mDL's chain was refused after the import. This probe runs
 * that library, at the exact versions Paradym locks, over the samples the Java harness writes, so a list Paradym would
 * refuse cannot merge.
 *
 *   npm ci && node probe.mjs ../../../../certify-service/target/mdoc-samples   # CI: every *.mdoc with a sidecar
 *   node probe.mjs <directory>                                                 # locally, the same
 *
 * The tree is installed with `install-strategy=nested` (.npmrc), so each package keeps the dependency versions Paradym's
 * pnpm lockfile pins (the versions match; pnpm may still load one shared `cbor-x` instance): `@owf/token-status-list` 0.6.0 gets the `@owf/cose` 0.6.0 it pins and its own `cbor-x`,
 * beside `@owf/mdoc` 0.9.1's `@owf/cose` 0.6.2. `npm`'s flat node_modules instead keeps one `@owf/cose` beside the
 * other, both register their CBOR tag-24 decoders in the one deduped `cbor-x`, and the copy that loads last then decodes
 * tag 24 for both, so `IssuerSigned.decode` sees a `DataItem` that is not its own class. `@owf/cose` 0.6.2 is also a
 * top-level dependency because the probe itself imports it.
 *
 * The two checks per sample:
 *   1. `@owf/mdoc`'s `Holder.verifyIssuerSigned` accepts the credential with `trustedCertificates: [{issuance: [top]}]`,
 *      fetching the sample's `.statuslist.cwt` sidecar for the status list. This is the library Paradym verifies with;
 *      it refuses a JWT list (JwtNotSupportForStatusListError), a list whose chain does not reach the trusted
 *      certificate, and a list whose signature does not verify or whose bit at `idx` says revoked.
 *   2. Credo's equal-chain rule, reimplemented here in fifteen lines over the two CBOR structures: the list's `x5chain`
 *      must be the IssuerAuth's `x5chain`, certificate for certificate.
 *
 * Then the negative controls: in-memory mutants of the `-oid4vci` sample, each of which must fail the check it is aimed
 * at, so a probe whose signature, chain or media-type check regressed cannot stay green. The samples are signed by the
 * issuer's Document Signer, whose private key no tool here has, so a mutant list cannot be validly re-signed: the
 * tampered-`lst` control proves the claims are covered by the signature (and `-revoked` proves the library reads the bit,
 * since its PASS is the library's own "not Valid (0)" refusal).
 *
 * Exit status 1 when any sample or any control fails, naming it and the reason. The MdocContext @owf/mdoc asks for is
 * built from Node's own crypto and @owf/cose (`@owf/mdoc` ships none: its reference context lives in the upstream tests
 * and pulls @peculiar/x509, jose, @noble/* and hpke, which nothing here needs).
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import zlib from 'node:zlib'

import { CoseKey, ProtectedHeaders, Sign1, cborDecode, cborEncode } from '@owf/cose'
import { Holder, IssuerSigned } from '@owf/mdoc'

/** draft-ietf-oauth-status-list-21 section 8.1: the one media type an mDoc's status list is served as. */
const CWT = 'application/statuslist+cwt'
/** The media type of a JWT list: the control's body, and what @owf/token-status-list refuses (D-M11-2). */
const JWT = 'application/statuslist+jwt'
const JWT_BODY = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln')
const HASH_BY_CURVE = { 'P-256': 'sha256', 'P-384': 'sha384', 'P-521': 'sha512' }

const x509 = {
  async verifyCertificateChain({ trustedCertificates, x5chain, now }) {
    if (!x5chain || x5chain.length === 0) throw new Error('the x5chain is empty')
    const at = now ?? new Date()
    const certificates = x5chain.map((der) => new crypto.X509Certificate(Buffer.from(der)))
    const trusted = (trustedCertificates ?? []).map((der) => new crypto.X509Certificate(Buffer.from(der)))
    // the anchor Paradym trusts for our HAIP chain (no IACA in the x5chain) is the presented leaf itself
    const index = certificates.findIndex((certificate) => trusted.some((t) => t.raw.equals(certificate.raw)))
    if (trusted.length > 0 && index === -1) {
      throw new Error('no trusted certificate was found in the chain')
    }
    for (let i = 0; i < certificates.length; i++) {
      const certificate = certificates[i]
      const issuer = certificates[i + 1] ?? (index === certificates.length - 1 ? certificates[i] : undefined)
      if (issuer && !issuer.raw.equals(certificate.raw) && !certificate.checkIssued(issuer)) {
        throw new Error(`certificate ${certificate.subject} is not issued by ${issuer.subject}`)
      }
      if (issuer && !issuer.raw.equals(certificate.raw) && !certificate.verify(issuer.publicKey)) {
        throw new Error(`the signature of certificate ${certificate.subject} is invalid`)
      }
      if (at < certificate.validFromDate || at > certificate.validToDate) {
        throw new Error(`certificate ${certificate.subject} is not valid at ${at.toISOString()}`)
      }
    }
    return { chain: certificates.slice().reverse().map((certificate) => new Uint8Array(certificate.raw)) }
  },

  async getPublicKey({ certificate }) {
    const parsed = new crypto.X509Certificate(Buffer.from(certificate))
    return CoseKey.fromJwk(parsed.publicKey.export({ format: 'jwk' }))
  },

  getSubjectNameField({ certificate, field }) {
    const parsed = new crypto.X509Certificate(Buffer.from(certificate))
    const name = field === 'issuer' ? parsed.issuer : parsed.subject
    return name.split('\n').map((line) => line.slice(line.indexOf('=') + 1))
  },

  async getCertificateData({ certificate }) {
    const parsed = new crypto.X509Certificate(Buffer.from(certificate))
    return {
      issuerName: parsed.issuer,
      subjectName: parsed.subject,
      pem: parsed.toString(),
      serialNumber: parsed.serialNumber,
      thumbprint: parsed.fingerprint256.replaceAll(':', '').toLowerCase(),
      notBefore: parsed.validFromDate,
      notAfter: parsed.validToDate
    }
  }
}

const cose = {
  sign1: {
    async verify({ signature, key, toBeVerified }) {
      const jwk = key instanceof CoseKey ? key.jwk : key
      const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' })
      const hash = HASH_BY_CURVE[jwk.crv] ?? 'sha256'
      return crypto.verify(hash, Buffer.from(toBeVerified), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature))
    }
  },
  mac0: {
    async verify() {
      throw new Error('this probe verifies signed mDLs only')
    }
  }
}

const context = (statusList) => ({
  fetch: async (input) => {
    const url = typeof input === 'string' ? input : input.url
    if (url !== statusList.uri) throw new Error(`the probe serves only ${statusList.uri}, asked for ${url}`)
    return new Response(statusList.body, { status: 200, headers: { 'content-type': statusList.contentType } })
  },
  crypto: {
    random: (length) => crypto.randomBytes(length),
    async digest({ digestAlgorithm, bytes }) {
      return new Uint8Array(crypto.createHash(digestAlgorithm.replace('-', '').toLowerCase()).update(Buffer.from(bytes)).digest())
    }
  },
  cose,
  x509
})

function sidecar(directory, name, suffix) {
  const file = path.join(directory, name + suffix)
  return fs.existsSync(file) ? fs.readFileSync(file) : undefined
}

/** Credo's rule (mdocUtil.ts:76-115): certificate for certificate, or Paradym refuses the mDL. */
function equalChains(issuerAuthChain, statusListChain) {
  if (issuerAuthChain.length !== statusListChain.length) return false
  return issuerAuthChain.every((der, i) => Buffer.from(der).equals(Buffer.from(statusListChain[i])))
}

/** The `status.status_list` entry the MSO carries, read from the raw MSO the IssuerAuth payload holds. */
function statusEntry(issuerSigned) {
  const mso = cborDecode(new Uint8Array(issuerSigned.issuerAuth.payload))
  const status = mso instanceof Map ? mso.get('status') : undefined
  return status instanceof Map ? status.get('status_list') : undefined
}

// ---- the two checks over one credential and the list its MSO names, as names the controls can aim at ---------------

const CONTENT_TYPE_CHECK = `the list is served as ${CWT}`
const ACCEPT_CHECK = '@owf/mdoc 0.9.1 verifies the mDL and its status list (trusted: the presented top certificate)'
const EQUAL_CHAIN_CHECK = "Credo's equal-chain rule: the list's x5chain is the IssuerAuth's"
const statusCheck = (expectedStatus) => `@owf/mdoc 0.9.1 reports the status the sample declares (${expectedStatus})`

/**
 * One credential, one list body: [{name, ok, detail}], the media type check first. Never throws: a list whose sidecar
 * does not even decode is one failed check, not a crash that hides the samples after it.
 */
async function judge({ issuerSigned, list, contentType, expectedStatus }) {
  const checks = []
  const record = (name, ok, detail = '') => checks.push({ name, ok, detail })
  // recorded, never a reason to stop: Paradym has no media-type pre-check of its own, @owf/token-status-list 0.6.0
  // does it, so the library is always called and its own refusal is what a control exercises
  record(CONTENT_TYPE_CHECK, contentType === CWT, `Content-Type ${contentType}`)
  const issuanceChain = issuerSigned.issuerAuth.x5chain ?? []
  const entry = statusEntry(issuerSigned)
  const uri = entry instanceof Map ? entry.get('uri') : undefined
  try {
    await Holder.verifyIssuerSigned(
      {
        issuerSigned,
        // the top of the presented chain, for both halves: Paradym's `getTrustedCertificatesForVerification` returns
        // `[certificateChain[last]]` and Credo's receipt requires the list's validated chain to equal the issuance
        // chain, and @owf/mdoc 0.9.1 reads the status anchors from the trusted entry's `status` list (index.mjs:2874)
        trustedCertificates: [{
          issuance: [issuanceChain[issuanceChain.length - 1]],
          status: [issuanceChain[issuanceChain.length - 1]]
        }],
        skewSeconds: 300
      },
      // the status list is fetched through the context: the sidecar the producer recorded, under the media type it
      // was served with, so a JWT body is what @owf/token-status-list refuses
      context({ uri, body: list, contentType })
    )
    if (expectedStatus === 0) {
      record(ACCEPT_CHECK, true)
    } else {
      record(statusCheck(expectedStatus), false, 'the credential verified, but its list reports the status as revoked')
    }
  } catch (e) {
    const revokedAsDeclared = expectedStatus === 1 && /not Valid \(0\)/.test(e.message)
    record(expectedStatus === 0 ? ACCEPT_CHECK : statusCheck(expectedStatus), revokedAsDeclared, `${e.name}: ${e.message}`)
  }
  let statusListChain = []
  try {
    // after the library: a sidecar that is not a COSE_Sign1 is the library's refusal above, and here an empty chain
    statusListChain = Sign1.decode(new Uint8Array(list)).certificateChain ?? []
  } catch (e) {
    statusListChain = []
  }
  const equal = equalChains(issuanceChain, statusListChain)
  record(EQUAL_CHAIN_CHECK, equal, equal ? '' : `list ${statusListChain.length} certificate(s), mDL ${issuanceChain.length}`)
  return checks
}

const failures = []

function check(sample, name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${sample}: ${name}${detail ? ': ' + detail : ''}`)
  if (!ok) failures.push(`${sample}: ${name}${detail ? ': ' + detail : ''}`)
}

async function probe(directory) {
  const samples = fs.readdirSync(directory).filter((file) => file.endsWith('.mdoc') && file.includes('MdocStatusListSampleTest')).sort()
  if (samples.length === 0) {
    console.error(`no mDoc samples under ${directory}`)
    return 1
  }
  for (const file of samples) {
    const name = file.slice(0, -'.mdoc'.length)
    const list = sidecar(directory, name, '.statuslist.cwt')
    if (!list) {
      console.log(`SKIP ${name}: no .statuslist.cwt sidecar (the MSO carries no status entry)`)
      continue
    }
    const contentType = sidecar(directory, name, '.statuslist.ct')?.toString('utf8').trim()
    const gaps = sidecar(directory, name, '.gaps')?.toString('utf8') ?? ''
    if (gaps.includes('issuerAuth.untagged:tagged')) {
      // the draft-13 compatibility shape wraps issuerAuth in tag 18, which @owf/mdoc 0.9.1 refuses before it reads any
      // status list: that surface's deviation is declared in the sample's own .gaps, not a status-list finding
      console.log(`SKIP ${name}: the sample declares issuerAuth.untagged:tagged (the draft-13 wrapper)`)
      continue
    }
    const issuerSigned = IssuerSigned.decode(new Uint8Array(fs.readFileSync(path.join(directory, file))))
    // a sample that declares the status its list reports (0 VALID, 1 INVALID: M-11e's revoked sample) is expected to
    // fail the holder's verification on the revocation, and nothing else
    const expectedStatus = Number(sidecar(directory, name, '.statuslist.status')?.toString('utf8').trim() ?? '0')
    for (const result of await judge({ issuerSigned, list, contentType, expectedStatus })) {
      check(name, result.name, result.ok, result.detail)
    }
  }
  if (failures.length > 0) {
    console.error(`\n${failures.length} failure(s)`)
    return 1
  }
  return 0
}

// ---- the negative controls: in-memory mutants of the sample, each of which must fail the check it is aimed at -----

/** The DER of a PEM certificate (the samples' `.iaca.pem` sidecar). */
function pemToDer(pem) {
  return new Uint8Array(Buffer.from(pem.toString('utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'))
}

/** The Sig_structure signature of a COSE_Sign1 under the given protected headers, as the wire carries it (r || s). */
function sign(protectedHeaders, payload, privateKey) {
  const toBeSigned = Sign1.toBeSigned({ payload, protectedHeaders })
  return new Uint8Array(crypto.sign('sha256', Buffer.from(toBeSigned), { key: privateKey, dsaEncoding: 'ieee-p1363' }))
}

/** The same list, signed by another key: the encoding the samples carry, minus the signature. */
function reSign(original, privateKey, protectedHeaders = original.protectedHeaders) {
  return Sign1.create({
    protectedHeaders,
    unprotectedHeaders: original.unprotectedHeaders,
    payload: original.payload,
    signature: sign(protectedHeaders, original.payload, privateKey)
  }).encode()
}

/** The list's protected headers with another `x5chain` (33), the `typ` and the `alg` kept. */
function withChain(original, chain) {
  const headers = cborDecode(original.protectedHeaders.encodedStructure)
  headers.set(33, chain)
  return ProtectedHeaders.create({ protectedHeaders: headers })
}

/** The list's claims with the bit at `idx` set after signing, so the payload no longer matches the signature. */
function tamperedLst(original, idx) {
  const claims = cborDecode(original.payload)
  const statusList = claims.get(65533)
  const raw = Buffer.from(zlib.inflateSync(Buffer.from(statusList.get('lst'))))
  raw[idx >> 3] |= 1 << (idx & 7)
  statusList.set('lst', new Uint8Array(zlib.deflateSync(raw)))
  return Sign1.create({
    protectedHeaders: original.protectedHeaders,
    unprotectedHeaders: original.unprotectedHeaders,
    payload: new Uint8Array(cborEncode(claims)),
    signature: original.signature
  }).encode()
}

async function controls(directory) {
  // the M-11e producer's sample: the one whose MSO carries a status entry and which has the list beside it (the golden
  // samples of the same surface carry none, and hold no list to mutate)
  const withList = (suffix) => fs.readdirSync(directory)
    .filter((candidate) => candidate.endsWith(`${suffix}.mdoc`))
    .filter((candidate) => fs.existsSync(path.join(directory, candidate.slice(0, -'.mdoc'.length) + '.statuslist.cwt')))
    .sort()[0]
  const file = withList('-oid4vci')
  const revokedFile = withList('-revoked')
  if (!file || !revokedFile) {
    const missing = !file ? '-oid4vci' : '-revoked'
    console.error(`\nFAIL control: no ${missing} sample with a .statuslist.cwt sidecar under ${directory} to mutate`)
    failures.push(`control: no ${missing} sample to mutate`)
    return 1
  }
  const name = file.slice(0, -'.mdoc'.length)
  const issuerSigned = IssuerSigned.decode(new Uint8Array(fs.readFileSync(path.join(directory, file))))
  const original = Sign1.decode(new Uint8Array(sidecar(directory, name, '.statuslist.cwt')))
  // the same list after the credential was revoked: the same Document Signer's chain, the same uri and idx, the bit set
  const revoked = sidecar(directory, revokedFile.slice(0, -'.mdoc'.length), '.statuslist.cwt')
  const iacaPem = sidecar(directory, name, '.iaca.pem')
  const entry = statusEntry(issuerSigned)
  const expectedStatus = Number(sidecar(directory, name, '.statuslist.status')?.toString('utf8').trim() ?? '0')
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  let failed = 0
  const mutants = [
    {
      // check 1 must be the signature over the claims: this key did not sign the list the DSC certificate names
      name: 're-signed by another key with the DSC certificate in the x5chain',
      expected: [ACCEPT_CHECK],
      reason: /signature of the CWT could not be verified/,
      list: () => reSign(original, other.privateKey)
    },
    {
      // check 1 must read the bit at idx: this list is validly signed by the same Document Signer, and revoked
      name: `the list says the credential is revoked (the -revoked sample's list, bit ${entry.get('idx')} set)`,
      expected: [ACCEPT_CHECK],
      reason: /not Valid \(0\)/,
      list: () => revoked
    },
    {
      // check 1 must be the signature over the claims: a list tampered after signing is not the list that was signed
      name: `a tampered lst (the bit at idx ${entry.get('idx')} set after signing)`,
      expected: [ACCEPT_CHECK],
      reason: /signature of the CWT could not be verified/,
      list: () => tamperedLst(original, entry.get('idx'))
    },
    {
      // check 1 must be the chain, check 2 must be Credo's rule: this chain is not the mDL's issuance chain
      name: 'a different chain (the IACA in the x5chain instead of the Document Signer)',
      expected: [ACCEPT_CHECK, EQUAL_CHAIN_CHECK],
      reason: /no trusted certificate was found in the chain/,
      // the IACA is a real certificate that is not the signer: no .iaca.pem sidecar, no such control
      list: () => reSign(original, other.privateKey, withChain(original, [pemToDer(iacaPem)]))
    },
    {
      // the media type is wrong, and @owf/token-status-list itself refuses the JWT format
      name: `a JWT body served as ${JWT}`,
      expected: [CONTENT_TYPE_CHECK, ACCEPT_CHECK],
      reason: /served in JWT format/,
      list: () => JWT_BODY,
      contentType: JWT
    },
    {
      // ... and a JWT body under the CWT media type is the library's own refusal (JwtNotSupportForStatusListError)
      name: `a JWT body served as ${CWT}`,
      expected: [ACCEPT_CHECK],
      reason: /Unable to decode status list CWT/,
      list: () => JWT_BODY
    }
  ].filter((mutant) => {
    if (iacaPem || !mutant.name.startsWith('a different chain')) return true
    // the chain control needs a second real certificate: without the sidecar it cannot be built, which is its own failure
    console.log('FAIL control: a different chain: the sample has no .iaca.pem sidecar to put in the x5chain')
    failures.push('control: a different chain: no .iaca.pem sidecar')
    failed += 1
    return false
  })
  for (const mutant of mutants) {
    const checks = await judge({
      issuerSigned,
      list: mutant.list(),
      contentType: mutant.contentType ?? CWT,
      expectedStatus
    })
    const refused = checks.filter((result) => !result.ok && mutant.expected.includes(result.name))
    const missed = mutant.expected.filter((expected) => !refused.some((result) => result.name === expected))
    const wrongReason = mutant.reason ? !refused.some((result) => mutant.reason.test(result.detail)) : false
    if (missed.length === 0 && !wrongReason) {
      console.log(`PASS control: ${mutant.name}: ${refused[0].name} fails: ${refused[0].detail}`)
    } else if (missed.length > 0) {
      console.log(`FAIL control: ${mutant.name}: ${missed.join('; ')} did not fail`)
      failures.push(`control: ${mutant.name}: ${missed.join('; ')} did not fail`)
      failed += 1
    } else {
      console.log(`FAIL control: ${mutant.name}: it failed, but not for the expected reason (${refused.map((r) => r.detail).join('; ')})`)
      failures.push(`control: ${mutant.name}: it failed for another reason`)
      failed += 1
    }
  }
  return failed
}

const directory = process.argv[2] ?? path.join('..', '..', '..', '..', 'certify-service', 'target', 'mdoc-samples')
const samples = await probe(directory)
const negative = await controls(directory)
if (negative !== 0) {
  console.error(`\n${negative} negative control(s) passed that the probe must fail`)
}
process.exit(samples === 0 && negative === 0 ? 0 : 1)
