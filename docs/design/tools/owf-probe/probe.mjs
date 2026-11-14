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
 * The lockfile pins one copy of `@owf/cose` (0.6.2) for the whole tree: `npm`'s flat node_modules would otherwise keep
 * `@owf/token-status-list`'s exact `@owf/cose@0.6.0` beside it, and the two copies register their CBOR tag decoders in
 * the one deduped `cbor-x`, so the copy that loads last decodes tag 24 for both — and `IssuerSigned.decode` then sees a
 * `DataItem` that is not its own class. Paradym's pnpm tree does not share this problem (each package gets its own
 * `cbor-x`); the override reproduces the single-`@owf/cose` view the library expects.
 *
 * The two checks per sample:
 *   1. `@owf/mdoc`'s `Holder.verifyIssuerSigned` accepts the credential with `trustedCertificates: [{issuance: [top]}]`,
 *      fetching the sample's `.statuslist.cwt` sidecar for the status list. This is the library Paradym verifies with;
 *      it refuses a JWT list (JwtNotSupportForStatusListError) and a list whose chain does not reach the trusted
 *      certificate.
 *   2. Credo's equal-chain rule, reimplemented here in fifteen lines over the two CBOR structures: the list's `x5chain`
 *      must be the IssuerAuth's `x5chain`, certificate for certificate.
 *
 * Exit status 1 when any sample fails, naming the sample and the reason. The MdocContext @owf/mdoc asks for is built
 * from Node's own crypto and @owf/cose (`@owf/mdoc` ships none: its reference context lives in the upstream tests and
 * pulls @peculiar/x509, jose, @noble/* and hpke, which nothing here needs).
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { CoseKey, Sign1, cborDecode } from '@owf/cose'
import { Holder, IssuerSigned } from '@owf/mdoc'

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
    if (contentType !== 'application/statuslist+cwt') {
      // @owf/token-status-list 0.6.0 asks for this media type and refuses anything else
      check(name, '@owf/mdoc accepts the list with its Content-Type', false, `Content-Type ${contentType}`)
      continue
    }
    const gaps = sidecar(directory, name, '.gaps')?.toString('utf8') ?? ''
    if (gaps.includes('issuerAuth.untagged:tagged')) {
      // the draft-13 compatibility shape wraps issuerAuth in tag 18, which @owf/mdoc 0.9.1 refuses before it reads any
      // status list: that surface's deviation is declared in the sample's own .gaps, not a status-list finding
      console.log(`SKIP ${name}: the sample declares issuerAuth.untagged:tagged (the draft-13 wrapper)`)
      continue
    }
    const issuerSigned = IssuerSigned.decode(new Uint8Array(fs.readFileSync(path.join(directory, file))))
    const issuanceChain = issuerSigned.issuerAuth.x5chain ?? []
    const statusListChain = Sign1.decode(new Uint8Array(list)).certificateChain ?? []
    // a sample that declares the status its list reports (0 VALID, 1 INVALID: M-11e's revoked sample) is expected to
    // fail the holder's verification on the revocation, and nothing else
    const expectedStatus = Number(sidecar(directory, name, '.statuslist.status')?.toString('utf8').trim() ?? '0')
    const uri = statusListUri(issuerSigned)

    // 1. the library Paradym verifies with, told to trust the top of the presented issuance chain
    const accept = '@owf/mdoc 0.9.1 verifies the mDL and its status list (trusted: the presented top certificate)'
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
        check(name, accept, true)
      } else {
        check(name, `@owf/mdoc 0.9.1 reports the status the sample declares (${expectedStatus})`, false,
          'the credential verified, but its list reports the status as revoked')
      }
    } catch (e) {
      const revokedAsDeclared = expectedStatus === 1 && /not Valid \(0\)/.test(e.message)
      check(name, expectedStatus === 0 ? accept : `@owf/mdoc 0.9.1 reports the status the sample declares (${expectedStatus})`,
        revokedAsDeclared, `${e.name}: ${e.message}`)
    }

    // 2. Credo's equal-chain rule
    check(name, "Credo's equal-chain rule: the list's x5chain is the IssuerAuth's", equalChains(issuanceChain, statusListChain),
      equalChains(issuanceChain, statusListChain) ? '' : `list ${statusListChain.length} certificate(s), mDL ${issuanceChain.length}`)
  }
  if (failures.length > 0) {
    console.error(`\n${failures.length} failure(s)`)
    return 1
  }
  return 0
}

/** The `status_list.uri` the MSO carries, read from the raw MSO the IssuerAuth payload holds. */
function statusListUri(issuerSigned) {
  const payload = issuerSigned.issuerAuth.payload
  const mso = cborDecode(new Uint8Array(payload))
  const status = mso instanceof Map ? mso.get('status') : undefined
  const entry = status instanceof Map ? status.get('status_list') : undefined
  return entry instanceof Map ? entry.get('uri') : undefined
}

const directory = process.argv[2] ?? path.join('..', '..', '..', '..', 'certify-service', 'target', 'mdoc-samples')
process.exit(await probe(directory))
