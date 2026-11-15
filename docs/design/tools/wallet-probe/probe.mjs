#!/usr/bin/env node
/*
 * P5-03b's independent verifier: every DeviceResponse the demo wallet produces, checked by a library Certify does not
 * maintain (docs/design/wp/P5-03-demo-wallet-presentation.md, plan sections 4.7 and 4.14, non-negotiable 2).
 *
 *   node docs/design/tools/wallet-probe/probe.mjs [samples-dir]
 *
 * `check-offer-wallet.mjs` writes the samples (`$WALLET_SAMPLES_DIR`, default `target/wallet-samples/`):
 *
 *   <name>/device-response.cbor   the response, byte for byte as the page built it
 *   <name>/transcript.json        what the page signed over: {clientId, nonce, jwkThumbprint, responseUri}
 *   <name>/expected.json          what a verifier must do: {expect, rejectedBy, verifier, docType, elements, now, ...}
 *   <name>/iaca.pem               the trust anchor the DSC chains to
 *
 * and this probe checks each one with `@owf/mdoc` 0.9.3 (the library Credo's OpenID4VP verifier uses):
 *
 * - it computes the OpenID4VP 1.0 `SessionTranscript` **itself**
 *   (`SessionTranscript.forOid4Vp`, plan 4.14's "computed by its own"), from `expected.verifier`, so a transcript the
 *   page got wrong cannot agree with itself;
 * - it verifies the whole response with `Verifier.verifyDeviceResponse`: the issuer signature and the x5chain to the
 *   fixture IACA (`trustedCertificates: [{issuance: [iaca]}]`), the MSO digests over the disclosed items, the device
 *   signature over the transcript it computed, the docType, and that the payload really is detached;
 * - it reads back the disclosed `(namespace, elementIdentifier)` set and holds it to `expected.elements`, so an element
 *   that was not chosen cannot be disclosed quietly (selective disclosure is checked in both directions).
 *
 * A negative sample must fail, and fail at the check `expected.rejectedBy` names: `deviceSignature` (the transcript or
 * the key is not the verifier's) or `digest` (an item was re-encoded, so it no longer hashes to the MSO's valueDigest).
 *
 * The crypto context is this file's: `@owf/mdoc` takes one, the way Credo supplies its own. Digests and X.509 path
 * validation come from WebCrypto and `@owf/x509` (the mdoc library's own ASN.1 module); COSE signatures are verified
 * with `@noble/curves` (ES256/ESP256, which is what an mDL device signature and the demo's IssuerAuth carry). Versions
 * are exact in package.json and `npm ci` is the only install (plan invariant I6: nothing here is on the runtime
 * classpath).
 *
 * The trust step is Certify's, not a library's: `@owf/mdoc` leaves path validation to its caller, so
 * `verifyCertificateChain` below builds the path from the fixture IACA and applies RFC 5280's CA constraints itself
 * (`checkPathConstraints`). Multipaz's `TrustManager`, in `certify-conformance-mdoc`, is the independent trust decision
 * the gate rests on (plan 4.14; decision log, P5-03b review round 1).
 */
import { createHash, hkdfSync, webcrypto } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CoseKey, SessionTranscript, Verifier } from "@owf/mdoc";
import { createCertificate, parseCertificate, verifyCertificateSignature } from "@owf/x509";
import { p256 } from "@noble/curves/p256";

const subtle = webcrypto.subtle;
const FILE = fileURLToPath(import.meta.url);
const REPO = resolve(dirname(FILE), "../../../..");
const SAMPLES = resolve(process.argv[2] === undefined ? resolve(REPO, "target/wallet-samples") : process.argv[2]);

/* ---------------------------------------------------------------- the crypto context @owf/mdoc takes */

const concat = (...parts) => new Uint8Array(Buffer.concat(parts.map((part) => Buffer.from(part))));
const hex = (bytes) => Buffer.from(bytes).toString("hex");

/** The digest algorithm a COSE algorithm uses, and the curve it signs on. */
const ES_ALGORITHMS = new Map([[-7, ["SHA-256", p256]], [-9, ["SHA-256", p256]], [-35, ["SHA-384", null]],
    [-36, ["SHA-512", null]]]);

/** ES256/ESP256 over a P-256 key, as a COSE signature (r || s) over the to-be-verified bytes. */
function verifyCoseSignature({ toBeVerified, signature, key, algorithm }) {
    const jwk = key.jwk;
    if (algorithm === undefined || !ES_ALGORITHMS.has(algorithm)) {
        throw new Error(`the probe verifies ES256/ESP256 signatures, not COSE algorithm ${String(algorithm)}`);
    }
    const [hash, curve] = ES_ALGORITHMS.get(algorithm);
    const digest = createHash(hash.toLowerCase().replace("-", "")).update(toBeVerified).digest();
    const point = concat(Uint8Array.of(4), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url"));
    // a COSE signature is the raw r || s, which is what @noble/curves verifies over the digest
    return curve.verify(signature, digest, point, { lowS: false });
}

/**
 * A certificate's own signature, checked with WebCrypto: ECDSA over the digest its signature algorithm names (the
 * `signatureP1363` @owf/x509 hands over is already the r || s WebCrypto wants), or RSA PKCS#1 v1.5.
 */
async function verifyCertificateSignatureWithWebCrypto({ data, signatureP1363, signatureAlgorithmName, publicKey }) {
    const jwk = publicKey.jwk;
    if (jwk === undefined) return false;
    const name = typeof signatureAlgorithmName === "string" ? signatureAlgorithmName
        : typeof publicKey.algorithm === "string" ? publicKey.algorithm : "";
    const hash = /512/.test(name) ? "SHA-512" : /384/.test(name) ? "SHA-384" : "SHA-256";
    if (jwk.kty === "RSA") {
        const key = await subtle.importKey("jwk", { ...jwk, ext: true }, { name: "RSASSA-PKCS1-v1_5", hash }, false,
            ["verify"]);
        return subtle.verify("RSASSA-PKCS1-v1_5", key, signatureP1363, data);
    }
    const key = await subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDSA", namedCurve: jwk.crv }, false,
        ["verify"]);
    return subtle.verify({ name: "ECDSA", hash }, key, signatureP1363, data);
}

/**
 * Path validation for the mdoc's x5chain: leaf first, each certificate signed by the next, ending at a trust anchor.
 *
 * This is the Node probe's own trust step, written here because `@owf/mdoc` leaves the decision to its caller (Credo
 * has its own). Multipaz's `TrustManager` in `certify-conformance-mdoc` is the independent trust decision the gate
 * rests on; this one exists so the probe fails a bad chain itself instead of reporting a signature result it would be
 * wrong to believe. It checks what RFC 5280 asks of a path (section 6.1: validity, signatures, and the CA constraints
 * of 4.2.1.3 and 4.2.1.9), not revocation: the fixtures are offline and carry no CRL.
 */
async function verifyCertificateChain({ trustedCertificates, x5chain, now }) {
    const trusted = trustedCertificates.map((der) => parseCertificate(der));
    const chain = x5chain.map((der) => parseCertificate(der));
    if (!chain.length) throw new Error("the mdoc carries no x5chain");
    const isTrusted = (certificate) => trusted.some((anchor) => hex(anchor.der) === hex(certificate.der));
    const at = now === undefined ? new Date() : now;
    const skew = 5 * 60 * 1000;
    const path = [chain[0]];
    for (let step = 0; step < 6; step += 1) {
        const current = path[path.length - 1];
        if (current.notBefore.getTime() - skew > at.getTime() || current.notAfter.getTime() + skew < at.getTime()) {
            throw new Error(`the certificate ${current.subject.rfc4514} is outside its validity at ${at.toISOString()}`);
        }
        if (isTrusted(current)) {
            checkPathConstraints(path);
            return { chain: path.map((certificate) => certificate.der) };
        }
        const candidates = [...chain.slice(1), ...trusted].filter((candidate) => !path.includes(candidate));
        let next = null;
        for (const candidate of candidates) {
            const matches = candidate.subject.rfc4514 === current.issuer.rfc4514;
            const signed = matches && await verifyCertificateSignature(current, candidate,
                verifyCertificateSignatureWithWebCrypto);
            if (signed) {
                next = candidate;
                break;
            }
        }
        if (next === null) {
            throw new Error(`no certificate in the x5chain or the trust anchors signed ${current.subject.rfc4514}`);
        }
        path.push(next);
    }
    throw new Error("the x5chain does not end at a trust anchor");
}

/**
 * RFC 5280 4.2.1.9, 4.2.1.3 and 6.1.4 (n)/(o): every certificate in a validated path that issued another one is a CA
 * allowed to sign certificates, and its `pathLenConstraint`, where present, covers the intermediate CA certificates
 * beneath it. A path that passes only because two names happen to match is not a trusted path.
 */
function checkPathConstraints(path) {
    for (let index = 1; index < path.length; index += 1) {
        const certificate = path[index];
        const name = certificate.subject.rfc4514;
        if (certificate.basicConstraints?.cA !== true) {
            throw new Error(`the certificate ${name} issued a certificate in the path but is not a CA`
                + " (basicConstraints cA is not TRUE, RFC 5280 4.2.1.9)");
        }
        if (certificate.keyUsage !== undefined && !certificate.keyUsage.includes("keyCertSign")) {
            throw new Error(`the certificate ${name} issued a certificate in the path but its keyUsage does not allow`
                + " signing certificates (keyCertSign, RFC 5280 4.2.1.3)");
        }
        const below = index - 1;
        const limit = certificate.basicConstraints.pathLenConstraint;
        if (limit !== undefined && below > limit) {
            throw new Error(`the certificate ${name} allows ${limit} intermediate CA certificate(s) below it and the`
                + ` path has ${below} (pathLenConstraint, RFC 5280 4.2.1.9)`);
        }
    }
}

/** The values of one subject field, by its short name or OID (e.g. `C`, `CN`, `2.5.4.6`). */
const SUBJECT_FIELDS = { C: "countryName", CN: "commonName", O: "organizationName", ST: "stateOrProvinceName",
    L: "localityName", OU: "organizationalUnitNames", serialNumber: "serialNumber" };

const context = {
    fetch: (...args) => globalThis.fetch(...args),
    crypto: {
        random: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
        digest: ({ digestAlgorithm, bytes }) => subtle.digest(digestAlgorithm, bytes).then((result) => new Uint8Array(result)),
        // ISO/IEC 18013-5 9.1.1.5's session keys: HKDF-SHA256 over Z, which the device MAC would use
        hdkf: ({ digestAlgorithm = "SHA-256", privateKey, publicKey, salt, info }) => new Uint8Array(
            hkdfSync(digestAlgorithm.toLowerCase().replace("-", ""), privateKey, salt, info, 32)),
    },
    cose: {
        sign1: {
            verify: verifyCoseSignature,
            sign: () => { throw new Error("the probe only verifies"); },
        },
        mac0: {
            verify: () => { throw new Error("the probe verifies device signatures, not device MACs"); },
            authenticate: () => { throw new Error("the probe only verifies"); },
        },
    },
    x509: {
        getSubjectNameField: ({ certificate, field }) => {
            const subject = parseCertificate(certificate).subject;
            const name = SUBJECT_FIELDS[field] ?? field;
            return subject.attributes.filter((attribute) => attribute.name === name || attribute.type === name)
                .map((attribute) => attribute.value);
        },
        getPublicKey: ({ certificate }) => {
            const jwk = parseCertificate(certificate).publicKey.jwk;
            if (jwk === undefined) throw new Error("the certificate's public key is not an EC or RSA key");
            return CoseKey.fromJwk(jwk);
        },
        verifyCertificateChain,
        getCertificateData: ({ certificate }) => {
            const parsed = parseCertificate(certificate);
            return { issuerName: parsed.issuer.rfc4514, subjectName: parsed.subject.rfc4514,
                serialNumber: parsed.serialNumber,
                thumbprint: createHash("sha256").update(parsed.der).digest("hex"),
                notBefore: parsed.notBefore, notAfter: parsed.notAfter, pem: parsed.pem };
        },
    },
};

/* ---------------------------------------------------------------- the samples */

const pemToDer = (pem) => new Uint8Array(Buffer.from(
    pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"));

/** The transcript the *verifier* would compute, with the library's own `SessionTranscript.forOid4Vp`. */
async function transcriptFor(verifier) {
    const transcript = await SessionTranscript.forOid4Vp({
        clientId: verifier.clientId,
        nonce: verifier.nonce,
        jwkThumbprint: verifier.jwkThumbprint === null ? undefined : new Uint8Array(Buffer.from(verifier.jwkThumbprint,
            "base64url")),
        responseUri: verifier.responseUri,
    }, context);
    return transcript.encode();
}

/** The disclosed `(namespace, element)` set of every document, as "namespace/element" strings. */
function disclosedFrom(result) {
    const disclosed = [];
    for (const { document } of result.documents) {
        // a query without claims carries the IssuerAuth and no nameSpaces at all (OpenID4VP 1.0 6.4.1)
        for (const [namespace, items] of document.issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map()) {
            for (const item of items) disclosed.push(`${namespace}/${item.elementIdentifier}`);
        }
    }
    return disclosed.sort();
}

/** What the probe expects a rejection to say, so a sample cannot fail for the wrong reason. */
const REJECTIONS = {
    // `@owf/mdoc`'s own words for these two checks, exactly: a bare /signature/ also matches its issuer-auth message
    // ("Issuer auth signature is invalid"; "Signature on MSO failed to verify" is Multipaz's wording for the same
    // failure), so a document signed by another DSC would satisfy a device-signature negative for the wrong reason
    // (P5-03b review round 1, finding 3)
    deviceSignature: [/^Unable to verify deviceAuth signature \(ECDSA\/EdDSA\): Device signature must be valid$/],
    digest: [/^The calculated digest for .+ attribute must match the digest in the issuerAuth element$/],
};

async function probeSample(name) {
    const directory = resolve(SAMPLES, name);
    const response = new Uint8Array(readFileSync(resolve(directory, "device-response.cbor")));
    const expected = JSON.parse(readFileSync(resolve(directory, "expected.json"), "utf8"));
    const transcript = await transcriptFor(expected.verifier);
    const iaca = pemToDer(readFileSync(resolve(directory, "iaca.pem"), "utf8"));
    if (createHash("sha256").update(iaca).digest("hex") !== expected.iacaSha256) {
        throw new Error(`${name}: iaca.pem is not the anchor expected.json names`);
    }
    const options = {
        deviceResponse: response,
        sessionTranscript: transcript,
        trustedCertificates: [{ issuance: [iaca] }],
        now: new Date(expected.now),
    };
    if (expected.expect === "accepted") {
        const result = await Verifier.verifyDeviceResponse(options, context);
        if (result.documents.length !== 1) throw new Error(`${name}: ${result.documents.length} documents, not one`);
        const document = result.documents[0].document;
        if (document.docType !== expected.docType) {
            throw new Error(`${name}: docType ${document.docType}, not ${expected.docType}`);
        }
        const disclosed = disclosedFrom(result);
        if (JSON.stringify(disclosed) !== JSON.stringify([...expected.elements].map(([namespace, identifier]) =>
            `${namespace}/${identifier}`).sort())) {
            throw new Error(`${name}: disclosed ${JSON.stringify(disclosed)}, not ${JSON.stringify(expected.elements)}`);
        }
        // the device signature really is a signature: it must be the page's key, over the verifier's transcript
        const signature = document.deviceSigned.deviceAuth.decodedStructure.get("deviceSignature");
        if (signature.payload !== null) throw new Error(`${name}: the deviceSignature is not detached`);
        if (signature.signature.length !== 64) throw new Error(`${name}: the deviceSignature is not a raw r || s`);
        return { name, expect: "accepted", disclosed };
    }
    let failure = null;
    try {
        await Verifier.verifyDeviceResponse(options, context);
    } catch (error) {
        failure = error;
    }
    if (failure === null) throw new Error(`${name}: the verifier accepted a response it must reject`);
    const message = String(failure.message ?? failure);
    const patterns = REJECTIONS[expected.rejectedBy];
    if (patterns === undefined) throw new Error(`${name}: expected.json names the unknown rejection ${expected.rejectedBy}`);
    if (!patterns.some((pattern) => pattern.test(message))) {
        throw new Error(`${name}: rejected as "${message}", not at the ${expected.rejectedBy} check`);
    }
    return { name, expect: "rejected", rejectedBy: expected.rejectedBy, reason: message };
}

/* ---------------------------------------------------------------- the appendix's own vectors */

/**
 * OpenID4VP 1.0 Appendix B.2.6.1's worked example, through the library: if `@owf/mdoc`'s own
 * `SessionTranscript.forOid4Vp` does not reproduce these bytes, the library and this run disagree about what a device
 * signature covers before a single sample is looked at. `check-offer-wallet.mjs` holds the page to the same vectors.
 */
async function checkAppendixVectors() {
    const thumbprint = new Uint8Array(Buffer.from("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047", "hex"));
    const inputs = { clientId: "x509_san_dns:example.com", nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
        responseUri: "https://example.com/response" };
    const withThumbprint = hex((await SessionTranscript.forOid4Vp({ ...inputs, jwkThumbprint: thumbprint }, context)).encode());
    const plain = hex((await SessionTranscript.forOid4Vp(inputs, context)).encode());
    const expected = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d"
        + "254b046b11b68013722aad38ac";
    if (withThumbprint !== expected) {
        throw new Error(`@owf/mdoc's SessionTranscript does not reproduce VP B.2.6.1: ${withThumbprint}`);
    }
    if (plain === withThumbprint || !plain.startsWith("83f6f6")) {
        throw new Error(`the null-thumbprint transcript is not the appendix's null form: ${plain}`);
    }
    console.log("ok    VP B.2.6.1's vector, computed by @owf/mdoc's own SessionTranscript.forOid4Vp");
}

/* ---------------------------------------------------------------- the trust step's own rules */

/**
 * The rules `checkPathConstraints` applies, exercised on the fixture IACA: an issuer that is not marked as a CA, one
 * whose `keyUsage` does not allow signing certificates, and one whose `pathLenConstraint` does not cover the path
 * beneath it are each refused, by name. Then one refusal comes through {@link verifyCertificateChain} itself, on a path
 * `@owf/x509`'s `createCertificate` built: an intermediate with `cA: false` that signs a leaf. Without that, the only
 * thing tying the rules to the step the samples take would be a reader's eye on the one line that calls them
 * (P5-03b review round 1, finding 4; round 2, finding 3).
 */
async function checkTrustConstraints() {
    const anchor = parseCertificate(pemToDer(readFileSync(resolve(REPO,
        "docs/design/tools/fixtures/wallet/iaca.pem"), "utf8")));
    const plainLeaf = { ...anchor, basicConstraints: undefined, keyUsage: ["digitalSignature"] };
    const replaced = (overrides) => ({ ...anchor, ...overrides });
    const refuses = async (label, attempt, pattern) => {
        let error = null;
        try {
            await attempt();
        } catch (caught) {
            error = caught;
        }
        if (error === null || !pattern.test(error.message)) {
            throw new Error(`the trust step did not refuse ${label}: ${error === null ? "it passed" : error.message}`);
        }
        console.log(`ok    the trust step refuses ${label}`);
    };
    await refuses("an issuer that is not a CA",
        () => checkPathConstraints([plainLeaf, replaced({ basicConstraints: { cA: false } })]), /is not a CA/);
    await refuses("an issuer whose keyUsage has no keyCertSign",
        () => checkPathConstraints([plainLeaf, replaced({ keyUsage: ["digitalSignature"] })]), /keyCertSign/);
    await refuses("an issuer whose pathLenConstraint is too small", () => checkPathConstraints([plainLeaf,
        replaced({}), replaced({ basicConstraints: { cA: true, pathLenConstraint: 0 } })]), /pathLenConstraint/);
    // and the fixture's own path passes: the rules are not simply refusing everything
    checkPathConstraints([plainLeaf, anchor]);

    // the same refusal, through the step a sample's own chain goes through: an intermediate the anchor signed and
    // that itself signed the leaf, but that is not a CA - so `verifyCertificateChain` can only refuse it by calling
    // `checkPathConstraints` on the path it built
    const built = await nonCaIntermediatePath();
    await refuses("a non-CA intermediate, through verifyCertificateChain", () => verifyCertificateChain({
        trustedCertificates: [built.anchor.der], x5chain: [built.leaf.der, built.intermediate.der] }), /is not a CA/);
    // the same shape with a CA intermediate passes, so the refusal above is about the intermediate's constraints
    const accepted = await verifyCertificateChain({ trustedCertificates: [built.anchor.der],
        x5chain: [built.leafUnderCa.der, built.intermediateCa.der] });
    if (hex(accepted.chain[0]) !== hex(built.leafUnderCa.der) || accepted.chain.length !== 3) {
        throw new Error(`verifyCertificateChain did not build [leaf, intermediate CA, anchor]: ${accepted.chain.length}`);
    }
    console.log("ok    verifyCertificateChain accepts the same path with a CA intermediate");
}

/** A P-256 key pair, its public JWK and a signer over it, for the certificates the trust checks build. */
async function p256Pair() {
    const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return { publicJwk: await subtle.exportKey("jwk", pair.publicKey),
        signer: async (tbs) => new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey,
            tbs)) };
}

/**
 * The path `verifyCertificateChain`'s own refusal is proved on, built with `@owf/x509`'s `createCertificate`: an anchor,
 * a **non-CA** intermediate it signed (`cA: false`, which also leaves `keyUsage` at `digitalSignature`), and a leaf that
 * intermediate signed. The anchor also signs a proper CA intermediate, so the check can show a path of the same shape
 * passing; otherwise its refusal could be a step that refuses everything.
 */
async function nonCaIntermediatePath() {
    const now = Date.now();
    const notBefore = new Date(now - 24 * 60 * 60 * 1000);
    const notAfter = new Date(now + 24 * 60 * 60 * 1000);
    const anchorKeys = await p256Pair();
    const notCaKeys = await p256Pair();
    const caKeys = await p256Pair();
    const certificate = async (serialNumber, commonName, subjectPublicKey, signer, extra) => createCertificate({
        subject: [["countryName", "IN"], ["commonName", commonName]], subjectPublicKey, serialNumber, notBefore,
        notAfter, signatureAlgorithm: "ES256", signer, ...extra });
    const anchor = await certificate("01", "wallet-probe anchor", anchorKeys.publicJwk, anchorKeys.signer,
        { basicConstraints: { cA: true } });
    const intermediate = await certificate("02", "wallet-probe non-CA intermediate", notCaKeys.publicJwk,
        anchorKeys.signer, { issuerCertificate: anchor.der, basicConstraints: { cA: false } });
    const intermediateCa = await certificate("03", "wallet-probe intermediate CA", caKeys.publicJwk,
        anchorKeys.signer, { issuerCertificate: anchor.der, basicConstraints: { cA: true } });
    const leaf = await certificate("04", "wallet-probe leaf", notCaKeys.publicJwk, notCaKeys.signer,
        { issuerCertificate: intermediate.der });
    const leafUnderCa = await certificate("05", "wallet-probe leaf under a CA", caKeys.publicJwk, caKeys.signer,
        { issuerCertificate: intermediateCa.der });
    return { anchor, intermediate, intermediateCa, leaf, leafUnderCa };
}

/* ---------------------------------------------------------------- run */

const SAMPLE_FILES = ["device-response.cbor", "transcript.json", "expected.json", "iaca.pem"];

async function main() {
    await checkAppendixVectors();
    await checkTrustConstraints();
    const directories = existsSync(SAMPLES) ? readdirSync(SAMPLES, { withFileTypes: true })
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort() : [];
    if (directories.length === 0) {
        console.error(`wallet-probe: no samples in ${SAMPLES}; run node docs/design/tools/check-offer-wallet.mjs first`);
        process.exitCode = 1;
        return;
    }
    const results = [];
    const failures = [];
    for (const name of directories) {
        try {
            for (const file of SAMPLE_FILES) readFileSync(resolve(SAMPLES, name, file));
            results.push(await probeSample(name));
        } catch (error) {
            failures.push(`${name}: ${error.message}`);
            console.error(`FAIL  ${name}: ${error.message}`);
        }
    }
    const accepted = results.filter((result) => result.expect === "accepted").length;
    const rejected = results.filter((result) => result.expect === "rejected").length;
    for (const result of results) {
        console.log(result.expect === "accepted"
            ? `ok    ${result.name}: verified, ${result.disclosed.length} elements disclosed ${JSON.stringify(result.disclosed)}`
            : `ok    ${result.name}: rejected at the ${result.rejectedBy} check`);
    }
    console.log();
    if (failures.length) {
        console.error(`wallet-probe: ${failures.length} of ${directories.length} samples FAILED (@owf/mdoc 0.9.3)`);
        process.exitCode = 1;
        return;
    }
    console.log(`wallet-probe: all ${results.length} samples passed (@owf/mdoc 0.9.3): ${accepted} accepted, ${rejected} rejected`);
}

await main();
