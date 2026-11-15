#!/usr/bin/env node
/*
 * Builds the `hosted/` request objects of plan section 4.12 for the P5-03 checks, once, with the output committed:
 *
 *   node docs/design/tools/fixtures/wallet/make-hosted.mjs
 *
 * **What these are, and what they are not.** The plan calls `hosted/` "the request objects captured from
 * verifier-backend.eudiw.dev and verifier.multipaz.org". The captures themselves are not in this repository, and no
 * test may contact a real verifier (the plan's hard rule), so this file records the two verifiers' *shapes* instead,
 * signed with the fixture verifier certificate: every member plan 2.1 lists is here, and nothing is here that the
 * captures were recorded as lacking - Multipaz's object still has no `aud` and no `state`, and EUDI's is still ~23 KB
 * because of its `verifier_info` registration certificate. What the checks prove with them is that the page reads
 * these shapes (R1-R11, the card, the findings), not that the verifiers' bytes are exactly these.
 *
 * The client_name, the URLs and the nonces are the fixture's. Nothing here is a secret: `verifier.key.pem` is the
 * committed test key.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = resolve(fileURLToPath(import.meta.url), "..");
const VERIFIER = resolve(HERE, "verifier");
const OUT = resolve(HERE, "hosted");

const pem = (name) => readFileSync(resolve(VERIFIER, name), "utf8");
const der = (name) => new Uint8Array(Buffer.from(pem(name).replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"));
const b64url = (value) => Buffer.from(value).toString("base64url");

/** The fixture's "now": the harness pins the same instant, inside every fixture certificate's validity. */
const NOW = Date.UTC(2026, 10, 15, 9, 0, 0) / 1000;

const LEAF_DER = der("verifier.pem");
const LEAF_X5C = Buffer.from(LEAF_DER).toString("base64");
const LEAF_HASH = createHash("sha256").update(LEAF_DER).digest("base64url");

/** The verifier's response-encryption key, as `client_metadata.jwks` carries it (VP section 8.3). */
function jweJwk() {
    const jwk = createPublicKey(pem("jwe.pub.pem")).export({ format: "jwk" });
    return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid: readFileSync(resolve(VERIFIER, "kid.txt"), "utf8").trim(),
        use: "enc", alg: "ECDH-ES" };
}

/** An ES256 compact JWS over `payload`, signed with the fixture leaf's key (raw r || s, RFC 7518 section 3.4). */
function signJws(payload, header) {
    const protectedHeader = Object.assign({ alg: "ES256", typ: "oauth-authz-req+jwt" }, header || {});
    const signingInput = b64url(JSON.stringify(protectedHeader)) + "." + b64url(JSON.stringify(payload));
    const signature = sign("sha256", Buffer.from(signingInput, "ascii"),
        { key: createPrivateKey(pem("verifier.key.pem")), dsaEncoding: "ieee-p1363" });
    return signingInput + "." + Buffer.from(signature).toString("base64url");
}

/** A registration certificate's JWS, about as long as EUDI's, so the request object lands near 23 KB. */
function registrationCertificate() {
    const header = { alg: "ES256", typ: "rc-wallet+jwt" };
    const payload = {
        iss: "https://verifier.example",
        sub: "registration certificate",
        iat: NOW - 3600,
        exp: NOW + 86400 * 30,
        // EUDI's registration certificate is what makes its request object ~23 KB; this stands in for its bulk
        credentials: Array.from({ length: 40 }, (_, index) => ({
            format: "dc+sd-jwt", vct: "urn:eudi:pid:1", meta: { vct_values: ["urn:eudi:pid:1"] }, index: index,
        })),
        padding: "https://verifier.example/".repeat(272),
    };
    const signingInput = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
    const signature = sign("sha256", Buffer.from(signingInput, "ascii"),
        { key: createPrivateKey(pem("verifier.key.pem")), dsaEncoding: "ieee-p1363" });
    return signingInput + "." + Buffer.from(signature).toString("base64url");
}

const MDL_CLAIMS = [
    ["family_name", false], ["given_name", false], ["birth_date", false], ["age_over_18", false],
    ["issue_date", false], ["expiry_date", false], ["issuing_country", false], ["document_number", false],
    ["portrait", true], ["driving_privileges", false],
];

/** EUDI's request object: `x509_hash`, `aud`, `state`, `direct_post.jwt`, and a `verifier_info` registration cert. */
const eudi = {
    client_id: "x509_hash:" + LEAF_HASH,
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    response_uri: "https://verifier.example/wallet/direct_post/3f1c0b7e-6a54-4d31-9c2a-1e8b7a6d4f21",
    nonce: "4d9e2f6a-8c1b-4f7d-9a3e-5b2c8d1e7f40",
    state: "9c1f7e2a-3b64-4d8e-a1f0-6c2d9e4b7a15",
    aud: "https://self-issued.me/v2",
    iat: NOW - 30,
    exp: NOW + 600,
    client_metadata: {
        jwks: { keys: [jweJwk()] },
        vp_formats_supported: {
            mso_mdoc: { issuerauth_alg_values: [-7, -35, -36], deviceauth_alg_values: [-7, -35, -36] },
        },
        encrypted_response_enc_values_supported: ["A128GCM", "A256GCM"],
        client_name: "EUDI Reference Verifier (fixture)",
    },
    dcql_query: {
        credentials: [{
            id: "query_0",
            format: "mso_mdoc",
            meta: { doctype_value: "org.iso.18013.5.1.mDL" },
            claims: MDL_CLAIMS.map(([element, retain]) => ({
                path: ["org.iso.18013.5.1", element], intent_to_retain: retain,
            })),
        }],
    },
    verifier_info: [{ format: "registration_cert", type: "registration_cert", data: registrationCertificate() }],
};

/** Multipaz's request object: `x509_san_dns`, `expected_origins`, and no `aud` and no `state` (plan 2.1). */
const multipaz = {
    client_id: "x509_san_dns:verifier.example",
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    response_uri: "https://verifier.example/verifier/response/7b2d9c14-0e6a-4f83-b5d1-2c8a6e4f9b73",
    nonce: "c2a7e4f1-9d38-4b6a-8e05-1f3c7a9d2b64",
    expected_origins: ["https://verifier.example"],
    iat: NOW - 20,
    exp: NOW + 300,
    client_metadata: {
        jwks: { keys: [jweJwk()] },
        vp_formats_supported: { mso_mdoc: { issuerauth_alg_values: [-9, -7], deviceauth_alg_values: [-9, -7] } },
        client_name: "Multipaz Web Verifier (fixture)",
    },
    dcql_query: {
        credentials: [{
            id: "cred1",
            format: "mso_mdoc",
            meta: { doctype_value: "org.iso.18013.5.1.mDL" },
            claims: MDL_CLAIMS.slice(0, 6).map(([element]) => ({ path: ["org.iso.18013.5.1", element] })),
        }],
    },
};

const EUDI_TEXT = signJws(eudi, { x5c: [LEAF_X5C] });
const MULTIPAZ_TEXT = signJws(multipaz, { x5c: [LEAF_X5C] });

writeFileSync(resolve(OUT, "eudi.request.jwt"), EUDI_TEXT + "\n");
writeFileSync(resolve(OUT, "multipaz.request.jwt"), MULTIPAZ_TEXT + "\n");
console.log(`eudi.request.jwt ${EUDI_TEXT.length} bytes, multipaz.request.jwt ${MULTIPAZ_TEXT.length} bytes, leaf x509_hash:${LEAF_HASH}`);
