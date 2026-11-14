#!/usr/bin/env node
/*
 * P5-03a behaviour check: the offer page keeps an issued mDL in this browser, and the demo wallet lists, shows and
 * deletes what it kept (docs/design/wp/P5-03-demo-wallet-presentation.md, work package P5-03a).
 *
 * Plain Node (24, the version CI pins), no npm dependencies, no browser, no server:
 *   node docs/design/tools/check-offer-wallet.mjs
 * It shares the fake DOM, the fake fetch and the check helpers with check-offer-page.mjs, and evaluates the page's own
 * `src` scripts (cbor.js, mdoc.js, wallet-store.js; `scripts: "real"`), so `Cbor.encode`, `Mdoc.readIssuerSigned` and
 * `WalletStore` are the shipped files, not stubs.
 *
 * The mDL fixtures are built here, in memory, with the page's own encoder: an ISO/IEC 18013-5 IssuerSigned with a
 * tag-24 MSO, a P-256 deviceKey and one SHA-256 digest per tag-24 IssuerSignedItemBytes. P5-03b records the committed
 * fixtures through Certify's formatter; this slice needs no issuer and no fixture file, which is why the bytes are made
 * here.
 *
 * What it cannot check: a real browser's IndexedDB (the fake below is the storage model), a rendered layout, and the
 * HTTP headers (check-offer-page.mjs is offline; OfferPageTest recomputes the inline script's hash from the bytes the
 * controller serves and finds it in the Content-Security-Policy).
 */
import { createHash, createPublicKey, verify, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import vm from "node:vm";

import { openPage, parseMarkup, check, equal, section, counts, Element, Text, FakeIndexedDB, REPO,
    OID4VCI_ISSUER, OID4VCI_DOCUMENT, DEFAULT_AS_METADATA, offerByValue, offerDocument } from "./check-offer-page.mjs";

const STATIC = resolve(REPO, "certify-service/src/main/resources/static/offer");
const DOC_TYPE = "org.iso.18013.5.1.mDL";
const PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
const DB_NAME = "certify-demo-wallet";

/** Runs one shipped module with the globals it expects, returning its single global. */
function shipped(file, globals, name) {
    const names = Object.keys(globals);
    const values = names.map((key) => globals[key]);
    return new Function(...names, readFileSync(resolve(STATIC, file), "utf8") + `; return ${name};`)(...values);
}

const Cbor = shipped("cbor.js", {}, "Cbor");
const Mdoc = shipped("mdoc.js", { Cbor, crypto: webcrypto, btoa }, "Mdoc");

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const hash = (algorithm, bytes) => new Uint8Array(createHash(algorithm.replace("-", "").toLowerCase()).update(bytes).digest());
const bytesOf = (value) => new Uint8Array(Buffer.from(value));

/* ---------------------------------------------------------------- fixtures */

const HOLDER_A = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const HOLDER_B = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwkOf = (pair) => webcrypto.subtle.exportKey("jwk", pair.publicKey);
const HOLDER_A_JWK = await jwkOf(HOLDER_A);
const HOLDER_B_JWK = await jwkOf(HOLDER_B);
const HOLDER_A_PRIVATE = await webcrypto.subtle.exportKey("jwk", HOLDER_A.privateKey);

/** A COSE_Key for a P-256 JWK, or the override a negative case needs. */
function coseKey(jwk, override) {
    if (override) return override;
    return new Map([[1, 2], [-1, 1], [-2, bytesOf(Buffer.from(jwk.x, "base64url"))], [-3, bytesOf(Buffer.from(jwk.y, "base64url"))]]);
}

/**
 * Builds one IssuerSigned the way ISO/IEC 18013-5 8.3.2.1.2 describes it: nameSpaces of tag-24 IssuerSignedItemBytes and
 * an issuerAuth COSE_Sign1 whose payload is a tag-24 MSO. `tamper` re-encodes one element's value after its digest was
 * computed (check 4); `tag24Payload: false` writes the MSO as a plain byte string (check 1).
 */
function buildIssuerSigned(options) {
    const algorithm = options.digestAlgorithm || "SHA-256";
    const nameSpaces = new Map();
    const digests = new Map();
    let digestId = 0;
    for (const namespace of Object.keys(options.elements)) {
        const encoded = [];
        const byDigestId = new Map();
        for (const [identifier, value] of Object.entries(options.elements[namespace])) {
            const itemBytes = Cbor.encode(new Map([
                ["digestID", digestId],
                ["random", new Uint8Array(16).fill(digestId + 1)],
                ["elementIdentifier", identifier],
                ["elementValue", value],
            ]));
            let item = Cbor.encode(new Cbor.Tagged(24, itemBytes));
            if (options.tamper === identifier) {
                item = Cbor.encode(new Cbor.Tagged(24, Cbor.encode(new Map([
                    ["digestID", digestId], ["random", new Uint8Array(16).fill(digestId + 1)],
                    ["elementIdentifier", identifier], ["elementValue", "changed after signing"],
                ]))));
            }
            byDigestId.set(digestId, hash(algorithm, Cbor.encode(new Cbor.Tagged(24, itemBytes))));
            encoded.push(item);
            digestId++;
        }
        nameSpaces.set(namespace, encoded);
        digests.set(namespace, byDigestId);
    }
    const mso = new Map([
        ["version", "1.0"],
        ["digestAlgorithm", algorithm],
        ["valueDigests", digests],
        ["deviceKeyInfo", new Map([["deviceKey", coseKey(options.holder, options.deviceKey)]])],
        ["docType", options.docType],
        ["validityInfo", new Map([["signed", "2026-11-01T00:00:00Z"], ["validFrom", "2026-11-01T00:00:00Z"],
            ["validUntil", "2026-12-01T00:00:00Z"]])],
    ]);
    const msoBytes = Cbor.encode(mso);
    const payload = options.tag24Payload === false ? new Cbor.Raw(msoBytes) : new Cbor.Raw(Cbor.encode(new Cbor.Tagged(24, msoBytes)));
    const issuerAuth = [
        Cbor.encode(new Map([[1, -7]])),
        new Map([[33, [new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])]]]),
        payload,
        new Uint8Array(64),
    ];
    const bytes = Cbor.encode(new Map([
        ["nameSpaces", new Map([...nameSpaces].map(([namespace, items]) => [namespace, items.map((item) => new Cbor.Raw(item))]))],
        ["issuerAuth", issuerAuth],
    ]));
    return { bytes, nameSpaces, digests, mso, docType: options.docType };
}

const MDL_ELEMENTS = {
    "org.iso.18013.5.1": {
        family_name: "Ipsum",
        given_name: "Lorem",
        birth_date: new Cbor.Tagged(1004, "1985-04-12"),
        portrait: new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]),
        age_over_18: true,
    },
};
const PID_ELEMENTS = {
    "eu.europa.ec.eudi.pid.1": {
        family_name: "Ipsum",
        given_name: "Lorem",
        birth_date: "1985-04-12",
        nationality: "IN",
    },
};
const MDL_A = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS });
const MDL_B = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_B_JWK, elements: MDL_ELEMENTS });
const PID = buildIssuerSigned({ docType: PID_DOCTYPE, holder: HOLDER_A_JWK, elements: PID_ELEMENTS });

/** The page's WebCrypto with `generateKey` handing back the fixture holder's key, imported non-extractable. */
function cryptoForFixture() {
    return {
        subtle: new Proxy(webcrypto.subtle, {
            get(target, property) {
                if (property === "generateKey") {
                    return async () => ({
                        privateKey: await webcrypto.subtle.importKey("jwk", HOLDER_A_PRIVATE,
                            { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]),
                        publicKey: await webcrypto.subtle.importKey("jwk", HOLDER_A_JWK,
                            { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
                    });
                }
                const value = Reflect.get(target, property);
                return typeof value === "function" ? value.bind(target) : value;
            },
        }),
        randomUUID: () => webcrypto.randomUUID(),
        getRandomValues: (array) => webcrypto.getRandomValues(array),
    };
}

const CONFIGURATIONS = { mdoc: { format: "mso_mdoc", doctype: DOC_TYPE } };
const ISSUER_DOCUMENT = Object.assign({}, OID4VCI_DOCUMENT, { credential_configurations_supported: CONFIGURATIONS });
const CREDENTIAL_ANSWER = (credentials) => ({ status: 200, body: { credentials: credentials.map((credential) => ({ credential: b64url(credential.bytes) })) } });

/** Opens the offer page with the shipped scripts, an mso_mdoc configuration and one offer ready to redeem. */
function openOffer(options = {}) {
    const page = openPage({ subjects: [] }, {
        scripts: "real",
        pagePath: resolve(STATIC, "index.html"),
        configurations: options.configurations || CONFIGURATIONS,
        issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, ISSUER_DOCUMENT, options.issuerDocument || {}) },
        asMetadata: DEFAULT_AS_METADATA,
        offers: [offerByValue("keep", offerDocument(OID4VCI_ISSUER, options.configurationId || "mdoc", "keep-code"))],
        credential: options.credential || CREDENTIAL_ANSWER([MDL_A]),
        indexedDB: options.indexedDB,
        crypto: options.crypto || cryptoForFixture(),
        walletConfig: true,
    });
    return page;
}

/** Creates the offer and runs the page's wallet, as a visitor does. */
async function issue(page) {
    await page.settle();
    page.el("subject").value = "mdl-demo-1";
    await page.createOffer();
    await page.runWallet();
    await page.settle();
}

const credentialsIn = (fake) => {
    const database = fake.databases.get(DB_NAME);
    return database === undefined ? [] : [...database.stores.get("credentials").records.values()];
};

/** The records' metadata without their key material, for a readable assertion. */
const summary = (fake) => credentialsIn(fake).map((record) => [record.format, record.docType, record.credentialConfigurationId,
    record.issuerSigned.length, record.privateKey && record.privateKey.type, record.privateKey && record.privateKey.extractable]);

/** Opens the wallet page against the same fake database, with the shipped scripts. */
function openWallet(indexedDB) {
    const source = readFileSync(resolve(STATIC, "wallet.html"), "utf8");
    const { ids: elements, scripts } = parseMarkup(source);
    const document = {
        getElementById(id) { return elements.get(String(id)) ?? null; },
        createElement: (tag) => new Element(String(tag).toLowerCase()),
        createTextNode: (data) => new Text(data),
    };
    const context = vm.createContext({
        document,
        console: { log: () => {}, warn: () => {}, error: () => {} },
        setTimeout, clearTimeout, URL, URLSearchParams, Blob, crypto: webcrypto,
        TextEncoder, TextDecoder, btoa, atob, structuredClone, indexedDB,
    });
    let scriptError = null;
    for (const script of scripts) {
        const src = script.attributes.get("src");
        try {
            vm.runInContext(src === undefined ? script.textContent : readFileSync(resolve(STATIC, src), "utf8"), context,
                { filename: src || "wallet.html" });
        } catch (error) {
            scriptError = scriptError || error;
        }
    }
    return { elements, document, scriptError, el: (id) => elements.get(id) ?? null };
}

async function settle() {
    for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done));
}

/** The extractable flag and an export attempt on a kept key, and its signature over a challenge. */
async function checkKeptKey(record, publicJwk) {
    check("P5-03a: the kept private key is non-extractable", record.privateKey.extractable === false);
    let exported = false;
    try {
        await webcrypto.subtle.exportKey("jwk", record.privateKey);
        exported = true;
    } catch (error) {
        exported = false;
    }
    check("P5-03a: the kept private key cannot be exported", exported === false);
    const challenge = Buffer.from("P5-03a challenge");
    const signature = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, record.privateKey, challenge);
    const key = createPublicKey({ key: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, format: "jwk" });
    check("P5-03a: the kept key signs a challenge that verifies with the fixture's public key",
        verify("sha256", challenge, { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature)) === true);
}

/* ---------------------------------------------------------------- checks */

try {

// 1. RFC 8949 Appendix A, for every type the encoder supports
await section("1. Cbor.encode", async () => {
    const vectors = [
        [0, "00"], [23, "17"], [24, "1818"], [255, "18ff"], [256, "190100"], [65535, "19ffff"], [65536, "1a00010000"],
        [4294967296, "1b0000000100000000"], [9007199254740993n, "1b0020000000000001"],
        [-1, "20"], [-25, "3818"], [-18446744073709551616n, "3bffffffffffffffff"],
        [new Uint8Array(0), "40"], [new Uint8Array([1, 2, 3, 4]), "4401020304"],
        ["", "60"], ["IETF", "6449455446"], ["ü", "62c3bc"],
        [[], "80"], [[1, [2, 3]], "8201820203"], [{}, "a0"], [new Map([[1, 2], [3, 4]]), "a201020304"],
        [new Cbor.Tagged(24, new Uint8Array([0xa0])), "d81841a0"],
    ];
    for (const [value, expected] of vectors) {
        const label = typeof value === "bigint" ? String(value) : value instanceof Uint8Array ? "h'" + hex(value) + "'"
            : value instanceof Map ? "Map" : value instanceof Cbor.Tagged ? "Tagged(24, h'a0')" : JSON.stringify(value);
        equal(`RFC 8949 Appendix A: ${label}`, hex(Cbor.encode(value)), expected);
    }
    // 2^64 is the first value a head cannot hold: tag 2 bignum (RFC 8949 3.4.3)
    equal("RFC 8949 Appendix A: 2^64 is a tag-2 bignum", hex(Cbor.encode(18446744073709551616n)), "c249010000000000000000");
    equal("RFC 8949 Appendix A: -1-2^64 is a tag-3 bignum", hex(Cbor.encode(-18446744073709551617n)), "c349010000000000000000");
    for (const [label, value] of [["a float", 1.5], ["undefined", undefined], ["a Date", new Date(0)], ["NaN", NaN]]) {
        let refused = false;
        try { Cbor.encode(value); } catch (error) { refused = true; }
        check(`Cbor.encode refuses ${label}`, refused);
    }
    for (const [label, bytes] of [["a non-item", new Uint8Array([0x1c])], ["two items", new Uint8Array([0x01, 0x02])],
        ["an empty buffer", new Uint8Array(0)]]) {
        let refused = false;
        try { new Cbor.Raw(bytes); } catch (error) { refused = true; }
        check(`Cbor.Raw refuses ${label}`, refused);
    }
    equal("Cbor.Raw emits exactly the item it was given", hex(Cbor.encode(new Cbor.Raw(new Uint8Array([0x82, 0x01, 0x02])))), "820102");
});

// 2. the non-extractable holder key, and the proof the page still sends
await section("2. holder key and proof", async () => {
    const page = openOffer();
    await issue(page);
    check("the shipped page scripts ran", page.scriptError === null, page.scriptError && String(page.scriptError.stack));
    const request = page.requests.filter((entry) => entry.method === "POST" && typeof entry.body === "string" && entry.body.includes("\"proofs\"")).pop();
    const proof = request && JSON.parse(request.body).proofs.jwt[0];
    check("the page still sends one compact proof JWT", typeof proof === "string" && proof.split(".").length === 3);
    const [, claimsPart] = proof.split(".");
    const claims = JSON.parse(Buffer.from(claimsPart, "base64url").toString("utf8"));
    equal("the proof claims are unchanged: aud, iat and the nonce the issuer gave", Object.keys(claims).sort(), ["aud", "iat", "nonce"]);
    equal("aud is still the credential issuer", claims.aud, OID4VCI_ISSUER);
    const [record] = credentialsIn(page.indexedDB);
    await checkKeptKey(record, HOLDER_A_JWK);
});

// 3. issuing keeps exactly one record, byte for byte
await section("3. keep one credential", async () => {
    const page = openOffer();
    await issue(page);
    equal("one credential is kept", credentialsIn(page.indexedDB).length, 1);
    const [record] = credentialsIn(page.indexedDB);
    equal("the record is the shape the plan names", summary(page.indexedDB),
        [["mso_mdoc", DOC_TYPE, "mdoc", MDL_A.bytes.length, "private", false]]);
    equal("the kept issuerSigned is the fixture's bytes", hex(record.issuerSigned), hex(MDL_A.bytes));
    equal("the public key is the holder's, and carries no private member", [record.publicJwk.x, record.publicJwk.y, "d" in record.publicJwk],
        [HOLDER_A_JWK.x, HOLDER_A_JWK.y, false]);
    equal("the record names the issuer and the configuration", [record.credentialIssuer, record.credentialConfigurationId],
        [OID4VCI_ISSUER, "mdoc"]);
    check("the record carries its validity window", record.validFrom === "2026-11-01T00:00:00Z" && record.validUntil === "2026-12-01T00:00:00Z");
    check("the page says what it kept", page.el("keepNote").hidden === false && page.el("keepNote").textContent.includes("Kept in this browser"),
        page.el("keepNote").textContent);
    // I9: keeping is a local write. Every request the run made is one the issuance flow already made: the page's own
    // paths on this origin, or the issuer and authorization server documents and endpoints the offer named.
    equal("keeping sends nothing anywhere else", page.requests.filter((request) =>
        !request.url.startsWith("/v1/certify/") && !request.url.startsWith("https://credentials.example/")).map((request) => request.url), []);
});

// 4. Mdoc.readIssuerSigned: the raw slices are the issued items, and they reassemble the nameSpaces byte for byte
await section("4. readIssuerSigned", async () => {
    const read = Mdoc.readIssuerSigned(MDL_A.bytes);
    equal("the docType and algorithm are read from the MSO", [read.issuerAuth.mso.docType, read.issuerAuth.mso.digestAlgorithm],
        [DOC_TYPE, "SHA-256"]);
    equal("the IssuerAuth keeps its ES256 algorithm", read.issuerAuth.alg, -7);
    const namespace = "org.iso.18013.5.1";
    equal("every element is read", read.nameSpaces[namespace].map((item) => item.elementIdentifier),
        Object.keys(MDL_ELEMENTS[namespace]));
    for (const item of read.nameSpaces[namespace]) {
        equal(`the slice of ${item.elementIdentifier} starts with the tag-24 head`, hex(item.raw.subarray(0, 2)), "d818");
        equal(`the slice of ${item.elementIdentifier} hashes to the MSO's valueDigest`,
            hex(hash("sha256", item.raw)), hex(MDL_A.digests.get(namespace).get(item.digestID)));
    }
    const rebuilt = Cbor.encode(new Map([...MDL_A.nameSpaces].map(([name, items]) => [name, items.map((item) => new Cbor.Raw(item))])));
    // the fixture's own nameSpaces value, cut out of the bytes as issued
    const nameSpacesRange = Cbor.spans(MDL_A.bytes, 1).ranges.find((range) => range.path.length === 1 && range.path[0] === "nameSpaces");
    equal("the slices with their array headers reassemble nameSpaces byte for byte", hex(rebuilt),
        hex(MDL_A.bytes.subarray(nameSpacesRange.start, nameSpacesRange.end)));
    equal("the IssuerAuth's raw slice is the whole COSE_Sign1", hex(read.issuerAuth.raw),
        hex(MDL_A.bytes.subarray(MDL_A.bytes.length - read.issuerAuth.raw.length)));
});

// 5. checks 1-5 of plan 4.2, each with its own refusal
await section("5. checkKeepable refusals", async () => {
    const doctype = DOC_TYPE;
    const keep = (credential, extra = {}) => Mdoc.checkKeepable(Object.assign({
        issuerSigned: credential.bytes, doctype, publicJwk: HOLDER_A_JWK, stored: 0,
    }, extra));
    const refused = async (label, result, expected) => {
        check(`checkKeepable refuses ${label}`, result.ok === false && result.message.includes(expected), JSON.stringify(result));
    };
    await refused("undecodable bytes", await keep({ bytes: new Uint8Array([0xff, 0x00]) }), "not an IssuerSigned");
    await refused("an IssuerAuth payload that is not tag 24",
        await keep(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS, tag24Payload: false })),
        "tag-24 MSO");
    await refused("another doctype than the configuration's", await keep(PID), "docType");
    await refused("another credential's key", await keep(MDL_B), "another holder");
    await refused("a P-384 deviceKey", await keep(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK,
        elements: MDL_ELEMENTS, deviceKey: new Map([[1, 2], [-1, 2], [-2, new Uint8Array(48)], [-3, new Uint8Array(48)]]) })),
        "P-256");
    await refused("a changed element value", await keep(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK,
        elements: MDL_ELEMENTS, tamper: "given_name" })), "does not hash");
    await refused("257 KiB", await keep({ bytes: new Uint8Array(257 * 1024) }), "at most");
    await refused("the 51st credential", await keep(MDL_A, { stored: 50 }), "delete one first");
    equal("the fixture passes every check", (await keep(MDL_A)).ok, true);
});

// 6. what the page does with a refusal: nothing kept, the check named, and the issuance result unchanged
await section("6. the page refuses to keep a wrong credential", async () => {
    const cases = [
        ["another credential's key", MDL_B, "another holder"],
        ["another doctype", PID, "docType"],
        ["undecodable bytes", { bytes: new Uint8Array([0xff]) }, "not an IssuerSigned"],
    ];
    for (const [label, credential, expected] of cases) {
        const page = openOffer({ credential: CREDENTIAL_ANSWER([credential]) });
        await issue(page);
        equal(`${label}: nothing is kept`, credentialsIn(page.indexedDB).length, 0);
        check(`${label}: the refusal names the check`, page.el("keepNote").hidden === false
            && page.el("keepNote").textContent.includes(expected), page.el("keepNote").textContent);
        check(`${label}: the issuance result is still reported`, page.el("walletStatus").textContent.includes("Credential issued"),
            page.el("walletStatus").textContent);
    }
});

// 7. two credentials in one response: the first is kept and the page says so
await section("7. two credentials", async () => {
    const page = openOffer({ credential: CREDENTIAL_ANSWER([MDL_A, PID]) });
    await issue(page);
    const kept = credentialsIn(page.indexedDB);
    equal("only the first credential is kept", kept.length, 1);
    equal("and it is the first one", hex(kept[0].issuerSigned), hex(MDL_A.bytes));
    check("the page says the rest were shown, not kept", page.el("keepNote").textContent.includes("only the first was kept"),
        page.el("keepNote").textContent);
});

// 8. when nothing may be kept: the box unticked, another format, or no IndexedDB
await section("8. nothing kept", async () => {
    const unticked = openOffer();
    await unticked.settle();
    unticked.el("keep").checked = false;
    unticked.el("subject").value = "mdl-demo-1";
    await unticked.createOffer();
    await unticked.runWallet();
    await unticked.settle();
    equal("unticked: nothing is kept", credentialsIn(unticked.indexedDB).length, 0);
    check("unticked: issuance is as today", unticked.el("walletStatus").textContent.includes("Credential issued"));

    const other = openOffer({ configurations: { demo: { format: "ldp_vc" } }, configurationId: "demo",
        credential: { status: 200, body: { credentials: [{ credential: "ldp-credential" }] } } });
    await issue(other);
    equal("a non-mso_mdoc configuration: the Keep box is hidden", other.el("keepLabel").hidden, true);
    equal("a non-mso_mdoc configuration: nothing is kept", credentialsIn(other.indexedDB).length, 0);

    const noStore = openOffer({ indexedDB: null });
    await issue(noStore);
    equal("no IndexedDB: nothing is kept", noStore.indexedDB, null);
    check("no IndexedDB: the page says so once", noStore.el("keepNote").hidden === false
        && noStore.el("keepNote").textContent.includes("IndexedDB"), noStore.el("keepNote").textContent);
    check("no IndexedDB: issuance is as today", noStore.el("walletStatus").textContent.includes("Credential issued"));
});

// 9. the 51st credential, through the page
await section("9. the 51st credential", async () => {
    const fake = new FakeIndexedDB();
    fake.seed("credentials", Array.from({ length: 50 }, (item, index) => ({ id: "seed-" + index, storedAt: index })));
    const page = openOffer({ indexedDB: fake });
    await issue(page);
    equal("the 51st is refused", credentialsIn(fake).length, 50);
    check("with 'delete one first'", page.el("keepNote").textContent.includes("delete one first"), page.el("keepNote").textContent);
});

// 10. the wallet page: list, details, delete one, delete everything
await section("10. the wallet page", async () => {
    const fake = new FakeIndexedDB();
    const first = openOffer({ indexedDB: fake });
    await issue(first);
    const second = openOffer({ indexedDB: fake });
    await issue(second);
    equal("two credentials were kept", credentialsIn(fake).length, 2);

    const wallet = openWallet(fake);
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    await settle();
    const list = wallet.el("records");
    equal("the list shows both", list.children.length, 2);
    equal("and is not empty", wallet.el("empty").hidden, true);
    equal("Delete everything is enabled", wallet.el("deleteAll").disabled, false);
    const opened = list.children[0].children[0];
    await opened.fire("click");
    equal("the details view opens", wallet.el("details").hidden, false);
    check("the details name the docType and show an element", wallet.el("detailsTable").children.length >= 6,
        String(wallet.el("detailsTable").children.length));
    equal("the details title is the credential's label", wallet.el("detailsTitle").textContent, DOC_TYPE);

    await wallet.el("delete").fire("click");
    await settle();
    equal("Delete removes one record", credentialsIn(fake).length, 1);
    equal("the list follows", list.children.length, 1);

    await wallet.el("deleteAll").fire("click");
    await settle();
    equal("Delete everything empties the store", credentialsIn(fake).length, 0);
    equal("the empty message is shown", wallet.el("empty").hidden, false);
    equal("the list follows", list.children.length, 0);
});

// 11. the page's own headers are the controller's job; here: the page the controller serves has one inline script,
//     and the wallet page none, so the CSP the controller builds covers exactly them
await section("11. page scripts and the CSP hash", async () => {
    const html = readFileSync(resolve(STATIC, "index.html"), "utf8");
    const inline = parseMarkup(html).scripts.filter((script) => !script.attributes.has("src"));
    equal("the offer page has exactly one inline script", inline.length, 1);
    const digest = createHash("sha256").update(inline[0].textContent, "utf8").digest("base64");
    equal("its CSP hash is the SHA-256 of its text, base64", digest.length, 44);
    equal("the wallet page has no inline script",
        parseMarkup(readFileSync(resolve(STATIC, "wallet.html"), "utf8")).scripts.filter((script) => !script.attributes.has("src")).length, 0);
    // OfferPageTest recomputes this hash from the bytes /offer/ serves and finds it in the header; the controller's own
    // template is the header list of plan 4.13
    const controller = readFileSync(resolve(REPO, "certify-service/src/main/java/io/mosip/certify/offer/OfferPageController.java"), "utf8");
    for (const directive of ["default-src 'none'", "style-src 'self' 'unsafe-inline'", "img-src 'self' blob: data:",
        "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'", "object-src 'none'", "camera=()", "camera=(self)"]) {
        check(`OfferPageController carries "${directive}"`, controller.includes(directive));
    }
});

} finally {
    const { checks, failures } = counts();
    console.log();
    if (!checks) check("the harness ran at least one check", false);
    if (failures) {
        console.log(`check-offer-wallet: ${failures} of ${counts().checks} checks FAILED`);
    } else {
        console.log(`check-offer-wallet: all ${checks} checks passed`);
    }
    process.exitCode = failures ? 1 : 0;
}
