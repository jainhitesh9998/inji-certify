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
 * The fixtures are of two kinds, on purpose:
 *
 * - one recorded from **Certify's own `MdocFormatter`** (`certify-format-mdoc`'s WalletFixtureRecorder, plan 4.12),
 *   committed under docs/design/tools/fixtures/wallet/ with the holder key it was issued to. This is the layout the
 *   issuer really writes - an IssuerAuth whose payload is a bstr holding `#6.24(bstr .cbor MSO)`, and a DSC-only
 *   x5chain as a single bstr (RFC 9360 section 2) - and it is what a self-built fixture got wrong.
 * - built here, byte part by byte part, in the same ISO/IEC 18013-5 8.3.2.1.2 shape, plus the encodings a reader must
 *   also accept: a non-preferred tag head (`d9 00 18`), indefinite lengths, a `#6.18`-tagged COSE_Sign1. Each part's
 *   expected [start, end) is recorded as it is concatenated, so the slices and digests are computed independently of
 *   `Cbor.spans`, the reader under test.
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
const FIXTURES = resolve(REPO, "docs/design/tools/fixtures/wallet");
const DOC_TYPE = "org.iso.18013.5.1.mDL";
const PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
const MDL_NAMESPACE = "org.iso.18013.5.1";
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
const sameBytes = (left, right) => hex(left) === hex(right);

/* ---------------------------------------------------------------- fixtures */

/**
 * Concatenates byte parts, recording each part's [start, end) as it is written. A fixture's expected slices therefore
 * come from the concatenation itself - not from `Cbor.spans`, the reader under test.
 */
class Bytes {
    constructor() {
        this.parts = [];
        this.length = 0;
    }

    add(part) {
        const bytes = Buffer.from(part);
        const start = this.length;
        this.parts.push(bytes);
        this.length += bytes.length;
        return { start, end: this.length };
    }

    bytes() {
        return new Uint8Array(Buffer.concat(this.parts, this.length));
    }
}

/** The preferred CBOR head for a major type and argument, written here rather than by `Cbor.encode`. */
function head(major, argument) {
    const bits = major << 5;
    if (argument < 24) return Uint8Array.of(bits | argument);
    if (argument < 256) return Uint8Array.of(bits | 24, argument);
    if (argument < 65536) return Uint8Array.of(bits | 25, argument >> 8, argument & 0xff);
    return Uint8Array.of(bits | 26, (argument >>> 24) & 0xff, (argument >> 16) & 0xff, (argument >> 8) & 0xff, argument & 0xff);
}

const tstr = (value) => {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([Buffer.from(head(3, bytes.length)), bytes]);
};
const bstr = (value) => Buffer.concat([Buffer.from(head(2, value.length)), Buffer.from(value)]);
/** A tag head, in its preferred form or in the (legal, non-preferred) three-byte form RFC 8949 allows. */
const tagHead = (tag, nonPreferred) => nonPreferred ? Uint8Array.of(0xd9, tag >> 8, tag & 0xff) : head(6, tag);

/** A stand-in for a DER certificate: mdoc.js reads the chain into a list, it does not parse certificates. */
const DUMMY_DER = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);
const SECOND_DER = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x02]);

const HOLDER_A = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const HOLDER_B = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const HOLDER_A_JWK = await webcrypto.subtle.exportKey("jwk", HOLDER_A.publicKey);
const HOLDER_B_JWK = await webcrypto.subtle.exportKey("jwk", HOLDER_B.publicKey);
const HOLDER_A_PRIVATE = await webcrypto.subtle.exportKey("jwk", HOLDER_A.privateKey);

/** A COSE_Key for a P-256 JWK, or the override a negative case needs. */
function coseKey(jwk, override) {
    if (override) return override;
    return new Map([[1, 2], [-1, 1], [-2, bytesOf(Buffer.from(jwk.x, "base64url"))], [-3, bytesOf(Buffer.from(jwk.y, "base64url"))]]);
}

/**
 * Assembles one IssuerSigned the way ISO/IEC 18013-5 8.3.2.1.2 and RFC 9052 4.2 lay it out: `nameSpaces` of tag-24
 * IssuerSignedItemBytes and an `issuerAuth` COSE_Sign1 whose element 2 is a **byte string** holding
 * `#6.24(bstr .cbor MSO)` - the layout Certify's MdocFormatter writes. `options.forms` selects the encodings a reader
 * must also accept (`nonPreferredTagHead`, `indefiniteLengths`, `taggedCose`); `options.tamper` re-encodes one element's
 * value after its digest was computed (check 4); `options.payloadWithoutTag` writes the bare MSO map as the payload's
 * content, which is the "not tag 24" refusal (check 1).
 */
function buildIssuerSigned(options) {
    const forms = options.forms || {};
    const algorithm = options.digestAlgorithm || "SHA-256";
    const msoTag = tagHead(24, forms.nonPreferredTagHead);
    const coseTag = tagHead(18, forms.nonPreferredTagHead);

    const itemParts = new Map();
    const digests = new Map();
    let digestId = 0;
    for (const namespace of Object.keys(options.elements)) {
        const byDigestId = new Map();
        const items = [];
        for (const [identifier, value] of Object.entries(options.elements[namespace])) {
            const itemMap = (elementValue) => Cbor.encode(new Map([
                ["digestID", digestId],
                ["random", new Uint8Array(16).fill(digestId + 1)],
                ["elementIdentifier", identifier],
                ["elementValue", elementValue],
            ]));
            const signed = Buffer.concat([Buffer.from(msoTag), bstr(itemMap(value))]);
            const written = options.tamper === identifier
                ? Buffer.concat([Buffer.from(msoTag), bstr(itemMap("changed after signing"))])
                : signed;
            byDigestId.set(digestId, hash(algorithm, signed));
            items.push({ elementIdentifier: identifier, digestID: digestId, bytes: new Uint8Array(written) });
            digestId++;
        }
        digests.set(namespace, byDigestId);
        itemParts.set(namespace, items);
    }

    const chain = options.x5chain === undefined ? [DUMMY_DER] : (Array.isArray(options.x5chain) ? options.x5chain : [options.x5chain]);
    const x5chainValue = options.chainForm === "array" || chain.length > 1
        ? Buffer.concat([Buffer.from(head(4, chain.length)), ...chain.map((der) => bstr(der))])
        : bstr(chain[0]);

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
    const trailing = Buffer.from(options.payloadTrailing || []);
    // ISO/IEC 18013-5 9.1.2.4: the payload's content is #6.24(bstr .cbor MSO), tag head and all - and nothing else
    const payload = options.payloadWithoutTag
        ? Buffer.concat([msoBytes, trailing])
        : Buffer.concat([Buffer.from(msoTag), bstr(msoBytes), trailing]);

    // issuerAuth: [protected, unprotected, payload, signature] (RFC 9052 4.2); element 2 is a bstr either way
    const issuerAuth = new Bytes();
    issuerAuth.add(forms.indefiniteLengths ? Uint8Array.of(0x9f) : head(4, 4));
    issuerAuth.add(bstr(Cbor.encode(new Map([[1, -7]]))));
    issuerAuth.add(Buffer.concat([Buffer.from(head(5, 1)), head(0, 33),
        Buffer.from(options.x5chainRaw === undefined ? x5chainValue : options.x5chainRaw)]));
    issuerAuth.add(bstr(payload));
    issuerAuth.add(bstr(new Uint8Array(64))); // a placeholder signature: the page checks structure, not this signature
    if (forms.indefiniteLengths) issuerAuth.add(Uint8Array.of(0xff));
    let issuerAuthBytes = Buffer.from(issuerAuth.bytes());
    if (forms.taggedCose) issuerAuthBytes = Buffer.concat([Buffer.from(coseTag), issuerAuthBytes]);

    // the IssuerSigned map, its parts' ranges recorded as they are written
    const out = new Bytes();
    out.add(forms.indefiniteLengths ? Uint8Array.of(0xbf) : head(5, 2));
    out.add(tstr("nameSpaces"));
    const nameSpacesStart = out.length;
    out.add(forms.indefiniteLengths ? Uint8Array.of(0xbf) : head(5, itemParts.size));
    const items = new Map();
    for (const [namespace, namespaceItems] of itemParts) {
        out.add(tstr(namespace));
        out.add(forms.indefiniteLengths ? Uint8Array.of(0x9f) : head(4, namespaceItems.length));
        const ranges = [];
        for (const item of namespaceItems) {
            const range = out.add(item.bytes);
            ranges.push({ elementIdentifier: item.elementIdentifier, digestID: item.digestID, start: range.start, end: range.end });
        }
        if (forms.indefiniteLengths) out.add(Uint8Array.of(0xff));
        items.set(namespace, ranges);
    }
    if (forms.indefiniteLengths) out.add(Uint8Array.of(0xff)); // closes nameSpaces' own map
    const nameSpacesRange = { start: nameSpacesStart, end: out.length };
    out.add(tstr("issuerAuth"));
    const issuerAuthRange = out.add(issuerAuthBytes);
    if (forms.indefiniteLengths) out.add(Uint8Array.of(0xff)); // closes the IssuerSigned map
    return { bytes: out.bytes(), items, nameSpacesRange, issuerAuthRange, digests, mso, docType: options.docType };
}

const MDL_ELEMENTS = {
    [MDL_NAMESPACE]: {
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
/** The same mDL in the encodings a byte-preserving reader must also accept (RFC 8949 3.1, 3.2.3; RFC 9052 4.2). */
const MDL_TAGGED_COSE = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
    forms: { taggedCose: true } });
const MDL_NON_PREFERRED = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
    forms: { nonPreferredTagHead: true, taggedCose: true } });
const MDL_INDEFINITE = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
    forms: { indefiniteLengths: true } });
const MDL_TWO_CERTIFICATES = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
    x5chain: [DUMMY_DER, SECOND_DER], chainForm: "array" });

/**
 * The IssuerSigned Certify's own MdocFormatter produced, and the holder key it was issued to (plan 4.12). Recorded with
 * `mvn -pl certify-format-mdoc test -Dwallet.fixture.record=true`; see docs/design/tools/fixtures/wallet/README.md.
 */
const CERTIFY_ISSUER_SIGNED = bytesOf(readFileSync(resolve(FIXTURES, "certify-mdl.issuersigned")));
const CERTIFY_HOLDER = JSON.parse(readFileSync(resolve(FIXTURES, "certify-mdl.holder.jwk"), "utf8"));
const CERTIFY_PUBLIC_JWK = { kty: CERTIFY_HOLDER.kty, crv: CERTIFY_HOLDER.crv, x: CERTIFY_HOLDER.x, y: CERTIFY_HOLDER.y };

/** The page's WebCrypto with `generateKey` answering the fixture holder's key, imported non-extractable. */
function cryptoForFixture(holder = { publicJwk: HOLDER_A_JWK, privateJwk: HOLDER_A_PRIVATE }) {
    const calls = [];
    return {
        subtle: new Proxy(webcrypto.subtle, {
            get(target, property) {
                if (property === "generateKey") {
                    return async (...args) => {
                        calls.push(args);
                        return {
                            privateKey: await webcrypto.subtle.importKey("jwk", holder.privateJwk,
                                { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]),
                            publicKey: await webcrypto.subtle.importKey("jwk", holder.publicJwk,
                                { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
                        };
                    };
                }
                const value = Reflect.get(target, property);
                return typeof value === "function" ? value.bind(target) : value;
            },
        }),
        randomUUID: () => webcrypto.randomUUID(),
        getRandomValues: (array) => webcrypto.getRandomValues(array),
        // every call the page made, in order: (algorithm, extractable, usages)
        generateKeyCalls: calls,
    };
}

/** The page's WebCrypto with the **real** `generateKey`: it records what the page asked for and the pair it produced. */
function cryptoRecordingRealKeys() {
    const calls = [];
    const pairs = [];
    return {
        subtle: new Proxy(webcrypto.subtle, {
            get(target, property) {
                if (property === "generateKey") {
                    return async (...args) => {
                        calls.push(args);
                        const pair = await webcrypto.subtle.generateKey(...args);
                        pairs.push(pair);
                        return pair;
                    };
                }
                const value = Reflect.get(target, property);
                return typeof value === "function" ? value.bind(target) : value;
            },
        }),
        randomUUID: () => webcrypto.randomUUID(),
        getRandomValues: (array) => webcrypto.getRandomValues(array),
        generateKeyCalls: calls,
        generatedPairs: pairs,
    };
}

/**
 * Asserts the one call the page must make (plan 4.2): a P-256 ECDSA key, generated non-extractable, usable only for
 * signing. Asserting what the page asked for is the point: a stub that ignored its arguments let a page asking for an
 * extractable key pass every other check.
 */
function assertGenerateKeyCall(label, calls) {
    equal(`${label}: the page generated exactly one key`, calls.length, 1);
    if (!calls.length) return;
    const [algorithm, extractable, usages] = calls[0];
    equal(`${label}: the key is ECDSA P-256`, [algorithm && algorithm.name, algorithm && algorithm.namedCurve], ["ECDSA", "P-256"]);
    equal(`${label}: the private key was generated non-extractable`, extractable, false);
    equal(`${label}: its only usage is sign`, [...usages], ["sign"]);
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
        // P5-03a: /offer/wallet/config. 404 means certify.offer-page.wallet.enabled=false: no Keep box, no storage.
        walletConfig: options.walletConfig === undefined ? true : options.walletConfig,
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
    for (let i = 0; i < 60; i++) await new Promise((done) => setImmediate(done));
}

/** The extractable flag and an export attempt on a kept key, and its signature over a challenge. */
async function checkKeptKey(record, publicJwk, label = "") {
    check(`P5-03a: the kept private key is non-extractable${label}`, record.privateKey.extractable === false);
    let exported = false;
    try {
        await webcrypto.subtle.exportKey("jwk", record.privateKey);
        exported = true;
    } catch (error) {
        exported = false;
    }
    check(`P5-03a: the kept private key cannot be exported${label}`, exported === false);
    const challenge = Buffer.from("P5-03a challenge");
    const signature = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, record.privateKey, challenge);
    const key = createPublicKey({ key: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, format: "jwk" });
    check(`P5-03a: the kept key signs a challenge that verifies with the fixture's public key${label}`,
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
        [[], "80"], [[1, [2, 3]], "8201820203"], [new Map(), "a0"], [new Map([[1, 2], [3, 4]]), "a201020304"],
        [new Cbor.Tagged(24, new Uint8Array([0xa0])), "d81841a0"],
        // plan 4.3: the two constructors work without `new`, as the plan writes them
        [Cbor.Tagged(24, new Uint8Array([0xa0])), "d81841a0"],
    ];
    for (const [value, expected] of vectors) {
        const label = typeof value === "bigint" ? String(value) : value instanceof Uint8Array ? "h'" + hex(value) + "'"
            : value instanceof Map ? "Map" : value instanceof Cbor.Tagged ? "Tagged(24, h'a0')" : JSON.stringify(value);
        equal(`RFC 8949 Appendix A: ${label}`, hex(Cbor.encode(value)), expected);
    }
    // 2^64 is the first value a head cannot hold: tag 2 bignum (RFC 8949 3.4.3)
    equal("RFC 8949 Appendix A: 2^64 is a tag-2 bignum", hex(Cbor.encode(18446744073709551616n)), "c249010000000000000000");
    equal("RFC 8949 Appendix A: -1-2^64 is a tag-3 bignum", hex(Cbor.encode(-18446744073709551617n)), "c349010000000000000000");
    equal("Cbor.Raw works without new", hex(Cbor.encode(Cbor.Raw(new Uint8Array([0x82, 0x01, 0x02])))), "820102");
    for (const [label, value] of [["a float", 1.5], ["undefined", undefined], ["a Date", new Date(0)], ["NaN", NaN],
        ["a plain object (only Map is a map, plan 4.3)", { 1: 2 }]]) {
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

// 2. Mdoc.readIssuerSigned: the raw slices are the issued items, exactly as the bytes carry them
await section("2. readIssuerSigned", async () => {
    const read = Mdoc.readIssuerSigned(MDL_A.bytes);
    equal("the docType and algorithm are read from the MSO", [read.issuerAuth.mso.docType, read.issuerAuth.mso.digestAlgorithm],
        [DOC_TYPE, "SHA-256"]);
    equal("the IssuerAuth keeps its ES256 algorithm", read.issuerAuth.alg, -7);
    equal("every element is read", read.nameSpaces[MDL_NAMESPACE].map((item) => item.elementIdentifier),
        Object.keys(MDL_ELEMENTS[MDL_NAMESPACE]));
    for (const item of read.nameSpaces[MDL_NAMESPACE]) {
        const expected = MDL_A.items.get(MDL_NAMESPACE).find((entry) => entry.elementIdentifier === item.elementIdentifier);
        check(`the slice of ${item.elementIdentifier} is the IssuerSignedItemBytes the fixture wrote`,
            sameBytes(item.raw, MDL_A.bytes.subarray(expected.start, expected.end)),
            hex(item.raw));
        equal(`the slice of ${item.elementIdentifier} hashes to the MSO's valueDigest`,
            hex(hash("sha256", item.raw)), hex(MDL_A.digests.get(MDL_NAMESPACE).get(item.digestID)));
        equal(`its digest is the one computed over the same expected bytes`,
            hex(hash("sha256", MDL_A.bytes.subarray(expected.start, expected.end))),
            hex(MDL_A.digests.get(MDL_NAMESPACE).get(item.digestID)));
    }
    // 10: the rebuild comes from the reader's own slices and is compared with the fixture's own bytes, not with the
    // builder's data: the array header is the only thing added
    const rebuilt = Cbor.encode(new Map([...Object.keys(read.nameSpaces).map((namespace) =>
        [namespace, read.nameSpaces[namespace].map((item) => new Cbor.Raw(item.raw))])]));
    equal("the slices with their array headers reassemble the fixture's nameSpaces byte for byte", hex(rebuilt),
        hex(MDL_A.bytes.subarray(MDL_A.nameSpacesRange.start, MDL_A.nameSpacesRange.end)));
    equal("the IssuerAuth's raw slice is the whole COSE_Sign1", hex(read.issuerAuth.raw),
        hex(MDL_A.bytes.subarray(MDL_A.issuerAuthRange.start, MDL_A.issuerAuthRange.end)));

    // 2: RFC 9360 section 2 - COSE_X509 = bstr / [2*certs: bstr]. Certify emits the bstr form for a DSC-only chain.
    equal("a single-certificate x5chain, as a single bstr, is normalised to one certificate", read.issuerAuth.x5chain.length, 1);
    equal("and it is the certificate the fixture carries", hex(read.issuerAuth.x5chain[0]), hex(DUMMY_DER));
    const two = Mdoc.readIssuerSigned(MDL_TWO_CERTIFICATES.bytes);
    equal("the array form keeps both certificates, in order", two.issuerAuth.x5chain.map(hex), [hex(DUMMY_DER), hex(SECOND_DER)]);
    const oneInArray = Mdoc.readIssuerSigned(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK,
        elements: MDL_ELEMENTS, x5chain: [DUMMY_DER], chainForm: "array" }).bytes);
    equal("a one-entry array is read as one certificate too", oneInArray.issuerAuth.x5chain.map(hex), [hex(DUMMY_DER)]);
    let refusedChain = null;
    try {
        Mdoc.readIssuerSigned(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
            x5chainRaw: tstr("not a certificate") }).bytes);
    } catch (error) {
        refusedChain = error;
    }
    check("an x5chain that is not a byte string or an array of them is refused",
        refusedChain !== null && /x5chain/.test(refusedChain.message), refusedChain && refusedChain.message);

    // 9: a tag is recognised by its numeric value, whatever head carries it, and the bytes are kept
    const nonPreferred = Mdoc.readIssuerSigned(MDL_NON_PREFERRED.bytes);
    equal("a non-preferred tag head (d9 00 18) is the same tag 24", hex(nonPreferred.nameSpaces[MDL_NAMESPACE][0].raw.subarray(0, 3)),
        "d90018");
    for (const item of nonPreferred.nameSpaces[MDL_NAMESPACE]) {
        const expected = MDL_NON_PREFERRED.items.get(MDL_NAMESPACE).find((entry) => entry.elementIdentifier === item.elementIdentifier);
        check(`the non-preferred head slice of ${item.elementIdentifier} is byte for byte the fixture's`,
            sameBytes(item.raw, MDL_NON_PREFERRED.bytes.subarray(expected.start, expected.end)));
        equal(`the non-preferred head slice of ${item.elementIdentifier} hashes to the MSO's valueDigest`,
            hex(hash("sha256", item.raw)), hex(MDL_NON_PREFERRED.digests.get(MDL_NAMESPACE).get(item.digestID)));
    }

    // indefinite lengths: the ranges come from the input, so they are still exact
    const indefinite = Mdoc.readIssuerSigned(MDL_INDEFINITE.bytes);
    for (const item of indefinite.nameSpaces[MDL_NAMESPACE]) {
        const expected = MDL_INDEFINITE.items.get(MDL_NAMESPACE).find((entry) => entry.elementIdentifier === item.elementIdentifier);
        check(`an indefinite-length IssuerSigned: the slice of ${item.elementIdentifier} is exact`,
            sameBytes(item.raw, MDL_INDEFINITE.bytes.subarray(expected.start, expected.end)));
        equal(`an indefinite-length IssuerSigned: ${item.elementIdentifier} hashes to its valueDigest`,
            hex(hash("sha256", item.raw)), hex(MDL_INDEFINITE.digests.get(MDL_NAMESPACE).get(item.digestID)));
    }
    equal("the indefinite-length IssuerAuth slice is exact too", hex(indefinite.issuerAuth.raw),
        hex(MDL_INDEFINITE.bytes.subarray(MDL_INDEFINITE.issuerAuthRange.start, MDL_INDEFINITE.issuerAuthRange.end)));

    // 1: a #6.18-tagged COSE_Sign1 reads the same, and `raw` keeps the tag head
    const tagged = Mdoc.readIssuerSigned(MDL_TAGGED_COSE.bytes);
    equal("a #6.18-tagged COSE_Sign1 is read, tag and all", hex(tagged.issuerAuth.raw.subarray(0, 1)), "d2");
    equal("and its MSO comes out of the bstr payload", tagged.issuerAuth.mso.docType, DOC_TYPE);
    equal("the tagged COSE_Sign1's raw slice is the fixture's", hex(tagged.issuerAuth.raw),
        hex(MDL_TAGGED_COSE.bytes.subarray(MDL_TAGGED_COSE.issuerAuthRange.start, MDL_TAGGED_COSE.issuerAuthRange.end)));
    equal("its elements are read as well", tagged.nameSpaces[MDL_NAMESPACE].length, Object.keys(MDL_ELEMENTS[MDL_NAMESPACE]).length);

    // the one shape that must be refused: a bstr holding a bare MSO map, with no tag 24
    let refused = null;
    try {
        Mdoc.readIssuerSigned(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
            payloadWithoutTag: true }).bytes);
    } catch (error) {
        refused = error;
    }
    check("a payload that is a bare MSO map, with no tag 24, is refused", refused !== null && /tag-24/.test(refused.message),
        refused && refused.message);
    let refusedHead = null;
    try {
        // a tag 24 whose content is not a bstr (the tag wraps the map directly) is refused as well
        const bad = new Bytes();
        bad.add(head(5, 2));
        bad.add(tstr("nameSpaces"));
        bad.add(head(5, 0));
        bad.add(tstr("issuerAuth"));
        const cose = new Bytes();
        cose.add(head(4, 4));
        cose.add(bstr(Cbor.encode(new Map([[1, -7]]))));
        cose.add(head(5, 0));
        cose.add(Buffer.concat([Buffer.from(head(6, 24)), Buffer.from(Cbor.encode(new Map([["docType", DOC_TYPE]])))]));
        cose.add(bstr(new Uint8Array(64)));
        bad.add(cose.bytes());
        Mdoc.readIssuerSigned(bad.bytes());
    } catch (error) {
        refusedHead = error;
    }
    check("a tag 24 whose content is not a byte string is refused", refusedHead !== null && /byte string/.test(refusedHead.message),
        refusedHead && refusedHead.message);
    let refusedTrailing = null;
    try {
        Mdoc.readIssuerSigned(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
            payloadTrailing: new Uint8Array([0x00]) }).bytes);
    } catch (error) {
        refusedTrailing = error;
    }
    check("a payload with bytes after the tag-24 item is refused", refusedTrailing !== null && /exactly one/.test(refusedTrailing.message),
        refusedTrailing && refusedTrailing.message);
});

// 3. the IssuerSigned Certify's own MdocFormatter produced (plan 4.12): the layout real mDLs arrive in
await section("3. Certify's own IssuerSigned", async () => {
    const read = Mdoc.readIssuerSigned(CERTIFY_ISSUER_SIGNED);
    equal("the fixture is the mDL the formatter issued", read.issuerAuth.mso.docType, DOC_TYPE);
    equal("its MSO version is the formatter's", read.issuerAuth.mso.version, "1.0");
    equal("the IssuerAuth payload is a bstr holding the tag-24 MSO", read.issuerAuth.mso.digestAlgorithm, "SHA-256");
    check("the validity window is the formatter's tdate text",
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(read.issuerAuth.mso.validityInfo.validFrom)
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(read.issuerAuth.mso.validityInfo.validUntil),
        JSON.stringify(read.issuerAuth.mso.validityInfo));
    // Certify signs without the IACA, so the chain is the DSC alone: RFC 9360 section 2's single bstr, which this
    // reader used to refuse outright
    equal("the DSC-only x5chain arrives as a single bstr and is read as one certificate", read.issuerAuth.x5chain.length, 1);
    check("and it is a real DER certificate, not a placeholder", read.issuerAuth.x5chain[0].length > 300,
        String(read.issuerAuth.x5chain[0].length));
    const items = read.nameSpaces[MDL_NAMESPACE];
    check("every element the formatter salted is read", items.length >= 12, String(items.length));
    for (const item of items) {
        const expected = read.issuerAuth.mso.valueDigests[MDL_NAMESPACE][String(item.digestID)];
        equal(`Certify fixture: ${item.elementIdentifier} hashes to its valueDigest`, hex(hash("sha256", item.raw)), hex(expected));
    }
    const verdict = await Mdoc.checkKeepable({ issuerSigned: CERTIFY_ISSUER_SIGNED, doctype: DOC_TYPE,
        publicJwk: CERTIFY_PUBLIC_JWK });
    check("Certify's own credential passes every keep check", verdict.ok === true, JSON.stringify(verdict));
    equal("and it reports the formatter's docType", verdict.docType, DOC_TYPE);

    // the same bytes through the page: kept exactly once, byte for byte, with the key the fixture was issued to
    const crypto = cryptoForFixture({ publicJwk: CERTIFY_PUBLIC_JWK, privateJwk: CERTIFY_HOLDER });
    const page = openOffer({ crypto, credential: CREDENTIAL_ANSWER([{ bytes: CERTIFY_ISSUER_SIGNED }]) });
    await issue(page);
    assertGenerateKeyCall("Certify fixture through the page", crypto.generateKeyCalls);
    const kept = credentialsIn(page.indexedDB);
    equal("Certify's own mDL is kept, exactly once", kept.length, 1);
    equal("and byte for byte", hex(kept[0].issuerSigned), hex(CERTIFY_ISSUER_SIGNED));
    equal("the record names the docType the MSO carries", kept[0].docType, DOC_TYPE);
    check("the page says it kept it", page.el("keepNote").hidden === false
        && page.el("keepNote").textContent.includes("Kept in this browser"), page.el("keepNote").textContent);
    await checkKeptKey(kept[0], CERTIFY_PUBLIC_JWK, " (Certify fixture)");
});

// 4. the holder key: what the page asks WebCrypto for, and the proof it still sends
await section("4. holder key and proof", async () => {
    const crypto = cryptoForFixture();
    const page = openOffer({ crypto });
    await issue(page);
    check("the shipped page scripts ran", page.scriptError === null, page.scriptError && String(page.scriptError.stack));
    // 6: the arguments the page passed, not only what the stub handed back
    assertGenerateKeyCall("fixture key", crypto.generateKeyCalls);
    const request = page.requests.filter((entry) => entry.method === "POST" && typeof entry.body === "string" && entry.body.includes("\"proofs\"")).pop();
    const proof = request && JSON.parse(request.body).proofs.jwt[0];
    check("the page still sends one compact proof JWT", typeof proof === "string" && proof.split(".").length === 3);
    const [, claimsPart] = proof.split(".");
    const claims = JSON.parse(Buffer.from(claimsPart, "base64url").toString("utf8"));
    equal("the proof claims are unchanged: aud, iat and the nonce the issuer gave", Object.keys(claims).sort(), ["aud", "iat", "nonce"]);
    equal("aud is still the credential issuer", claims.aud, OID4VCI_ISSUER);
    const [record] = credentialsIn(page.indexedDB);
    await checkKeptKey(record, HOLDER_A_JWK);

    // 6: and one run with the real generateKey, whose key is genuinely the browser's: non-extractable, not exportable
    const real = cryptoRecordingRealKeys();
    const realPage = openOffer({ crypto: real });
    await issue(realPage);
    assertGenerateKeyCall("real generateKey", real.generateKeyCalls);
    equal("real generateKey: one pair was produced", real.generatedPairs.length, 1);
    const [pair] = real.generatedPairs;
    equal("real generateKey: the private key is non-extractable", pair.privateKey.extractable, false);
    let exported = false;
    try {
        await webcrypto.subtle.exportKey("jwk", pair.privateKey);
        exported = true;
    } catch (error) {
        exported = false;
    }
    check("real generateKey: exportKey('jwk', privateKey) rejects", exported === false);
    const signature = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, Buffer.from("challenge"));
    const publicJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
    const key = createPublicKey({ key: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, format: "jwk" });
    check("real generateKey: the key it produced signs and verifies",
        verify("sha256", Buffer.from("challenge"), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature)) === true);
    check("real generateKey: issuance is as before", realPage.el("walletStatus").textContent.includes("Credential issued"),
        realPage.el("walletStatus").textContent);
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
        await keep(buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS, payloadWithoutTag: true })),
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

// 7. issuing keeps exactly one record, byte for byte
await section("7. keep one credential", async () => {
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

// 8. two credentials in one response: the first is kept and the page says so
await section("8. two credentials", async () => {
    const page = openOffer({ credential: CREDENTIAL_ANSWER([MDL_A, PID]) });
    await issue(page);
    const kept = credentialsIn(page.indexedDB);
    equal("only the first credential is kept", kept.length, 1);
    equal("and it is the first one", hex(kept[0].issuerSigned), hex(MDL_A.bytes));
    check("the page says the rest were shown, not kept", page.el("keepNote").textContent.includes("only the first was kept"),
        page.el("keepNote").textContent);
});

// 9. when nothing may be kept: the box unticked, another format, or no IndexedDB
await section("9. nothing kept", async () => {
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

// 10. I4: with the wallet switched off, /offer/wallet/config answers 404 and nothing is stored - not even a store opened
await section("10. the wallet switch gates storage", async () => {
    const fake = new FakeIndexedDB();
    const page = openOffer({ indexedDB: fake, walletConfig: false });
    await issue(page);
    equal("a 404 from /offer/wallet/config: the Keep box is not shown", page.el("keepLabel").hidden, true);
    equal("the offer page does not even link the wallet", page.el("walletLink").hidden, true);
    equal("no connection to the wallet's store was opened", fake.opens, 0);
    equal("and nothing was kept", credentialsIn(fake).length, 0);
    check("issuance is as before", page.el("walletStatus").textContent.includes("Credential issued"),
        page.el("walletStatus").textContent);
    // the endpoint was asked: the page's silence comes from its answer, not from a skipped fetch
    check("the page asked for the wallet's config", page.requests.some((request) => request.url === "/v1/certify/offer/wallet/config"),
        JSON.stringify(page.requests.map((request) => request.url)));
    // and with the wallet on, the same run shows the box and stores the credential: the gate is the answer, not the format
    const enabled = openOffer();
    await issue(enabled);
    equal("with a 200 from /offer/wallet/config the box is shown", enabled.el("keepLabel").hidden, false);
    equal("and the credential is kept", credentialsIn(enabled.indexedDB).length, 1);
});

// 11. the 51st credential, and the cap that two tabs cannot walk past
await section("11. the 50-credential cap", async () => {
    const fake = new FakeIndexedDB();
    fake.seed("credentials", Array.from({ length: 50 }, (item, index) => ({ id: "seed-" + index, storedAt: index })));
    const page = openOffer({ indexedDB: fake });
    await issue(page);
    equal("the 51st is refused", credentialsIn(fake).length, 50);
    check("with 'delete one first'", page.el("keepNote").textContent.includes("delete one first"), page.el("keepNote").textContent);

    // 5: two tabs keeping their 50th and 51st at the same moment. The count and the put share one readwrite
    // transaction, so only one of the two can succeed; with them apart, both would read 49 and 51 would be kept.
    const WalletStore = shipped("wallet-store.js", { indexedDB: fake }, "WalletStore");
    const first = await WalletStore.open();
    const second = await WalletStore.open();
    fake.databases.get(DB_NAME).stores.get("credentials").records.clear();
    for (let index = 0; index < 49; index++) {
        fake.databases.get(DB_NAME).stores.get("credentials").putClone({ id: "concurrent-" + index, storedAt: index });
    }
    const [keptFirst, keptSecond] = await Promise.all([
        WalletStore.putWithinLimit(first, { id: "tab-1", storedAt: 100 }, Mdoc.MAX_CREDENTIALS),
        WalletStore.putWithinLimit(second, { id: "tab-2", storedAt: 101 }, Mdoc.MAX_CREDENTIALS),
    ]);
    equal("two tabs starting at 49 keep exactly one more between them", credentialsIn(fake).length, 50);
    equal("one tab was told its credential was stored", [keptFirst, keptSecond].filter(Boolean).length, 1);
    first.close();
    second.close();
});

// 12. the wallet page: list, details, delete one, delete everything
await section("12. the wallet page", async () => {
    const fake = new FakeIndexedDB();
    const opened = openOffer({ indexedDB: fake });
    await issue(opened);
    const again = openOffer({ indexedDB: fake });
    await issue(again);
    equal("two credentials were kept", credentialsIn(fake).length, 2);

    const wallet = openWallet(fake);
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    await settle();
    const list = wallet.el("records");
    equal("the list shows both", list.children.length, 2);
    equal("and is not empty", wallet.el("empty").hidden, true);
    equal("Delete everything is enabled", wallet.el("deleteAll").disabled, false);
    const openedDetails = list.children[0].children[0];
    await openedDetails.fire("click");
    equal("the details view opens", wallet.el("details").hidden, false);
    check("the details name the docType and show an element", wallet.el("detailsTable").children.length >= 6,
        String(wallet.el("detailsTable").children.length));
    equal("the details title is the credential's label", wallet.el("detailsTitle").textContent, DOC_TYPE);

    await wallet.el("delete").fire("click");
    await settle();
    equal("Delete removes one record", credentialsIn(fake).length, 1);
    equal("the list follows", list.children.length, 1);
    // 16: the confirmation is written where the visitor can still see it: the details section is hidden on success
    equal("the details section is hidden again", wallet.el("details").hidden, true);
    check("the deletion is confirmed in the section that stays on screen",
        wallet.el("storageStatus").textContent.includes("Deleted") && wallet.el("storageStatus").textContent.includes("key went with it"),
        wallet.el("storageStatus").textContent);

    await wallet.el("deleteAll").fire("click");
    await settle();
    equal("Delete everything empties the store", credentialsIn(fake).length, 0);
    equal("the empty message is shown", wallet.el("empty").hidden, false);
    equal("the list follows", list.children.length, 0);
    check("and says so", wallet.el("storageStatus").textContent.includes("was deleted"), wallet.el("storageStatus").textContent);
    // the page reopens the store afterwards (a version-1 open recreates an empty database, as a browser does), so what
    // proves the delete is the delete request's own success, not the database's absence
    equal("the delete request completed", fake.deletions, 1);
});

// 13. Delete everything with another wallet tab open: never hangs, and asks for the one thing that unblocks it
await section("13. Delete everything with another tab open", async () => {
    const fake = new FakeIndexedDB();
    const keepOne = openOffer({ indexedDB: fake });
    await issue(keepOne);
    equal("a credential is kept", credentialsIn(fake).length, 1);

    // two more connections, as two open wallet tabs would hold: the page's own delete closes its own first
    const WalletStore = shipped("wallet-store.js", { indexedDB: fake }, "WalletStore");
    const tabA = await WalletStore.open();
    const tabB = await WalletStore.open();
    let versionChangesA = 0;
    let versionChangesB = 0;
    const pageHandlerA = tabA.onversionchange;
    const pageHandlerB = tabB.onversionchange;
    // the wrapper counts what the browser delivered and then defers to the page's own handler, when it set one
    tabA.onversionchange = (event) => { versionChangesA++; if (typeof pageHandlerA === "function") pageHandlerA(event); };
    tabB.onversionchange = (event) => { versionChangesB++; if (typeof pageHandlerB === "function") pageHandlerB(event); };
    equal("WalletStore's own connection closes itself on versionchange", typeof pageHandlerA, "function");

    // the wallet page opens a third connection; its "Delete everything" closes that one, then deletes
    const wallet = openWallet(fake);
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    await settle();
    await wallet.el("deleteAll").fire("click");
    await settle();
    equal("both other tabs were asked to close", [versionChangesA, versionChangesB], [1, 1]);
    equal("the delete request completed", fake.deletions, 1);
    check("the page says so", wallet.el("storageStatus").textContent.includes("was deleted"), wallet.el("storageStatus").textContent);
    equal("and the closed tabs did close", [tabA.closed, tabB.closed], [true, true]);

    // a tab that ignores the request blocks the delete; the page must say what to do about it instead of waiting
    const blocking = new FakeIndexedDB();
    const keepsOne = openOffer({ indexedDB: blocking });
    await issue(keepsOne);
    const stubborn = await (shipped("wallet-store.js", { indexedDB: blocking }, "WalletStore")).open();
    stubborn.onversionchange = null; // a tab that does not close (an older build, a frozen tab)
    const blockedWallet = openWallet(blocking);
    await settle();
    await blockedWallet.el("deleteAll").fire("click");
    await settle();
    check("a blocked delete is reported, not left hanging",
        blockedWallet.el("storageStatus").textContent.includes("could not be deleted")
        && blockedWallet.el("storageStatus").textContent.includes("close every other wallet tab"),
        blockedWallet.el("storageStatus").textContent);
    equal("and the store is still there", blocking.databases.has(DB_NAME), true);
    equal("the page's own list still works after the refusal", blockedWallet.el("records").children.length, 1);
    stubborn.close();
    await settle();
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
