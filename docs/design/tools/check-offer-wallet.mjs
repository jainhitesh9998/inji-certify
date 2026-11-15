#!/usr/bin/env node
/*
 * P5-03a behaviour check: the offer page keeps an issued mDL in this browser, and the demo wallet lists, shows and
 * deletes what it kept (docs/design/wp/P5-03-demo-wallet-presentation.md, work package P5-03a).
 *
 * Plain Node (24, the version CI pins), no npm dependencies, no browser, no server:
 *   node docs/design/tools/check-offer-wallet.mjs
 * It shares the fake DOM, the fake fetch, the fake IndexedDB and the check helpers with check-offer-page.mjs, and
 * evaluates the page's own `src` scripts (cbor.js, mdoc.js, wallet-store.js, wallet.js; `scripts: "real"`), so
 * `Cbor.encode`, `Mdoc.readIssuerSigned`, `WalletStore` and the wallet page are the shipped files, not stubs.
 *
 * The storage scenarios (`storageConformance`, `walletDeleteScenarios`) are exported and take the IndexedDB factory
 * they run on: run directly they use the harness's fake, and docs/design/tools/wallet-probe/idb-crosscheck.mjs runs
 * the same ones on fake-indexeddb, an implementation of IndexedDB 3.0, so the fake and the page are both held to what
 * the standard does.
 *
 * The fixtures are of two kinds, on purpose:
 *
 * - `mdl-a`, recorded from **Certify's own `MdocFormatter`** (`certify-format-mdoc`'s WalletFixtureRecorderTest, plan
 *   4.12): the 15 elements the demo issues to `mdl-demo-1`, committed under docs/design/tools/fixtures/wallet/ with the
 *   holder key it was issued to. This is the layout the issuer really writes - an IssuerAuth whose payload is a bstr
 *   holding `#6.24(bstr .cbor MSO)`, and a DSC-only x5chain as a single bstr (RFC 9360 section 2) - and it is what a
 *   self-built fixture got wrong.
 * - built here, byte part by byte part, in the same ISO/IEC 18013-5 8.3.2.1.2 shape, plus the encodings a reader must
 *   also accept: a non-preferred tag head (`d9 00 18`), indefinite lengths, a `#6.18`-tagged COSE_Sign1. Each part's
 *   expected [start, end) is recorded as it is concatenated, so the slices and digests are computed independently of
 *   `Cbor.spans`, the reader under test.
 *
 * What it cannot check: a real browser's IndexedDB (the fake is the storage model, cross-checked against
 * fake-indexeddb by wallet-probe/idb-crosscheck.mjs), a rendered layout, and the HTTP headers (check-offer-page.mjs is
 * offline; OfferPageTest recomputes the inline script's hash from the bytes the controller serves and finds it in the
 * Content-Security-Policy).
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify, webcrypto, constants } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { openPage, parseMarkup, check, equal, section, counts, Element, Text, FakeIndexedDB, taskTimers, REPO,
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
 *
 * The shapes a decoder hides, each one a refusal (review round 2): `coseWrap` puts issuerAuth inside another tag than 18
 * (tag 24 as `#6.24(bstr .cbor COSE_Sign1)`); `payloadWrap` tags element 2 (tag 24 as `#6.24(bstr .cbor bstr)`, which
 * decodes to the very bstr a payload is); `protectedAsMap` writes element 0 as a map; `itemForms` writes an element as
 * a bare map (`"bare"`) or `#6.55799(map)` (`"tag55799"`), its digest taken over exactly those bytes so that only the
 * tag-24 check can refuse it.
 *
 * The COSE headers and the MSO's typed maps (review round 3): `protectedRaw` is the protected header's map content (the
 * builder wraps it in the bstr), `unprotectedRaw(x5chainValue)` writes the whole unprotected header map, and
 * `valueDigests(digests)` replaces the MSO's valueDigests (a text DigestID, say).
 *
 * Review round 4: `rawItems[identifier](digestId, random)` writes that element's IssuerSignedItem map bytes by hand (the
 * bstr's content; its digest is taken over the tag-24 item that wraps them), for a key or a digestID `Cbor.encode`
 * would never write; `itemForms` also takes `"tag24tagged"` (`#6.24(#6.99(bstr))`); `msoTag` wraps the MSO map in a
 * tag inside its bstr, and `msoContentTag` wraps that bstr in a tag inside the tag 24.
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
            const rawItem = (options.rawItems || {})[identifier];
            const content = rawItem !== undefined ? Buffer.from(rawItem(digestId, new Uint8Array(16).fill(digestId + 1)))
                : itemMap(value);
            const form = (options.itemForms || {})[identifier];
            const signed = form === "bare" ? Buffer.from(content)
                : form === "tag55799" ? Buffer.concat([Buffer.from(head(6, 55799)), Buffer.from(content)])
                : form === "tag24tagged" ? Buffer.concat([Buffer.from(msoTag), Buffer.from(head(6, 99)), bstr(content)])
                : Buffer.concat([Buffer.from(msoTag), bstr(content)]);
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
        ["valueDigests", options.valueDigests ? options.valueDigests(digests) : digests],
        ["deviceKeyInfo", new Map([["deviceKey", coseKey(options.holder, options.deviceKey)]])],
        ["docType", options.docType],
        ["validityInfo", new Map([["signed", "2026-11-01T00:00:00Z"], ["validFrom", "2026-11-01T00:00:00Z"],
            ["validUntil", "2026-12-01T00:00:00Z"]])],
    ]);
    const msoMap = Buffer.from(Cbor.encode(mso));
    const msoBytes = options.msoTag === undefined ? msoMap : Buffer.concat([Buffer.from(head(6, options.msoTag)), msoMap]);
    const msoContent = options.msoContentTag === undefined ? bstr(msoBytes)
        : Buffer.concat([Buffer.from(head(6, options.msoContentTag)), bstr(msoBytes)]);
    const trailing = Buffer.from(options.payloadTrailing || []);
    // ISO/IEC 18013-5 9.1.2.4: the payload's content is #6.24(bstr .cbor MSO), tag head and all - and nothing else
    const payload = options.payloadWithoutTag
        ? Buffer.concat([msoBytes, trailing])
        : Buffer.concat([Buffer.from(msoTag), msoContent, trailing]);

    // issuerAuth: [protected, unprotected, payload, signature] (RFC 9052 4.2); element 2 is a bstr either way
    const issuerAuth = new Bytes();
    issuerAuth.add(forms.indefiniteLengths ? Uint8Array.of(0x9f) : head(4, 4));
    const protectedMap = options.protectedRaw === undefined ? Cbor.encode(new Map([[1, -7]])) : Buffer.from(options.protectedRaw);
    issuerAuth.add(options.protectedAsMap ? protectedMap : bstr(protectedMap));
    issuerAuth.add(options.unprotectedRaw !== undefined ? Buffer.from(options.unprotectedRaw(x5chainValue))
        : Buffer.concat([Buffer.from(head(5, 1)), head(0, 33),
            Buffer.from(options.x5chainRaw === undefined ? x5chainValue : options.x5chainRaw)]));
    issuerAuth.add(options.payloadWrap === undefined ? bstr(payload)
        : Buffer.concat([Buffer.from(head(6, options.payloadWrap)), options.payloadWrap === 24 ? bstr(bstr(payload)) : bstr(payload)]));
    issuerAuth.add(bstr(new Uint8Array(64))); // a placeholder signature: the page checks structure, not this signature
    if (forms.indefiniteLengths) issuerAuth.add(Uint8Array.of(0xff));
    let issuerAuthBytes = Buffer.from(issuerAuth.bytes());
    if (forms.taggedCose) issuerAuthBytes = Buffer.concat([Buffer.from(coseTag), issuerAuthBytes]);
    if (options.coseWrap !== undefined) {
        issuerAuthBytes = Buffer.concat([Buffer.from(head(6, options.coseWrap)),
            options.coseWrap === 24 ? bstr(issuerAuthBytes) : issuerAuthBytes]);
    }

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
 * `mdl-a`: the IssuerSigned Certify's own MdocFormatter produced for `mdl-demo-1`'s 15 elements, and the holder key it
 * was issued to (plan 4.12). Recorded by WalletFixtureRecorderTest with `-Dwallet.fixture.record=true`; see
 * docs/design/tools/fixtures/wallet/README.md.
 */
const CERTIFY_ISSUER_SIGNED = bytesOf(readFileSync(resolve(FIXTURES, "mdl-a.issuersigned")));
const CERTIFY_HOLDER = JSON.parse(readFileSync(resolve(FIXTURES, "mdl-a.holder.jwk"), "utf8"));
/** The elements the demo issues to mdl-demo-1 (config/mdl/holders.json, config/mdl/mdl.vm), in the template's order. */
const MDL_DEMO_1_ELEMENTS = ["family_name", "given_name", "birth_date", "issue_date", "expiry_date", "issuing_country",
    "issuing_authority", "document_number", "portrait", "driving_privileges", "sex", "age_over_18", "nationality",
    "resident_city", "un_distinguishing_sign"];
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

/**
 * Opens the wallet page against an IndexedDB factory (the harness's fake, or another implementation), with the shipped
 * scripts. `walletConfig: false` makes `wallet/config` answer 404, as it does with the wallet switched off. Every fetch
 * the page makes is recorded in `requests` (I9).
 *
 * P5-03c adds: `pageUrl`, so a same-device invocation can arrive in the query or the fragment; `relayHosts`, which is
 * what `wallet/config` publishes; `respond`, the answers to every other request (`{status, body, contentType}` or
 * `"throw"`); and `clock`, the instant the page's `new Date()` reads, so the request checks run under a faked clock.
 */
function openWallet(indexedDB, options = {}) {
    const source = readFileSync(resolve(STATIC, "wallet.html"), "utf8");
    const { ids: elements, scripts } = parseMarkup(source);
    const document = {
        getElementById(id) { return elements.get(String(id)) ?? null; },
        createElement: (tag) => new Element(String(tag).toLowerCase()),
        createTextNode: (data) => new Text(data),
    };
    const requests = [];
    const replacedUrls = [];
    const pageUrl = new URL(options.pageUrl || "https://credentials.example/v1/certify/offer/wallet");
    const relayHosts = options.relayHosts || [];
    const fetch = async (url, init = {}) => {
        const target = new URL(String(url), pageUrl).href;
        const request = {
            method: (init.method || "GET").toUpperCase(),
            url: target,
            headers: Object.assign({}, init.headers || {}),
            body: init.body,
            redirect: init.redirect,
        };
        requests.push(request);
        if (target === "https://credentials.example/v1/certify/offer/wallet/config") {
            const enabled = options.walletConfig === undefined ? true : options.walletConfig;
            return enabled
                ? { status: 200, text: async () => JSON.stringify({ relay: { hosts: relayHosts } }) }
                : { status: 404, text: async () => "" };
        }
        if (typeof options.respond === "function") {
            const answer = options.respond(request);
            if (answer === "throw") throw new TypeError("fetch failed");
            if (answer !== undefined) {
                return {
                    status: answer.status,
                    headers: { get: (name) => (String(name).toLowerCase() === "content-type" ? answer.contentType || "" : null) },
                    text: async () => (typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body === undefined ? "" : answer.body)),
                };
            }
        }
        return { status: 404, text: async () => "" };
    };
    // a faked clock: `new Date()` answers the pinned instant, every other Date call is the real one
    const PinnedDate = options.clock === undefined ? Date : class extends Date {
        constructor(...args) { if (args.length === 0) super(options.clock.getTime()); else super(...args); }
        static now() { return options.clock.getTime(); }
    };
    const context = vm.createContext({
        document,
        location: { href: pageUrl.href, origin: pageUrl.origin, pathname: pageUrl.pathname, search: pageUrl.search,
            hash: pageUrl.hash },
        // `replaceState` is recorded; a page that left the request parameters in the address bar shows here
        history: {
            replaceState(state, title, url) { replacedUrls.push(String(url)); },
        },
        fetch,
        console: { log: () => {}, warn: () => {}, error: () => {} },
        // a timer callback is a task of its own (the harness fake's transactions of the task before are inactive in it)
        setTimeout: taskTimers.setTimeout, clearTimeout: taskTimers.clearTimeout,
        URL, URLSearchParams, Blob, crypto: webcrypto,
        TextEncoder, TextDecoder, btoa, atob, structuredClone, indexedDB,
        Date: PinnedDate,
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
    return { elements, document, scriptError, requests, replacedUrls, el: (id) => elements.get(id) ?? null };
}

async function settle() {
    for (let i = 0; i < 200; i++) await new Promise((done) => setImmediate(done));
}

/** Real time, for what a page does on a timer (the offer page's "waiting for the store" note): bounded, never a hang. */
async function waitForMs(predicate, ms) {
    const until = Date.now() + ms;
    while (Date.now() < until) {
        if (predicate()) return true;
        await new Promise((done) => setTimeout(done, 5));
    }
    return predicate();
}

/**
 * The wallet page's storage status and its "Delete everything" control, written in one ordered trace: `status: <text>`
 * and `deleteAll enabled` / `deleteAll disabled`. A control that came back for a moment and went off again still shows.
 */
function traceControls(wallet) {
    const trace = [];
    const node = wallet.el("storageStatus");
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, "textContent");
    Object.defineProperty(node, "textContent", {
        configurable: true,
        get() { return descriptor.get.call(node); },
        set(value) { trace.push("status: " + String(value)); descriptor.set.call(node, value); },
    });
    const button = wallet.el("deleteAll");
    let disabled = button.disabled;
    Object.defineProperty(button, "disabled", {
        configurable: true,
        get() { return disabled; },
        set(value) { disabled = !!value; trace.push("deleteAll " + (disabled ? "disabled" : "enabled")); },
    });
    return trace;
}

/**
 * Turns of the event loop until `predicate()` holds, with a timer turn now and then so an implementation that queues
 * with timers rather than `setImmediate` gets its turn too. Bounded: a page that never gets there fails its check
 * instead of hanging the run.
 */
async function waitFor(predicate, turns = 2000) {
    for (let i = 0; i < turns; i++) {
        if (predicate()) return true;
        await new Promise((done) => (i % 50 === 49 ? setTimeout(done, 1) : setImmediate(done)));
    }
    return predicate();
}

/** The shipped WalletStore, bound to one IndexedDB factory. */
const storeOn = (indexedDB) => shipped("wallet-store.js", { indexedDB }, "WalletStore");

/** Keeps `count` records through the shipped store (no CryptoKey: the list, the details and the deletes need none). */
async function seedRecords(indexedDB, count) {
    const store = storeOn(indexedDB);
    const db = await store.open();
    for (let index = 0; index < count; index++) {
        await store.putWithinLimit(db, { id: "seed-" + index, format: "mso_mdoc", docType: DOC_TYPE,
            issuerSigned: MDL_A.bytes, storedAt: index + 1, label: "Seeded " + index }, Mdoc.MAX_CREDENTIALS);
    }
    db.close();
}

/** How many credentials the store holds, read through the shipped store on a connection of its own. */
async function keptCount(indexedDB) {
    const store = storeOn(indexedDB);
    const db = await store.open();
    const count = await store.count(db);
    db.close();
    return count;
}

/** Every text the page wrote into its storage status, in order: a message that was shown and replaced still counts. */
function statusHistory(wallet) {
    const node = wallet.el("storageStatus");
    const history = [];
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, "textContent");
    Object.defineProperty(node, "textContent", {
        configurable: true,
        get() { return descriptor.get.call(node); },
        set(value) { history.push(String(value)); descriptor.set.call(node, value); },
    });
    return history;
}

const listButtons = (wallet) => wallet.el("records").children.map((item) => item.children[0]);

/** A call that must throw, with a message matching `pattern`. */
function refusedWith(label, attempt, pattern) {
    let error = null;
    try {
        attempt();
    } catch (caught) {
        error = caught;
    }
    check(`refused: ${label}`, error !== null && pattern.test(error.message), error ? error.message : "it was read");
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

/* ---------------------------------------------------------------- storage scenarios (shared with wallet-probe) */

/**
 * The parts of IndexedDB 3.0 the wallet's correctness rests on, checked on one factory: the harness's fake or a
 * spec-conformant implementation (wallet-probe/idb-crosscheck.mjs). Both must pass the same checks.
 */
async function storageConformance(makeIndexedDB, label) {
    await section(`IndexedDB 3.0 (${label}): the connection queue and transaction lifetime`, async () => {
        const indexedDB = makeIndexedDB();
        const store = storeOn(indexedDB);
        const holder = await store.open();
        holder.onversionchange = null; // stays open: the delete below is blocked by it
        const events = [];
        const deleting = indexedDB.deleteDatabase(DB_NAME);
        deleting.onblocked = (event) => events.push("delete blocked " + event.newVersion);
        deleting.onsuccess = () => events.push("delete success");
        deleting.onerror = () => events.push("delete error");
        const reopening = indexedDB.open(DB_NAME, 1);
        reopening.onupgradeneeded = (event) => {
            events.push("open upgradeneeded " + event.oldVersion);
            reopening.result.createObjectStore("credentials", { keyPath: "id" });
        };
        reopening.onsuccess = () => { events.push("open success"); reopening.result.close(); };
        reopening.onerror = () => events.push("open error");
        await waitFor(() => events.length > 0);
        await settle();
        equal(`${label}: blocked, the delete stays pending, and an open made after it waits behind it (5.1, 5.3)`, events,
            ["delete blocked null"]);
        holder.close();
        await waitFor(() => events.length >= 4);
        equal(`${label}: once the last connection closes the delete succeeds, then the open answers on a new database`, events,
            ["delete blocked null", "delete success", "open upgradeneeded 0", "open success"]);

        const db = await store.open();
        const finished = db.transaction(store.CREDENTIALS, "readonly");
        const finishedStore = finished.objectStore(store.CREDENTIALS);
        await new Promise((done) => { finished.oncomplete = done; });
        let late = null;
        try {
            finishedStore.count();
        } catch (error) {
            late = error;
        }
        equal(`${label}: a request on a finished transaction throws TransactionInactiveError (4.5)`, late && late.name,
            "TransactionInactiveError");

        const writing = db.transaction(store.CREDENTIALS, "readwrite");
        const writingStore = writing.objectStore(store.CREDENTIALS);
        let fromHandler = null;
        const counting = writingStore.count();
        counting.onsuccess = () => { fromHandler = writingStore.put({ id: "from-handler", storedAt: 1 }); };
        const outcome = await new Promise((done) => {
            writing.oncomplete = () => done("complete");
            writing.onabort = () => done("abort");
        });
        equal(`${label}: a request made from a success handler extends its transaction, which then commits (2.7.1)`,
            [outcome, fromHandler !== null, await store.count(db)], ["complete", true, 1]);

        db.close();
        let closing = null;
        try {
            db.transaction(store.CREDENTIALS, "readonly");
        } catch (error) {
            closing = error;
        }
        equal(`${label}: a closed connection refuses a new transaction (InvalidStateError)`, closing && closing.name, "InvalidStateError");
    });
}

/**
 * "Delete everything" against other tabs, on one factory (review round 2, major 1 and minor 6). Every check reads what
 * the visitor sees - the status line, the list, the controls - and the store itself afterwards, never the factory's
 * internals, so the same checks hold the page to a spec implementation.
 *
 * `closeWaitsForTransactions` (default true) is IndexedDB 3.0 2.6 and 5.3 steps 8-9: a connection whose close is
 * pending is closed only once its transactions complete, so a delete is `blocked` by a tab mid-transaction and waits for
 * it. fake-indexeddb 6.2.4 counts a close-pending connection as closed (its `waitForOthersClosedDelete`), so on it the
 * delete neither reports `blocked` nor waits for that transaction; the outcome the page reports must be the same either
 * way, and only the two checks that depend on the wait are skipped there.
 */
async function walletDeleteScenarios(makeIndexedDB, label, { closeWaitsForTransactions = true } = {}) {
    await section(`Delete everything (${label}): another tab that does not close`, async () => {
        const indexedDB = makeIndexedDB();
        await seedRecords(indexedDB, 1);
        const stubborn = await storeOn(indexedDB).open();
        stubborn.onversionchange = null; // an older build, a frozen tab: it never closes by itself
        const wallet = openWallet(indexedDB);
        check(`${label}: the wallet page's scripts ran`, wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
        await waitFor(() => wallet.el("records").children.length === 1);
        equal(`${label}: the wallet lists the kept credential`, wallet.el("records").children.length, 1);
        let finished = false;
        const pressed = wallet.el("deleteAll").fire("click").then(() => { finished = true; });
        const told = await waitFor(() => wallet.el("storageStatus").textContent.includes("Waiting for other wallet tabs to close"));
        check(`${label}: blocked, the page says it is waiting for the other tabs - before it awaits anything`, told,
            wallet.el("storageStatus").textContent);
        await settle();
        check(`${label}: and it keeps waiting rather than reporting an outcome`, finished === false
            && !wallet.el("storageStatus").textContent.includes("could not"), wallet.el("storageStatus").textContent);
        equal(`${label}: every control is disabled while it waits`, [wallet.el("deleteAll").disabled, wallet.el("delete").disabled,
            listButtons(wallet).every((button) => button.disabled)], [true, true, true]);
        stubborn.close();
        const done = await waitFor(() => finished);
        check(`${label}: the delete finishes by itself once the other tab closes`, done);
        check(`${label}: and the page reports the real outcome: deleted`,
            wallet.el("storageStatus").textContent === "Everything kept in this browser was deleted.", wallet.el("storageStatus").textContent);
        equal(`${label}: the list follows`, wallet.el("records").children.length, 0);
        // review round 3 (nit): Delete stays off too, as nothing is selected - it waits for a credential to be chosen
        equal(`${label}: the controls come back (Delete everything off for an empty list, Delete off with nothing selected)`,
            [wallet.el("deleteAll").disabled, wallet.el("delete").disabled], [true, true]);
        equal(`${label}: nothing is kept any more`, await keptCount(indexedDB), 0);
        await pressed;
    });

    await section(`Delete everything (${label}): another tab still running a transaction`, async () => {
        const indexedDB = makeIndexedDB();
        await seedRecords(indexedDB, 1);
        // a tab that closes itself on versionchange (WalletStore's own handler), but is in the middle of a transaction:
        // its connection closes only once that transaction finishes, so the delete is blocked for a moment
        const busyTab = await storeOn(indexedDB).open();
        const wallet = openWallet(indexedDB);
        await waitFor(() => wallet.el("records").children.length === 1);
        const history = statusHistory(wallet);
        let reads = 0;
        const reading = busyTab.transaction("credentials", "readonly").objectStore("credentials");
        const readOn = () => {
            const request = reading.count();
            request.onsuccess = () => { reads++; if (reads < 150) readOn(); };
        };
        readOn();
        let finished = false;
        const pressed = wallet.el("deleteAll").fire("click").then(() => { finished = true; });
        const done = await waitFor(() => finished, 5000);
        check(`${label}: the delete completes`, done);
        if (closeWaitsForTransactions) {
            equal(`${label}: once the other tab's transaction has run to its end (2.6)`, reads, 150);
            check(`${label}: the page said it was waiting while the other tab finished`,
                history.some((text) => text.includes("Waiting for other wallet tabs to close")), JSON.stringify(history));
        }
        check(`${label}: and reports the delete it did, never a failure`,
            wallet.el("storageStatus").textContent === "Everything kept in this browser was deleted."
            && !history.some((text) => text.includes("could not")), JSON.stringify(history));
        equal(`${label}: nothing is kept any more`, await keptCount(indexedDB), 0);
        await pressed;
    });

    await section(`Delete everything (${label}): a wallet tab follows a delete made in another`, async () => {
        const indexedDB = makeIndexedDB();
        await seedRecords(indexedDB, 2);
        const first = openWallet(indexedDB);
        const second = openWallet(indexedDB);
        await waitFor(() => first.el("records").children.length === 2 && second.el("records").children.length === 2);
        // the first tab is looking at a credential when the second deletes everything
        await listButtons(first)[0].fire("click");
        equal(`${label}: the first tab shows a credential's details`, first.el("details").hidden, false);
        await second.el("deleteAll").fire("click");
        check(`${label}: the second tab deletes without waiting on the first`,
            second.el("storageStatus").textContent === "Everything kept in this browser was deleted.", second.el("storageStatus").textContent);
        const followed = await waitFor(() => first.el("storageStatus").textContent.includes("Another wallet tab deleted everything"));
        check(`${label}: the first tab says another tab deleted everything`, followed, first.el("storageStatus").textContent);
        equal(`${label}: its list and details follow`, [first.el("records").children.length, first.el("details").hidden], [0, true]);
        // its next action meets a live connection, not the closed one: nothing to delete, and no InvalidStateError
        await first.el("delete").fire("click");
        await settle();
        check(`${label}: pressing Delete in the first tab reports no error`, !first.el("detailsStatus").textContent.includes("could not")
            && !first.el("storageStatus").textContent.includes("could not"),
            first.el("detailsStatus").textContent + " | " + first.el("storageStatus").textContent);
        // and its new connection gives way to the next delete too, so that one is not blocked by it
        const blocked = [];
        await storeOn(indexedDB).deleteEverything(() => blocked.push("blocked"));
        equal(`${label}: a later delete from elsewhere is not blocked by either tab`, blocked, []);
        await waitFor(() => first.el("storageStatus").textContent.includes("Another wallet tab deleted everything")
            && second.el("storageStatus").textContent.includes("Another wallet tab deleted everything"));
        check(`${label}: and both tabs follow it`, second.el("storageStatus").textContent.includes("Another wallet tab deleted everything"),
            second.el("storageStatus").textContent);
    });
}

/* ---------------------------------------------------------------- P5-03c: the verifier's material */

const VERIFIER_DIR = resolve(FIXTURES, "verifier");
const HOSTED_DIR = resolve(FIXTURES, "hosted");
/** The harness's pinned instant: inside every fixture certificate's validity, and the hosted objects' lifetime. */
const NOW = new Date("2026-11-15T09:00:00Z");
const PUBLIC_PAGE = new URL("https://credentials.example/v1/certify/offer/wallet");
const LOCAL_PAGE = new URL("http://localhost:8090/v1/certify/offer/wallet");

const pemText = (name) => readFileSync(resolve(VERIFIER_DIR, name + ".pem"), "utf8");
/** A fixture certificate's DER. */
const derOf = (name) => new Uint8Array(Buffer.from(pemText(name).replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"));
const signerOf = (name) => createPrivateKey(readFileSync(resolve(VERIFIER_DIR, name + ".key.pem"), "utf8"));
/** An `x5c` entry: base64 of the DER, not base64url (RFC 7515 section 4.1.6). */
const x5cOf = (name) => Buffer.from(derOf(name)).toString("base64");
const leafHashOf = (name) => createHash("sha256").update(derOf(name)).digest("base64url");
const jsonPart = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** The X.509 module exactly as the page loads it. */
const X509 = shipped("x509.js", { crypto: webcrypto, TextDecoder }, "X509");
/** The OpenID4VP module exactly as the page loads it. */
const Oid4vp = shipped("oid4vp.js", { X509, crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, URL, URLSearchParams },
    "Oid4vp");

/** A JWS signature over `signingInput` with a fixture key, for one of the algorithms the page verifies. */
function jwsSignature(alg, keyName, signingInput) {
    const data = Buffer.from(signingInput, "ascii");
    const key = signerOf(keyName);
    switch (alg) {
        case "ES256": return sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
        case "ES384": return sign("sha384", data, { key, dsaEncoding: "ieee-p1363" });
        case "ES512": return sign("sha512", data, { key, dsaEncoding: "ieee-p1363" });
        case "RS256": return sign("sha256", data, { key, padding: constants.RSA_PKCS1_PADDING });
        case "PS256": return sign("sha256", data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
        default: throw new Error("the harness does not sign " + alg);
    }
}

/**
 * A request object: a compact JWS over `payload`. `alg` picks the signature, `keyName` the fixture key that signs, and
 * `x5c` the chain (by default the signing key's own certificate). `options.header` is merged into the protected header,
 * `options.tamper` flips one bit of the signature, and `options.sign === false` carries no signature at all.
 */
function jar(payload, options = {}) {
    const alg = options.alg === undefined ? "ES256" : options.alg;
    const keyName = options.keyName === undefined ? "verifier" : options.keyName;
    const header = Object.assign({ alg, typ: "oauth-authz-req+jwt" }, options.header || {});
    if (options.x5c !== null) header.x5c = options.x5c === undefined ? [x5cOf(keyName)] : options.x5c;
    const signingInput = jsonPart(header) + "." + jsonPart(payload);
    if (options.sign === false) return signingInput + ".";
    const signature = Buffer.from(jwsSignature(alg, keyName, signingInput));
    if (options.tamper) signature[signature.length - 1] ^= 0x01;
    return signingInput + "." + signature.toString("base64url");
}

/** The members one request object starts from: an `x509_san_dns` request that passes R1-R11 under the pinned clock. */
const VERIFIER_REQUEST = () => ({
    client_id: "x509_san_dns:verifier.example",
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    response_uri: "https://verifier.example/response",
    nonce: "nonce-p503c",
    state: "state-p503c",
    aud: "https://self-issued.me/v2",
    iat: Math.floor(NOW.getTime() / 1000) - 10,
    exp: Math.floor(NOW.getTime() / 1000) + 600,
    dcql_query: {
        credentials: [{ id: "q1", format: "mso_mdoc", meta: { doctype_value: DOC_TYPE },
            claims: [{ path: [MDL_NAMESPACE, "family_name"] }] }],
    },
});

/** That request object with members replaced, or removed when the override is `undefined`. */
function withMembers(overrides) {
    const out = VERIFIER_REQUEST();
    for (const [key, value] of Object.entries(overrides || {})) {
        if (value === undefined) delete out[key];
        else out[key] = value;
    }
    return out;
}

/** The link parameters `checkRequest` takes, as a request_uri link of the given scheme gives them. */
function linkParams(extra = {}) {
    return Object.assign({
        scheme: "openid4vp",
        kind: "request_uri",
        clientId: "x509_san_dns:verifier.example",
        requestUri: "https://verifier.example/request.jwt/1",
        requestUriMethod: "get",
        findings: [],
    }, extra);
}

/** One `checkRequest` under the pinned clock and the public page's origin. */
async function checkRequestOf(text, options = {}) {
    return Oid4vp.checkRequest({
        text,
        link: options.link === undefined ? linkParams() : options.link,
        contentType: options.contentType === undefined ? "application/oauth-authz-req+jwt" : options.contentType,
        pageUrl: options.pageUrl === undefined ? PUBLIC_PAGE : options.pageUrl,
        now: options.now === undefined ? NOW : options.now,
        keptIssuerAuthAlgs: options.keptIssuerAuthAlgs,
    });
}

/** Asserts a refusal, naming the rule and what the message says (plan 4.5: "The panel names the rule"). */
function refusesWith(label, result, rule, fragment) {
    check(`${label}: refused under ${rule}`, result.ok === false && result.rule === rule,
        result.ok ? "it was accepted" : `${result.rule}: ${result.message}`);
    check(`${label}: the refusal names the reason`, result.ok === false && fragment.test(String(result.message)),
        result.ok ? "it was accepted" : String(result.message));
}

/** A `fetch` for `Oid4vp.fetchRequest`, answering from a table of URLs and recording every call. */
function scriptedFetch(answers) {
    const calls = [];
    const impl = async (url, init = {}) => {
        const target = String(url);
        calls.push({ url: target, method: (init.method || "GET").toUpperCase(), headers: Object.assign({}, init.headers || {}),
            body: init.body, redirect: init.redirect });
        const answer = answers[target];
        if (answer === undefined || answer === "throw") throw new TypeError("Failed to fetch");
        return {
            status: answer.status,
            headers: { get: (name) => (String(name).toLowerCase() === "content-type" ? answer.contentType || "" : null) },
            text: async () => answer.body,
        };
    };
    return { impl, calls };
}


const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
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

    // review round 2 (nit): nesting is capped with a message, not left to exhaust the stack - also across tag-24 content
    const nested = (depth) => new Uint8Array([...new Array(depth).fill(0x81), 0x00]);
    equal("64 nested arrays decode", JSON.stringify(Cbor.decode(nested(64))).length, 129);
    refusedWith("65 nested arrays", () => Cbor.decode(nested(65)), /nests deeper than 64/);
    refusedWith("a deep item hidden in tag-24 content", () => Cbor.decode(new Uint8Array([...new Array(40).fill(0x81),
        ...Cbor.encode(new Cbor.Tagged(24, nested(30)))])), /nests deeper than 64/);
    refusedWith("200 000 nested arrays (no stack overflow)", () => Cbor.decode(new Uint8Array(200000).fill(0x81)), /nests deeper than 64/);
});

// 2. Mdoc.readIssuerSigned: the raw slices are the issued items, exactly as the bytes carry them
await section("2. readIssuerSigned", async () => {
    const read = Mdoc.readIssuerSigned(MDL_A.bytes);
    equal("the docType and algorithm are read from the MSO", [read.issuerAuth.mso.get("docType"),
        read.issuerAuth.mso.get("digestAlgorithm")], [DOC_TYPE, "SHA-256"]);
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
    // RFC 9360 section 2: the array form is [2*certs: bstr]. A one-entry array is not a COSE_X509 (the single bstr is),
    // so it is refused rather than read as if it were one
    refusedWith("a one-entry x5chain array (RFC 9360 section 2: two or more)", () => Mdoc.readIssuerSigned(buildIssuerSigned({
        docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS, x5chain: [DUMMY_DER], chainForm: "array" }).bytes),
        /two or more/);
    refusedWith("a tagged certificate inside an x5chain array", () => Mdoc.readIssuerSigned(buildIssuerSigned({
        docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS,
        x5chainRaw: Buffer.concat([Buffer.from(head(4, 2)), Buffer.from(head(6, 99)), bstr(DUMMY_DER), bstr(SECOND_DER)]) }).bytes),
        /x5chain certificate 0/);
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
    equal("and its MSO comes out of the bstr payload", tagged.issuerAuth.mso.get("docType"), DOC_TYPE);
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

    // review round 2, minor 1: the COSE_Sign1 shape is read from the bytes. The decoder resolves tags to what they carry,
    // so each of these decoded to a value the old checks accepted.
    const shaped = (extra) => buildIssuerSigned(Object.assign({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS }, extra));
    for (const [tag, why] of [[1, "an epoch date"], [24, "embedded CBOR, as #6.24(bstr .cbor COSE_Sign1)"], [55799, "self-described CBOR"]]) {
        refusedWith(`issuerAuth wrapped in tag ${tag} (${why}); only tag 18 may wrap a COSE_Sign1`,
            () => Mdoc.readIssuerSigned(shaped({ coseWrap: tag }).bytes), new RegExp(`wrapped in tag ${tag}`));
    }
    refusedWith("a payload that is #6.24(bstr .cbor bstr) - decoding to the very bstr - instead of a bstr",
        () => Mdoc.readIssuerSigned(shaped({ payloadWrap: 24 }).bytes), /issuerAuth element 2 .* is a tag/);
    refusedWith("a payload that is a bstr inside another tag (21)",
        () => Mdoc.readIssuerSigned(shaped({ payloadWrap: 21 }).bytes), /issuerAuth element 2 .* is a tag/);
    refusedWith("a protected header that is a map rather than a bstr (RFC 9052 section 4.2)",
        () => Mdoc.readIssuerSigned(shaped({ protectedAsMap: true }).bytes), /issuerAuth element 0 .* is a map/);
    for (const [label, extra] of [["issuerAuth wrapped in tag 1", { coseWrap: 1 }], ["a tag-24 payload", { payloadWrap: 24 }],
        ["a map as the protected header", { protectedAsMap: true }]]) {
        const verdict = await Mdoc.checkKeepable({ issuerSigned: shaped(extra).bytes, doctype: DOC_TYPE, publicJwk: HOLDER_A_JWK });
        check(`checkKeepable refuses ${label}`, verdict.ok === false && verdict.code === "issuer-signed", JSON.stringify(verdict));
    }

    // the same for the containers above the items: a tag around the IssuerSigned, its nameSpaces or a namespace's array
    const selfDescribed = Buffer.from(head(6, 55799));
    const nsArrayAt = MDL_A.nameSpacesRange.start + 1 + tstr(MDL_NAMESPACE).length;
    for (const [label, at, pattern] of [["the IssuerSigned map", 0, /not an IssuerSigned map/],
        ["the nameSpaces map", MDL_A.nameSpacesRange.start, /IssuerSigned nameSpaces is a tag, not a map/],
        ["a namespace's array", nsArrayAt, /the namespace org.iso.18013.5.1 is a tag, not an array/]]) {
        const wrapped = new Uint8Array(Buffer.concat([Buffer.from(MDL_A.bytes.subarray(0, at)), selfDescribed,
            Buffer.from(MDL_A.bytes.subarray(at))]));
        refusedWith(`${label} wrapped in tag 55799`, () => Mdoc.readIssuerSigned(wrapped), pattern);
    }

    // review round 2, minor 5: an IssuerSignedItem that is not tag 24 is refused even when its digest matches - its
    // digest is taken over exactly the bytes written, so the tag-24 check is the only one that can refuse it
    for (const form of ["bare", "tag55799"]) {
        const untagged = shaped({ itemForms: { given_name: form } });
        refusedWith(`an IssuerSignedItem written as ${form === "bare" ? "a bare map" : "#6.55799(map)"}, its digest matching`,
            () => Mdoc.readIssuerSigned(untagged.bytes), /given_name is not a tag-24 IssuerSignedItemBytes/);
        const verdict = await Mdoc.checkKeepable({ issuerSigned: untagged.bytes, doctype: DOC_TYPE, publicJwk: HOLDER_A_JWK });
        check(`checkKeepable refuses an IssuerSignedItem written as ${form}`, verdict.ok === false && /tag-24/.test(verdict.message),
            JSON.stringify(verdict));
    }

    // review round 2, major 2: a map key's contents are never a range. The decoy below is a key of the nameSpaces map,
    // {"org.iso.18013.5.1": [decoy item]}; recorded, its item would sit at ["nameSpaces", ns, 0] after the real one
    const nsStart = MDL_A.nameSpacesRange.start;
    const nsEnd = MDL_A.nameSpacesRange.end;
    const decoyItem = Buffer.concat([Buffer.from(head(6, 24)), bstr(Cbor.encode(new Map([["digestID", 0],
        ["random", new Uint8Array(16)], ["elementIdentifier", "family_name"], ["elementValue", "Decoy"]])))]);
    const decoyKey = Buffer.concat([Buffer.from(head(5, 1)), tstr(MDL_NAMESPACE), Buffer.from(head(4, 1)), decoyItem]);
    const itemProbe = new Uint8Array(Buffer.concat([Buffer.from(MDL_A.bytes.subarray(0, nsStart)), Buffer.from([head(5, 2)[0]]),
        Buffer.from(MDL_A.bytes.subarray(nsStart + 1, nsEnd)), decoyKey, Buffer.from([0xf6]), Buffer.from(MDL_A.bytes.subarray(nsEnd))]));
    equal("probe: the nameSpaces map of the item probe starts as the fixture's did", MDL_A.bytes[nsStart], head(5, 1)[0]);
    const itemWalk = Cbor.spans(itemProbe, 3);
    MDL_A.items.get(MDL_NAMESPACE).forEach((expected, index) => {
        const at = itemWalk.ranges.filter((range) => JSON.stringify(range.path) === JSON.stringify(["nameSpaces", MDL_NAMESPACE, index]));
        equal(`Cbor.spans records exactly the real item at ["nameSpaces", ns, ${index}], never the key's decoy`,
            at.map((range) => [range.start, range.end]), [[expected.start, expected.end]]);
    });
    const insideKey = (range) => range.start >= nsEnd && range.end <= nsEnd + decoyKey.length;
    check("Cbor.spans records nothing inside the decoy key", !itemWalk.ranges.some(insideKey),
        JSON.stringify(itemWalk.ranges.filter(insideKey)));
    refusedWith("a nameSpaces key that is a map (NameSpace = tstr)", () => Mdoc.readIssuerSigned(itemProbe),
        /a nameSpaces key is a map, not a text string/);
    const itemVerdict = await Mdoc.checkKeepable({ issuerSigned: itemProbe, doctype: DOC_TYPE, publicJwk: HOLDER_A_JWK });
    check("checkKeepable refuses the item probe", itemVerdict.ok === false && itemVerdict.code === "issuer-signed", JSON.stringify(itemVerdict));
    // an integer namespace key is not a NameSpace either
    const intKeyProbe = new Uint8Array(Buffer.concat([Buffer.from(MDL_A.bytes.subarray(0, nsStart)), Buffer.from([head(5, 2)[0]]),
        Buffer.from(MDL_A.bytes.subarray(nsStart + 1, nsEnd)), Buffer.from(head(0, 7)), Buffer.from(head(4, 1)), decoyItem,
        Buffer.from(MDL_A.bytes.subarray(nsEnd))]));
    refusedWith("an integer nameSpaces key", () => Mdoc.readIssuerSigned(intKeyProbe), /a nameSpaces key is an unsigned integer/);

    // and the reader's own guard, should a walk ever hand it two items at one path: refused, never "the last one wins"
    const doubled = shipped("mdoc.js", { Cbor: Object.assign({}, Cbor, { spans: (input, depth) => {
        const walked = Cbor.spans(input, depth);
        const real = walked.ranges.find((range) => JSON.stringify(range.path) === "[\"issuerAuth\"]");
        return Object.assign({}, walked, { ranges: walked.ranges.concat([Object.assign({}, real, { start: real.start + 1 })]) });
    } }), crypto: webcrypto, btoa }, "Mdoc");
    refusedWith("a walk with two items at one path", () => doubled.readIssuerSigned(MDL_A.bytes), /two data items sit at \["issuerAuth"\]/);
});

// review round 3: helpers of sections 2b and 2c
const cat = (...parts) => new Uint8Array(Buffer.concat(parts.map((part) => Buffer.from(part))));
const verdictOf = (built, publicJwk = HOLDER_A_JWK) => Mdoc.checkKeepable({ issuerSigned: built.bytes, doctype: DOC_TYPE,
    publicJwk });
const shapedMdl = (extra) => buildIssuerSigned(Object.assign({ docType: DOC_TYPE, holder: HOLDER_A_JWK, elements: MDL_ELEMENTS }, extra));
/** A typed map key as a check prints it: a text or an integer key as itself, a float its value, another key "#" + identity. */
const keyName = (key) => key instanceof Cbor.OtherKey ? (typeof key.value === "number" ? String(key.value) : "#" + key.identity) : key;
// {1: -7, "1": "private extension"}: RFC 9052 1.5, label = int / tstr, so these are two labels
const TWO_LABELS = cat(head(5, 2), head(0, 1), head(1, 6), tstr("1"), tstr("private extension"));

// 2b. review round 3, major 1: the decoder keeps map keys' types, and still refuses a key that is one data item twice
await section("2b. typed map keys in the decoder", async () => {
    const twoLabels = TWO_LABELS;
    // the decoder: one map, two keys of two types
    const typed = Cbor.decodeTyped(twoLabels);
    equal("decodeTyped keeps the integer key 1 and the text key \"1\" apart", [typed.size, typed.get(1), typed.get("1")],
        [2, -7, "private extension"]);
    const walked = Cbor.spans(twoLabels, 1);
    equal("Cbor.spans records both values, each under a path of its own type", walked.ranges.map((range) =>
        [range.path, range.start, range.end]), [[[1], 2, 3], [["1"], 5, 23]]);
    equal("and both keys, with their major types", walked.keys.map((key) => [key.key, key.major]), [[1, 0], ["1", 3]]);
    check("Cbor.Raw takes the map as the one well-formed item it is", hex(Cbor.encode(Cbor.Raw(twoLabels))) === hex(twoLabels));
    equal("Cbor.tagged reads it inside tag 24", Cbor.tagged(cat(head(6, 24), bstr(twoLabels))).tag, 24);
    // Cbor.decode is the offer page's display and is unchanged (plan 4.3): its plain objects cannot hold both keys
    refusedWith("Cbor.decode (the display form) still refuses the keys it would render alike",
        () => Cbor.decode(twoLabels), /ambiguous map key 1/);

    // the same data item twice is still a duplicate (RFC 8949 5.6), whatever head or chunks carry it
    for (const [label, first, second] of [
        ["the integer 1 under 01 and 18 01", head(0, 1), [0x18, 0x01]],
        ["the integer 1 under 01 and 19 00 01", head(0, 1), [0x19, 0x00, 0x01]],
        ["the integer 1 under 01 and 1b 00..01", head(0, 1), [0x1b, 0, 0, 0, 0, 0, 0, 0, 0x01]],
        ["the integer -7 under 26 and 38 06", head(1, 6), [0x38, 0x06]],
        ["the text \"1\" under 61 and 78 01", tstr("1"), [0x78, 0x01, 0x31]],
        ["the text \"1\" under 61 and 79 00 01", tstr("1"), [0x79, 0x00, 0x01, 0x31]],
        ["the text \"1\" and the same text in indefinite-length chunks", tstr("1"), [0x7f, 0x61, 0x31, 0xff]],
        ["the text \"ab\" and \"a\" \"b\" as two chunks", tstr("ab"), [0x7f, 0x61, 0x61, 0x61, 0x62, 0xff]],
        ["the byte string h'01' and the same bytes in chunks", bstr([1]), [0x5f, 0x41, 0x01, 0xff]],
    ]) {
        const doubled = cat(head(5, 2), first, head(0, 0), second, head(0, 0));
        refusedWith(`decodeTyped: ${label} is one key twice`, () => Cbor.decodeTyped(doubled), /duplicate map key/);
        refusedWith(`Cbor.spans: ${label} is one key twice`, () => Cbor.spans(doubled, 1), /duplicate map key/);
    }
    // two text keys whose bytes differ but would decode alike (invalid UTF-8, each one U+FFFD) are never merged: review
    // round 4 reads text strictly, so invalid UTF-8 is refused before any key is compared
    refusedWith("two invalid UTF-8 text keys that a lenient decoder reads as one string", () => Cbor.decodeTyped(cat(head(5, 2),
        [0x61, 0xff], head(0, 0), [0x61, 0xfe], head(0, 1))), /not valid UTF-8/);
    // ... while two distinct items of other types stay two keys (0 and 0.0, RFC 8949 5.6)
    equal("the integer 0 and the float 0.0 are two keys", Cbor.decodeTyped(cat(head(5, 2), head(0, 0), head(0, 1),
        [0xf9, 0x00, 0x00], head(0, 2))).size, 2);
    refusedWith("0.0 as a half and as a double is one float twice", () => Cbor.decodeTyped(cat(head(5, 2),
        [0xf9, 0x00, 0x00], head(0, 1), [0xfb, 0, 0, 0, 0, 0, 0, 0, 0], head(0, 2))), /duplicate map key/);
});

// 2d. review round 4: map keys compare as RFC 8949 5.6.1 says. Text keys compare by their UTF-8 bytes (a leading
// U+FEFF is a character, never stripped), +0.0 and -0.0 are one key, NaNs are one key exactly when their significands
// are, and a bignum is the integer it carries. Each probe runs on both typed entry points, decodeTyped and spans
await section("2d. map key equivalence (RFC 8949 5.6.1)", async () => {
    const BOM_X = Buffer.from("\ufeffx", "utf8"); // ef bb bf 78
    const bothRead = (label, bytes, expected) => {
        let typed;
        let walked;
        try {
            typed = [...Cbor.decodeTyped(bytes).keys()].map(keyName);
        } catch (error) {
            typed = "refused: " + error.message;
        }
        try {
            walked = Cbor.spans(bytes, 1).ranges.map((range) => JSON.stringify(range.path));
        } catch (error) {
            walked = "refused: " + error.message;
        }
        equal(`decodeTyped: ${label}`, typed, expected.keys);
        equal(`Cbor.spans: ${label}`, walked, expected.paths);
    };
    const bothRefuse = (label, bytes, pattern) => {
        refusedWith(`decodeTyped: ${label}`, () => Cbor.decodeTyped(bytes), pattern);
        refusedWith(`Cbor.spans: ${label}`, () => Cbor.spans(bytes, 1), pattern);
    };

    // finding 1: a leading U+FEFF is kept, in a definite string and in every chunk of an indefinite one
    equal("a text string with a leading U+FEFF reads as that string", Cbor.decodeTyped(cat(head(3, 4), BOM_X)), "\ufeffx");
    equal("and so does a chunk that starts with one", Cbor.decodeTyped(cat([0x7f], tstr("x"), head(3, 4), BOM_X, [0xff])), "x\ufeffx");
    equal("the display form keeps it too", Cbor.decode(cat(head(3, 4), BOM_X)), "\ufeffx");
    bothRead("the texts \"x\" and \"\\ufeffx\" are two keys", cat(head(5, 2), tstr("x"), head(0, 1), head(3, 4), BOM_X, head(0, 2)),
        { keys: ["x", "\ufeffx"], paths: ['["x"]', '["\ufeffx"]'] });
    bothRead("\"x\" and the chunks \"\\ufeff\" \"x\" are two keys", cat(head(5, 2), tstr("x"), head(0, 1),
        [0x7f, 0x63, 0xef, 0xbb, 0xbf], tstr("x"), [0xff], head(0, 2)), { keys: ["x", "\ufeffx"], paths: ['["x"]', '["\ufeffx"]'] });
    bothRead("\"xy\" and the chunks \"x\" \"\\ufeffy\" are two keys", cat(head(5, 2), tstr("xy"), head(0, 1),
        [0x7f], tstr("x"), tstr("\ufeffy"), [0xff], head(0, 2)), { keys: ["xy", "x\ufeffy"], paths: ['["xy"]', '["x\ufeffy"]'] });
    equal("the display form keeps \"x\" and \"\\ufeffx\" apart", Object.keys(Cbor.decode(cat(head(5, 2), tstr("x"), head(0, 1),
        head(3, 4), BOM_X, head(0, 2)))), ["x", "\ufeffx"]);
    // and UTF-8 is read strictly: a code point split across two chunks is not two chunks of text (RFC 8949 3.2.3)
    refusedWith("\"\u00fc\" split across two chunks", () => Cbor.decodeTyped(Uint8Array.of(0x7f, 0x61, 0xc3, 0x61, 0xbc, 0xff)),
        /not valid UTF-8/);
    refusedWith("an overlong encoding of \"/\"", () => Cbor.decodeTyped(Uint8Array.of(0x62, 0xc0, 0xaf)), /not valid UTF-8/);

    // finding 2: +0.0 and -0.0 are one key, whatever their widths
    bothRefuse("+0.0 and -0.0 (a2 f9 0000 01 f9 8000 02) are one key", Buffer.from("a2f9000001f9800002", "hex"), /duplicate map key/);
    bothRefuse("+0.0 as a half and -0.0 as a double are one key", Buffer.from("a2f9000001fb800000000000000002", "hex"), /duplicate map key/);
    // NaNs are one key exactly when their significands are, zero-extended at the right to 64 bits, sign aside
    bothRead("two NaNs whose significands differ (a2 f9 7e00 01 f9 7e01 02) are two keys", Buffer.from("a2f97e0001f97e0102", "hex"),
        { keys: ["NaN", "NaN"], paths: ['[{"key":"fNaN8000000000000000"}]', '[{"key":"fNaN8040000000000000"}]'] });
    bothRefuse("one NaN significand as a half and as a single", Buffer.from("a2f97e0001fa7fc0000002", "hex"), /duplicate map key/);
    bothRefuse("one NaN significand as a half and as a double", Buffer.from("a2f97e0001fb7ff800000000000002", "hex"), /duplicate map key/);
    bothRefuse("one NaN significand with either sign", Buffer.from("a2f97e0001f9fe0002", "hex"), /duplicate map key/);
    bothRead("a single-width NaN payload a half cannot hold is another key", Buffer.from("a2f97e0001fa7fc0000102", "hex"),
        { keys: ["NaN", "NaN"], paths: ['[{"key":"fNaN8000000000000000"}]', '[{"key":"fNaN8000020000000000"}]'] });

    // nit: a bignum key is the integer it carries (RFC 8949 3.4.3); one whose value an integer head holds is refused
    bothRefuse("the integer 1 and the bignum #6.2(h'01')", cat(head(5, 2), head(0, 1), head(0, 0), [0xc2, 0x41, 0x01], head(0, 0)),
        /bignum .* fits an integer head/);
    bothRefuse("a lone bignum key #6.3(h'00'), which is -1", cat(head(5, 1), [0xc3, 0x41, 0x00], head(0, 0)), /bignum .* fits an integer head/);
    bothRead("a bignum key beyond any integer head (2^64) is a key of its own",
        cat(head(5, 1), [0xc2, 0x49, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], head(0, 0)), { keys: ["#i18446744073709551616"],
            paths: ['[{"key":"i18446744073709551616"}]'] });
    bothRefuse("2^64 as a bignum with and without a leading zero byte", cat(head(5, 2), [0xc2, 0x49, 0x01, 0, 0, 0, 0, 0, 0, 0, 0],
        head(0, 0), [0xc2, 0x4a, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], head(0, 1)), /duplicate map key/);
    bothRefuse("the key [1] and the key [#6.2(h'01')]", cat(head(5, 2), head(4, 1), head(0, 1), head(0, 0), head(4, 1),
        [0xc2, 0x41, 0x01], head(0, 1)), /duplicate map key/);
    // a tag's byte-string content is read from the bytes, never through another tag
    refusedWith("a bignum around a tagged byte string (#6.2(#6.99(h'01')))", () => Cbor.decodeTyped(Uint8Array.of(0xc2, 0xd8, 0x63, 0x41, 0x01)),
        /tag 2 content is not a byte string/);
    refusedWith("a tag 24 around a tagged byte string (#6.24(#6.99(h'00')))", () => Cbor.decodeTyped(Uint8Array.of(0xd8, 0x18, 0xd8, 0x63, 0x41, 0x00)),
        /tag 24 content is not a byte string/);
});

// 2c. review round 3, major 1 and minor 4: the reader looks labels up by type, takes only int / tstr labels, and no
// label in both header buckets (RFC 9052 1.5 and 3). Only Mdoc's own interface is used, so these run on any build
await section("2c. COSE header labels and typed lookups in readIssuerSigned", async () => {
    const shaped = shapedMdl;
    const twoLabels = TWO_LABELS;
    // what the reader makes of the bytes, or its refusal: a refusal of a conformant credential is a failed check, not a crash
    const readsAs = (label, bytes, pick, expected) => {
        let got;
        try {
            got = pick(Mdoc.readIssuerSigned(bytes));
        } catch (error) {
            got = "refused: " + error.message;
        }
        equal(label, got, expected);
    };
    // the IssuerAuth: a protected header with both labels is a conformant credential, and alg is the integer label
    const bothProtected = shaped({ protectedRaw: twoLabels });
    readsAs("a protected header {1: -7, \"1\": ...} is read, and alg is the integer label's -7", bothProtected.bytes,
        (read) => read.issuerAuth.alg, -7);
    const bothVerdict = await verdictOf(bothProtected);
    check("checkKeepable keeps a credential whose protected header carries 1 and \"1\"", bothVerdict.ok === true,
        JSON.stringify(bothVerdict));
    // an unprotected header with x5chain (33) and a text label "33": the chain is the integer label's
    const textAndInt = shaped({ unprotectedRaw: (chain) => cat(head(5, 2), tstr("33"), tstr("not a chain"), head(0, 33), chain) });
    readsAs("x5chain is the integer label 33, never the text label \"33\"", textAndInt.bytes,
        (read) => read.issuerAuth.x5chain.map(hex), [hex(DUMMY_DER)]);
    check("checkKeepable keeps it", (await verdictOf(textAndInt)).ok === true);
    const textOnly = shaped({ unprotectedRaw: () => cat(head(5, 1), tstr("33"), bstr(DUMMY_DER)) });
    readsAs("a text label \"33\" alone is not an x5chain", textOnly.bytes, (read) => read.issuerAuth.x5chain, []);
    // a COSE_Key with a text label "1" next to kty: still the holder's EC2 P-256 key (RFC 9052 7: label = int / tstr)
    const deviceKey = coseKey(HOLDER_A_JWK);
    deviceKey.set("1", "a text label beside kty");
    const keyed = shaped({ deviceKey });
    const keyedVerdict = await verdictOf(keyed);
    check("checkKeepable reads the deviceKey's integer labels beside a text label \"1\"", keyedVerdict.ok === true,
        JSON.stringify(keyedVerdict));
    // DigestID = uint: a valueDigests keyed by the text "0", "1", ... is not the MSO's digest for item 0, 1, ...
    const textDigestIds = shaped({ valueDigests: (digests) => new Map([...digests].map(([namespace, byId]) =>
        [namespace, new Map([...byId].map(([id, digest]) => [String(id), digest]))])) });
    const textVerdict = await verdictOf(textDigestIds);
    check("checkKeepable refuses digests filed under text DigestIDs (the uint key is the one that counts)",
        textVerdict.ok === false && textVerdict.code === "digest", JSON.stringify(textVerdict));

    // a label of another type is not a COSE label (RFC 9052 1.5, 3)
    for (const [label, key] of [
        ["a byte string", bstr([0x21])],
        ["a float (33.0)", [0xfb, 0x40, 0x40, 0x80, 0, 0, 0, 0, 0]],
        ["a tag around the integer 33 (#6.1(33))", [0xc1, 0x18, 0x21]],
        ["an array", cat(head(4, 1), head(0, 33))],
        ["true", [0xf5]],
    ]) {
        const built = shaped({ unprotectedRaw: (chain) => cat(head(5, 2), head(0, 33), chain, key, head(0, 0)) });
        refusedWith(`an unprotected label that is ${label}`, () => Mdoc.readIssuerSigned(built.bytes),
            /a COSE label is an int or a tstr/);
    }
    const tagged33 = shaped({ protectedRaw: cat(head(5, 2), head(0, 1), head(1, 6), [0xc1, 0x18, 0x21], head(0, 0)) });
    refusedWith("a protected label that is a tag", () => Mdoc.readIssuerSigned(tagged33.bytes), /protected header has a label that is a tag/);
    // the round-2 decoy, in a header: a label that is the map {33: decoy}. Nothing inside it is a range, and it is refused
    const decoyDer = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x09]);
    const decoyKey = cat(head(5, 1), head(0, 33), bstr(decoyDer));
    const decoyHeader = shaped({ unprotectedRaw: (chain) => cat(head(5, 2), head(0, 33), chain, decoyKey, head(0, 0)) });
    const decoyBytes = cat(head(5, 2), head(0, 33), bstr(DUMMY_DER), decoyKey, head(0, 0));
    const decoyKeyStart = 1 + head(0, 33).length + bstr(DUMMY_DER).length;
    equal("Cbor.spans records nothing inside a header label that is a map", Cbor.spans(decoyBytes, 2).ranges
        .filter((range) => range.start >= decoyKeyStart && range.end <= decoyKeyStart + decoyKey.length), []);
    equal("only the real x5chain is recorded at [33]", Cbor.spans(decoyBytes, 2).ranges
        .filter((range) => JSON.stringify(range.path) === "[33]").map((range) => [range.start, range.end]),
        [[1 + head(0, 33).length, decoyKeyStart]]);
    refusedWith("a header label that is a map holding a decoy x5chain", () => Mdoc.readIssuerSigned(decoyHeader.bytes),
        /has a label that is a map; a COSE label is an int or a tstr/);
    // true duplicates in a header are refused, under any encoding
    refusedWith("a protected header with the label 1 twice (01, 18 01)", () => Mdoc.readIssuerSigned(shaped({
        protectedRaw: cat(head(5, 2), head(0, 1), head(1, 6), [0x18, 0x01], head(1, 6)) }).bytes), /duplicate map key 1/);
    refusedWith("an unprotected header with the label \"x\" twice (one in chunks)", () => Mdoc.readIssuerSigned(shaped({
        unprotectedRaw: (chain) => cat(head(5, 3), head(0, 33), chain, tstr("x"), head(0, 0), [0x7f, 0x61, 0x78, 0xff], head(0, 1)) })
        .bytes), /duplicate map key "x"/);

    // minor 4: a label in both buckets (RFC 9052 3). A stand-in x5chain in the protected bucket next to the real one in
    // the unprotected bucket, where ISO/IEC 18013-5 9.1.2.4 puts it, must not be what the reader returns
    const FAKE_DER = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x66]);
    const shadowed = shaped({ protectedRaw: cat(head(5, 2), head(0, 1), head(1, 6), head(0, 33), bstr(FAKE_DER)) });
    refusedWith("x5chain in the protected and the unprotected header", () => Mdoc.readIssuerSigned(shadowed.bytes),
        /label 33 is in both the protected and the unprotected header/);
    const shadowVerdict = await verdictOf(shadowed);
    check("checkKeepable refuses the shadowed x5chain", shadowVerdict.ok === false && shadowVerdict.code === "issuer-signed",
        JSON.stringify(shadowVerdict));
    refusedWith("alg in both headers", () => Mdoc.readIssuerSigned(shaped({
        unprotectedRaw: (chain) => cat(head(5, 2), head(0, 1), head(1, 6), head(0, 33), chain) }).bytes),
        /label 1 is in both/);
    const textBeside = shaped({ unprotectedRaw: (chain) => cat(head(5, 2), tstr("1"), tstr("not alg"), head(0, 33), chain) });
    readsAs("the integer label 1 in one bucket and the text label \"1\" in the other are two labels: both kept",
        textBeside.bytes, (read) => read.issuerAuth.alg, -7);

    // a namespace named "__proto__" is a namespace like any other: its items are checked, never hidden
    const proto = buildIssuerSigned({ docType: DOC_TYPE, holder: HOLDER_A_JWK,
        elements: { [MDL_NAMESPACE]: { given_name: "Lorem" }, ["__proto__"]: { proto_element: "a value" } }, tamper: "proto_element" });
    readsAs("readIssuerSigned lists a \"__proto__\" namespace", proto.bytes, (read) => Object.keys(read.nameSpaces).sort(),
        ["__proto__", MDL_NAMESPACE].sort());
    const protoVerdict = await verdictOf(proto);
    check("and checkKeepable checks its items: a changed one is refused", protoVerdict.ok === false && protoVerdict.code === "digest",
        JSON.stringify(protoVerdict));
});

// 2e. review round 4: the same equivalence where a credential is decided - COSE header labels, an element value whose
// digest matches - and the major types of the values a decision reads (the MSO, the deviceKey, each item's digestID)
await section("2e. key equivalence and value types in readIssuerSigned and checkKeepable", async () => {
    const shaped = shapedMdl;
    const BOM_X = Buffer.from("\ufeffx", "utf8");
    const keeps = async (label, built) => {
        const verdict = await verdictOf(built);
        check(`checkKeepable keeps ${label}`, verdict.ok === true, JSON.stringify(verdict));
    };
    const refuses = async (label, built, code, pattern, options = {}) => {
        let verdict;
        try {
            verdict = await verdictOf(built, options.publicJwk);
        } catch (error) {
            verdict = { thrown: String(error) };
        }
        check(`checkKeepable refuses ${label}`, verdict.ok === false && verdict.code === code && pattern.test(verdict.message),
            JSON.stringify(verdict));
    };

    // finding 1, in a COSE header: the labels "x" and "\ufeffx" are two labels (RFC 9052 1.5: tstr labels are text)
    const bomProtected = shaped({ protectedRaw: cat(head(5, 3), head(0, 1), head(1, 6), tstr("x"), head(0, 1), head(3, 4), BOM_X, head(0, 2)) });
    let alg;
    try {
        alg = Mdoc.readIssuerSigned(bomProtected.bytes).issuerAuth.alg;
    } catch (error) {
        alg = "refused: " + error.message;
    }
    equal("a protected header {1: -7, \"x\": 1, \"\\ufeffx\": 2} is read, alg -7", alg, -7);
    await keeps("a protected header carrying \"x\" and \"\\ufeffx\"", bomProtected);
    const bomChunked = shaped({ unprotectedRaw: (chain) => cat(head(5, 3), head(0, 33), chain, tstr("x"), head(0, 1),
        [0x7f, 0x63, 0xef, 0xbb, 0xbf], tstr("x"), [0xff], head(0, 2)) });
    await keeps("an unprotected header carrying \"x\" and the chunks \"\\ufeff\" \"x\"", bomChunked);
    const bomBuckets = shaped({ unprotectedRaw: (chain) => cat(head(5, 2), head(0, 33), chain, head(3, 4), BOM_X, head(0, 2)),
        protectedRaw: cat(head(5, 2), head(0, 1), head(1, 6), tstr("x"), head(0, 1)) });
    await keeps("\"x\" in the protected and \"\\ufeffx\" in the unprotected header (two labels, not one in both)", bomBuckets);

    // finding 2, in an element value whose digest is computed over exactly these bytes: only the key rule can refuse it
    const element = (valueBytes) => (digestId, random) => cat(head(5, 4), tstr("digestID"), head(0, digestId), tstr("random"),
        bstr(random), tstr("elementIdentifier"), tstr("family_name"), tstr("elementValue"), valueBytes);
    await refuses("an element value {+0.0: 1, -0.0: 2} (one key twice), its digest matching",
        shaped({ rawItems: { family_name: element(Buffer.from("a2f9000001f9800002", "hex")) } }), "issuer-signed", /duplicate map key/);
    const nans = shaped({ rawItems: { family_name: element(Buffer.from("a2f97e0001f97e0102", "hex")) } });
    await keeps("an element value whose two NaN keys have distinct significands", nans);
    equal("and reads both of its keys", Mdoc.readIssuerSigned(nans.bytes).nameSpaces[MDL_NAMESPACE][0].elementValue.size, 2);
    await refuses("an element value {1: \"a\", #6.2(h'01'): \"b\"}", shaped({ rawItems: { family_name: element(cat(head(5, 2),
        head(0, 1), tstr("a"), [0xc2, 0x41, 0x01], tstr("b"))) } }), "issuer-signed", /bignum/);

    // nit: the values a decision reads are of their CDDL types, read from the bytes, not only from what they decode to
    const item = (digestIdBytes) => (digestId, random) => cat(head(5, 4), tstr("digestID"), digestIdBytes, tstr("random"),
        bstr(random), tstr("elementIdentifier"), tstr("family_name"), tstr("elementValue"), tstr("Ipsum"));
    const notUint = /family_name digestID .* not an unsigned integer/;
    for (const [label, digestId, pattern] of [["the float 0.0", [0xf9, 0x00, 0x00], notUint], ["#6.99(0)", [0xd8, 0x63, 0x00], notUint],
        // a bignum decodes to a BigInt, which the value check refuses before the shape check is reached
        ["a bignum #6.2(h'00')", [0xc2, 0x41, 0x00], /is not an element map/]]) {
        await refuses(`a digestID that is ${label} (DigestID = uint), its digest matching`, shaped({ rawItems: { family_name: item(digestId) } }),
            "issuer-signed", pattern);
    }
    await refuses("an elementIdentifier that is #6.99(tstr)", shaped({ rawItems: { family_name: (digestId, random) => cat(head(5, 4),
        tstr("digestID"), head(0, digestId), tstr("random"), bstr(random), tstr("elementIdentifier"), [0xd8, 0x63], tstr("family_name"),
        tstr("elementValue"), tstr("Ipsum")) } }), "issuer-signed", /elementIdentifier .* not a text string/);
    await refuses("an IssuerSignedItem map inside #6.55799 within its tag-24 bstr", shaped({ rawItems: { family_name: (digestId, random) =>
        cat(head(6, 55799), item(head(0, digestId))(digestId, random)) } }), "issuer-signed", /does not embed an IssuerSignedItem map/);
    await refuses("an IssuerSignedItemBytes #6.24(#6.99(bstr))", shaped({ itemForms: { family_name: "tag24tagged" } }), "issuer-signed",
        /tag 24 content is not a byte string/);

    const keyWith = (overrides) => {
        const key = coseKey(HOLDER_A_JWK);
        for (const [label, value] of overrides) key.set(label, value);
        return key;
    };
    const holderX = bytesOf(Buffer.from(HOLDER_A_JWK.x, "base64url"));
    for (const [label, overrides, pattern] of [
        ["kty is the float 2.0", [[1, Cbor.Raw([0xf9, 0x40, 0x00])]], /deviceKey kty .* is a simple value/],
        ["kty is #6.99(2)", [[1, Cbor.Raw([0xd8, 0x63, 0x02])]], /deviceKey kty .* is a tag/],
        ["crv is the float 1.0", [[-1, Cbor.Raw([0xf9, 0x3c, 0x00])]], /deviceKey crv .* is a simple value/],
        ["x is #6.99(bstr)", [[-2, new Cbor.Tagged(99, holderX)]], /deviceKey x .* is a tag/],
        ["y is null", [[-3, null]], /deviceKey y .* is a simple value/],
    ]) {
        await refuses(`a deviceKey whose ${label}`, shaped({ deviceKey: keyWith(overrides) }), "issuer-signed", pattern);
    }
    // the shapes COSE_Key allows still reach check 3, which names what this page holds
    await refuses("a deviceKey whose kty is the text \"EC2\" at check 3, not as a shape", shaped({ deviceKey: keyWith([[1, "EC2"]]) }),
        "device-key", /label 1 must be 2/);
    // a compressed point (RFC 9053 7.1.1: y is the bool sign of the y coordinate) is the holder's key when x and the sign match
    const holderYOdd = (Buffer.from(HOLDER_A_JWK.y, "base64url").at(-1) & 1) === 1;
    await keeps("a deviceKey compressed to x and the bool sign of the holder's y", shaped({ deviceKey: keyWith([[-3, holderYOdd]]) }));
    await refuses("a deviceKey compressed to x and the opposite sign", shaped({ deviceKey: keyWith([[-3, !holderYOdd]]) }),
        "device-key", /not this browser's key/);
    // a bstr y is still compared in full: the holder's x with another y of the same sign is another key
    const sameSignOtherY = Buffer.from(HOLDER_A_JWK.y, "base64url");
    sameSignOtherY[31] ^= 0x02;
    await refuses("a deviceKey with the holder's x and another bstr y of the same sign", shaped({ deviceKey: keyWith([[-3,
        new Uint8Array(sameSignOtherY)]]) }), "device-key", /not this browser's key/);
    // and a held y that is not a 32-byte base64url coordinate gives no sign: refused, never thrown
    for (const badY of ["A", "AAAAA", "AA", HOLDER_A_JWK.y + "="]) {
        await refuses(`a compressed deviceKey checked against a held y of ${JSON.stringify(badY.slice(0, 8))}… (${badY.length} chars)`,
            shaped({ deviceKey: keyWith([[-3, true]]) }), "device-key", /not this browser's key/, { publicJwk: { ...HOLDER_A_JWK, y: badY } });
    }
    await refuses("a deviceKey compressed to another x and the holder's sign", shaped({ deviceKey: keyWith([[-2, new Uint8Array(32).fill(7)],
        [-3, holderYOdd]]) }), "device-key", /not this browser's key/);
    await refuses("a docType that is #6.99(tstr)", shaped({ docType: new Cbor.Tagged(99, DOC_TYPE) }), "issuer-signed", /docType, a tstr, is a tag/);
    await refuses("a Digest that is #6.99(bstr)", shaped({ valueDigests: (digests) => new Map([...digests].map(([namespace, byId]) =>
        [namespace, new Map([...byId].map(([id, digest]) => [id, new Cbor.Tagged(99, digest)]))])) }), "issuer-signed", /Digest 0 of .* is a tag/);
    await refuses("a valueDigests namespace map inside #6.99", shaped({ valueDigests: (digests) => new Map([...digests].map(([namespace, byId]) =>
        [namespace, new Cbor.Tagged(99, byId)])) }), "issuer-signed", /DigestIDs of .* is a tag/);
    await refuses("an MSO map inside #6.55799 within its bstr", shaped({ msoTag: 55799 }), "issuer-signed", /not an MSO map/);
    await refuses("an MSO bstr inside #6.99 within the tag 24", shaped({ msoContentTag: 99 }), "issuer-signed", /MSO content is not a byte string/);
    // and Certify's own credential and the built one are still kept
    await keeps("the built mDL", MDL_A);
});

// 3. the IssuerSigned Certify's own MdocFormatter produced (plan 4.12): the layout real mDLs arrive in
await section("3. Certify's own IssuerSigned", async () => {
    const read = Mdoc.readIssuerSigned(CERTIFY_ISSUER_SIGNED);
    equal("the fixture is the mDL the formatter issued", read.issuerAuth.mso.get("docType"), DOC_TYPE);
    equal("its MSO version is the formatter's", read.issuerAuth.mso.get("version"), "1.0");
    equal("the IssuerAuth payload is a bstr holding the tag-24 MSO", read.issuerAuth.mso.get("digestAlgorithm"), "SHA-256");
    const validityInfo = read.issuerAuth.mso.get("validityInfo");
    check("the validity window is the formatter's tdate text",
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(validityInfo.get("validFrom"))
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(validityInfo.get("validUntil")),
        JSON.stringify([...validityInfo]));
    // Certify signs without the IACA, so the chain is the DSC alone: RFC 9360 section 2's single bstr, which this
    // reader used to refuse outright
    equal("the DSC-only x5chain arrives as a single bstr and is read as one certificate", read.issuerAuth.x5chain.length, 1);
    check("and it is a real DER certificate, not a placeholder", read.issuerAuth.x5chain[0].length > 300,
        String(read.issuerAuth.x5chain[0].length));
    const items = read.nameSpaces[MDL_NAMESPACE];
    equal("mdl-a carries the 15 elements the demo issues to mdl-demo-1 (plan 4.12)",
        items.map((item) => item.elementIdentifier).sort(), MDL_DEMO_1_ELEMENTS.slice().sort());
    for (const item of items) {
        const expected = read.issuerAuth.mso.get("valueDigests").get(MDL_NAMESPACE).get(item.digestID);
        equal(`Certify fixture: ${item.elementIdentifier} hashes to its valueDigest`, hex(hash("sha256", item.raw)), hex(expected));
    }
    const verdict = await Mdoc.checkKeepable({ issuerSigned: CERTIFY_ISSUER_SIGNED, doctype: DOC_TYPE,
        publicJwk: CERTIFY_PUBLIC_JWK });
    check("Certify's own credential passes every keep check", verdict.ok === true, JSON.stringify(verdict));
    equal("and it reports the formatter's docType", verdict.docType, DOC_TYPE);

    // review round 2, major 2: the real Certify credential plus one more IssuerSigned entry whose key is the map
    // {"issuerAuth": <10-byte decoy>}. Were the key's contents recorded, the reader would return the decoy as
    // issuerAuth.raw while every check ran on the real MSO.
    const issuerAuthKey = tstr("issuerAuth");
    const nameSpacesKey = tstr("nameSpaces");
    equal("probe: Certify writes a two-entry IssuerSigned with issuerAuth first", hex(CERTIFY_ISSUER_SIGNED.subarray(0, 12)),
        "a2" + hex(issuerAuthKey));
    const realEnd = Buffer.from(CERTIFY_ISSUER_SIGNED).indexOf(nameSpacesKey, 12);
    const decoy = Uint8Array.from([0x4a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const rootProbe = new Uint8Array(Buffer.concat([Buffer.from([0xa3]), Buffer.from(CERTIFY_ISSUER_SIGNED.subarray(1)),
        Buffer.from(head(5, 1)), issuerAuthKey, Buffer.from(decoy), Buffer.from([0xf6])]));
    const rootWalk = Cbor.spans(rootProbe, 3);
    equal("Cbor.spans records one issuerAuth, the real one, and nothing of the key's decoy",
        rootWalk.ranges.filter((range) => JSON.stringify(range.path) === "[\"issuerAuth\"]").map((range) => [range.start, range.end]),
        [[12, realEnd]]);
    const rootKeyStart = CERTIFY_ISSUER_SIGNED.length;
    const rootKeyEnd = rootKeyStart + head(5, 1).length + issuerAuthKey.length + decoy.length;
    const insideRootKey = (range) => range.start >= rootKeyStart && range.end <= rootKeyEnd;
    check("no range lies inside the decoy key", !rootWalk.ranges.some(insideRootKey),
        JSON.stringify(rootWalk.ranges.filter(insideRootKey)));
    equal("the key is recorded as what it is: a map at the IssuerSigned's top level",
        rootWalk.keys.filter((key) => key.path.length === 0).map((key) => key.major), [3, 3, 5]);
    refusedWith("an IssuerSigned key that is a map", () => Mdoc.readIssuerSigned(rootProbe), /an IssuerSigned key is a map, not a text string/);
    const probeVerdict = await Mdoc.checkKeepable({ issuerSigned: rootProbe, doctype: DOC_TYPE, publicJwk: CERTIFY_PUBLIC_JWK });
    check("checkKeepable refuses the decoy-key probe", probeVerdict.ok === false && probeVerdict.code === "issuer-signed",
        JSON.stringify(probeVerdict));
    // a text key IssuerSigned does not define is refused too (its CDDL map is closed)
    const extraKey = new Uint8Array(Buffer.concat([Buffer.from([0xa3]), Buffer.from(CERTIFY_ISSUER_SIGNED.subarray(1)),
        tstr("deviceSigned"), Buffer.from([0xa0])]));
    refusedWith("an IssuerSigned key the structure does not define", () => Mdoc.readIssuerSigned(extraKey), /"deviceSigned"/);

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

    // review round 2 (nit): a run's note about keeping belongs to that run. The first run keeps and says so; a second
    // run with the box unticked keeps nothing and must not leave the first run's "Kept" on screen
    const twice = openOffer();
    await issue(twice);
    check("first run: the page says it kept the credential", twice.el("keepNote").hidden === false
        && twice.el("keepNote").textContent.includes("Kept in this browser"), twice.el("keepNote").textContent);
    twice.el("keep").checked = false;
    await twice.runWallet();
    await twice.settle();
    equal("second run, unticked: the first run's note is gone", [twice.el("keepNote").hidden, twice.el("keepNote").textContent], [true, ""]);
    equal("and still only the first run's credential is kept", credentialsIn(twice.indexedDB).length, 1);

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
    // review round 3 (nit): Delete acts on the selected credential, so it is off until one is selected
    equal("Delete is disabled while nothing is selected", wallet.el("delete").disabled, true);
    const openedDetails = list.children[0].children[0];
    await openedDetails.fire("click");
    equal("the details view opens", wallet.el("details").hidden, false);
    equal("and Delete is enabled for the selected credential", wallet.el("delete").disabled, false);
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

// 13. Delete everything with other tabs open (the harness's fake: its own bookkeeping says what happened underneath)
await section("13. Delete everything with other tabs open", async () => {
    const fake = new FakeIndexedDB();
    const keepOne = openOffer({ indexedDB: fake });
    await issue(keepOne);
    equal("a credential is kept", credentialsIn(fake).length, 1);

    // two more connections, as two open wallet tabs would hold: the page's own delete closes its own first
    const WalletStore = storeOn(fake);
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

    // a tab that does not close: the delete stays queued (blocked is not an outcome) and the store stays until it does
    const blocking = new FakeIndexedDB();
    await seedRecords(blocking, 1);
    const stubborn = await storeOn(blocking).open();
    stubborn.onversionchange = null; // a tab that does not close (an older build, a frozen tab)
    const blockedWallet = openWallet(blocking);
    await waitFor(() => blockedWallet.el("records").children.length === 1);
    const openRequestsBefore = blocking.openRequests;
    let finished = false;
    const pressed = blockedWallet.el("deleteAll").fire("click").then(() => { finished = true; });
    await waitFor(() => blockedWallet.el("storageStatus").textContent.includes("Waiting for other wallet tabs"));
    await settle();
    equal("while blocked, the delete has not completed", [blocking.deletions, blocking.databases.has(DB_NAME), finished], [0, true, false]);
    equal("and the page has asked for no open behind it (an open would queue behind the delete)",
        blocking.openRequests, openRequestsBefore);
    stubborn.close();
    await pressed;
    await settle();
    equal("once the other tab closes, the delete completes, and only then the page reopens (an empty store)",
        [blocking.deletions, blocking.openRequests - openRequestsBefore, blocking.databases.has(DB_NAME)], [1, 1, true]);

    // the browser closing the page's connection (site data cleared): the page says so instead of failing later
    const closing = new FakeIndexedDB();
    await seedRecords(closing, 1);
    const closedWallet = openWallet(closing);
    await waitFor(() => closedWallet.el("records").children.length === 1);
    [...closing.databases.get(DB_NAME).connections].forEach((connection) => connection.forceClose());
    await waitFor(() => closedWallet.el("storageStatus").textContent.includes("closed the credential store"));
    check("a connection the browser closed is reported, with what to do", closedWallet.el("storageStatus").textContent.includes("reload"),
        closedWallet.el("storageStatus").textContent);
    equal("and the list and the controls no longer offer a closed store", [closedWallet.el("records").children.length,
        closedWallet.el("deleteAll").disabled, closedWallet.el("delete").disabled], [0, true, true]);
});

// 14. the storage model itself, and the page's deletes, held to IndexedDB 3.0 (the same scenarios run on fake-indexeddb)
await storageConformance(() => new FakeIndexedDB(), "harness fake");
await walletDeleteScenarios(() => new FakeIndexedDB(), "harness fake");

// 15. I4 on the wallet page: with the wallet switched off, wallet/config answers 404 and the page opens no store at all,
// whatever path served it; with it on, the only request the page makes is that one (I9)
await section("15. the wallet page asks the switch before it stores anything", async () => {
    const off = new FakeIndexedDB();
    const offWallet = openWallet(off, { walletConfig: false });
    await settle();
    equal("switched off: no connection was opened", off.opens, 0);
    equal("and no database exists", off.databases.size, 0);
    check("the page says the wallet is off", offWallet.el("storageStatus").textContent.includes("switched off"),
        offWallet.el("storageStatus").textContent);
    equal("and offers nothing to delete", [offWallet.el("deleteAll").disabled, offWallet.el("delete").disabled], [true, true]);
    const on = new FakeIndexedDB();
    const onWallet = openWallet(on);
    await settle();
    equal("switched on: one connection", on.opens, 1);
    equal("the wallet page's only request is its own config (I9)", onWallet.requests.map((request) => [request.method, request.url]),
        [["GET", "https://credentials.example/v1/certify/offer/wallet/config"]]);
});

// 16. review round 3, minor 2: a keep that waits behind another tab's "Delete everything" does not hold the run. The
// store's open queues behind the pending delete (IndexedDB 3.0 5.1); the harness fake models that queue
await section("16. a keep waiting for the store does not hold the run", async () => {
    const fake = new FakeIndexedDB();
    await seedRecords(fake, 1);
    const stubborn = await storeOn(fake).open();
    stubborn.onversionchange = null; // another wallet tab that does not close, so the delete stays pending
    const blocked = [];
    let deleted = false;
    storeOn(fake).deleteEverything(() => blocked.push("blocked")).then(() => { deleted = true; });
    await waitFor(() => blocked.length === 1);
    equal("probe: another tab's delete is pending, blocked by a tab that stays open", [blocked.length, deleted], [1, false]);

    const page = openOffer({ indexedDB: fake });
    await page.settle();
    page.el("subject").value = "mdl-demo-1";
    await page.createOffer();
    let handlerDone = false;
    const run = page.runWallet().then(() => { handlerDone = true; });
    const back = await waitForMs(() => page.el("walletStatus").textContent.includes("Credential issued")
        && page.el("wallet").disabled === false && page.el("create").disabled === false, 3000);
    check("the run ends - Redeem and Create come back - while the store waits behind the delete", back,
        JSON.stringify([page.el("walletStatus").textContent, page.el("wallet").disabled, page.el("create").disabled]));
    const told = await waitForMs(() => page.el("keepNote").textContent.includes("Waiting for the credential store"), 3000);
    check("the page says it is waiting for the store, and why", told && page.el("keepNote").hidden === false
        && page.el("keepNote").textContent.includes("another tab is deleting it"), page.el("keepNote").textContent);
    equal("nothing is written while the delete is pending", credentialsIn(fake).map((record) => record.id), ["seed-0"]);
    equal("and the keep is still waiting", handlerDone, false);

    stubborn.close();
    const kept = await waitForMs(() => page.el("keepNote").textContent.includes("Kept in this browser"), 3000);
    check("once the other tab closes, the delete finishes and the keep reports its outcome", kept, page.el("keepNote").textContent);
    equal("the delete happened first, and the credential went into the new store", [deleted, credentialsIn(fake).length,
        credentialsIn(fake).length === 1 && hex(credentialsIn(fake)[0].issuerSigned) === hex(MDL_A.bytes)], [true, 1, true]);
    await run;
});

// 16b. review round 4, finding 3: a keep tagged with its run. Run 1's keep waits behind another tab's blocked delete;
// the visitor unticks Keep and redeems again. Run 2 must not hide run 1's pending note, and when the blocker closes
// run 1's outcome is reported as the earlier credential's, never as run 2's
await section("16b. a late keep reports as the earlier run's, in a note of its own", async () => {
    const blockedStore = async () => {
        const fake = new FakeIndexedDB();
        await seedRecords(fake, 1);
        const stubborn = await storeOn(fake).open();
        stubborn.onversionchange = null; // another wallet tab that does not close, so the delete stays pending
        const blocked = [];
        storeOn(fake).deleteEverything(() => blocked.push("blocked"));
        await waitFor(() => blocked.length === 1);
        return { fake, stubborn };
    };
    const notes = (page) => page.el("keepNote").children.map((note) => note.textContent);
    const KEPT = "Kept in this browser: " + DOC_TYPE + ".";

    const { fake, stubborn } = await blockedStore();
    const page = openOffer({ indexedDB: fake });
    await page.settle();
    page.el("subject").value = "mdl-demo-1";
    await page.createOffer();
    const first = page.runWallet(); // ends only when its keep does
    const waiting = await waitForMs(() => page.el("keepNote").textContent.includes("Waiting for the credential store")
        && page.el("wallet").disabled === false, 3000);
    check("run 1 has ended and its keep waits behind the other tab's delete", waiting, page.el("keepNote").textContent);

    page.el("keep").checked = false;
    await page.runWallet();
    await page.settle();
    check("run 2 (Keep unticked) has ended", page.el("walletStatus").textContent.includes("Credential issued"),
        page.el("walletStatus").textContent);
    equal("run 2 does not hide the note of run 1's keep, which is still pending", page.el("keepNote").hidden, false);
    equal("and labels it as the earlier credential's", page.el("keepNote").textContent, "Earlier credential: Waiting for the"
        + " credential store (another tab is deleting it). This credential is checked and kept once that delete is done.");

    stubborn.close();
    const reported = await waitForMs(() => page.el("keepNote").textContent.includes("Kept in this browser"), 3000);
    check("once the blocker closes, run 1's keep reports its outcome", reported, page.el("keepNote").textContent);
    equal("as the earlier credential's result, never as run 2's", page.el("keepNote").textContent, "Earlier credential: " + KEPT);
    equal("in the one note on screen", notes(page), ["Earlier credential: " + KEPT]);
    equal("run 1's credential was kept, run 2's was not", credentialsIn(fake).length, 1);
    await first;

    // the next run starts afresh: the finished earlier note goes, and its own note is unlabelled
    page.el("keep").checked = true;
    await page.runWallet();
    await page.settle();
    equal("run 3's note is its own, and only that", notes(page), [KEPT]);
    equal("and it kept its credential", credentialsIn(fake).length, 2);

    // two keeps pending at once: each has its own note, and neither result replaces the other's
    const both = await blockedStore();
    const twice = openOffer({ indexedDB: both.fake });
    await twice.settle();
    twice.el("subject").value = "mdl-demo-1";
    await twice.createOffer();
    const runOne = twice.runWallet();
    await waitForMs(() => twice.el("keepNote").textContent.includes("Waiting") && twice.el("wallet").disabled === false, 3000);
    const runTwo = twice.runWallet();
    const twoWaiting = await waitForMs(() => notes(twice).length === 2 && notes(twice)[1].startsWith("Waiting"), 3000);
    check("two pending keeps: two notes, the earlier one labelled", twoWaiting && notes(twice)[0].startsWith("Earlier credential: Waiting"),
        JSON.stringify(notes(twice)));
    both.stubborn.close();
    await waitForMs(() => credentialsIn(both.fake).length === 2, 3000);
    await Promise.all([runOne, runTwo]);
    equal("each reports in its own note", notes(twice), ["Earlier credential: " + KEPT, KEPT]);
    equal("and both were kept", credentialsIn(both.fake).length, 2);
});

// 17. review round 3, minor 3: a wallet tab whose first list read outlives its connection. Another tab deletes
// everything while the startup getAll is outstanding (the fake's `hold` keeps that read pending)
await section("17. a list read on a given-up connection is never shown", async () => {
    const fake = new FakeIndexedDB();
    await seedRecords(fake, 2);
    const stubborn = await storeOn(fake).open();
    stubborn.onversionchange = null; // keeps the delete pending after the wallet tab has let go
    const startupList = fake.hold("getAll", "credentials");
    const wallet = openWallet(fake);
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    const trace = traceControls(wallet);
    await startupList.reached;
    let deleted = false;
    storeOn(fake).deleteEverything().then(() => { deleted = true; });
    const told = await waitFor(() => wallet.el("storageStatus").textContent.includes("Another wallet tab is deleting everything"));
    check("the tab hears of the delete while its first list read is still outstanding",
        told && startupList.request.readyState === "pending", wallet.el("storageStatus").textContent);
    startupList.release();
    await waitFor(() => startupList.request.readyState === "done");
    await settle();
    equal("probe: the read answered on the given-up connection, and the delete still waits for the other tab",
        [startupList.request.result.length, deleted], [2, false]);
    equal("the answer is dropped: no deleted record is listed, so none can be clicked", [wallet.el("records").children.length,
        listButtons(wallet).filter((button) => !button.disabled).length], [0, 0]);
    equal("Delete everything and Delete stay off while the tab reconnects", [wallet.el("deleteAll").disabled,
        wallet.el("delete").disabled], [true, true]);

    // the reconnect's own read, held so the controls can be seen while it runs; another tab keeps a credential meanwhile
    const reconnectList = fake.hold("getAll", "credentials");
    stubborn.close();
    await reconnectList.reached;
    fake.databases.get(DB_NAME).stores.get("credentials").putClone({ id: "kept-after", format: "mso_mdoc", docType: DOC_TYPE,
        issuerSigned: MDL_A.bytes, storedAt: 99, label: "Kept after the delete" });
    await settle();
    equal("while the reconnect lists the store, nothing is listed and every control is off", [wallet.el("records").children.length,
        wallet.el("deleteAll").disabled, wallet.el("delete").disabled], [0, true, true]);
    reconnectList.release();
    await waitFor(() => wallet.el("records").children.length === 1 && wallet.el("deleteAll").disabled === false);
    check("the tab says another tab deleted everything", wallet.el("storageStatus").textContent.includes("Another wallet tab deleted everything"),
        wallet.el("storageStatus").textContent);
    equal("the list is the store as it now is", listButtons(wallet).map((button) => button.textContent), ["Kept after the delete"]);
    equal("and the controls are back (Delete waits for a selection)", [wallet.el("deleteAll").disabled, listButtons(wallet)[0].disabled,
        wallet.el("delete").disabled], [false, false, true]);
    // the startup ending must not clear the reconnect's busy: no control came back before the reconnect had finished
    const enabledAt = trace.indexOf("deleteAll enabled");
    const reconnectedAt = trace.findIndex((entry) => entry.startsWith("status: Another wallet tab deleted everything"));
    check("no control came back before the reconnect said it was done", reconnectedAt >= 0 && enabledAt > reconnectedAt,
        JSON.stringify(trace));
});

// 18. review round 3 (nit): a page timer is a task of its own, so the fake's transactions of the task before are
// inactive in its callback (IndexedDB 3.0 2.7.1), as they are in a browser
await section("18. a page timer starts a task", async () => {
    const fake = new FakeIndexedDB();
    const store = storeOn(fake);
    const db = await store.open();
    // two timers due together run back to back in Node's timers phase, before any setImmediate: the second callback is
    // a task after the first, so the transaction the first one made is inactive in it
    const seen = await new Promise((done) => {
        let objectStore = null;
        taskTimers.setTimeout(() => {
            objectStore = db.transaction(store.CREDENTIALS, "readonly").objectStore(store.CREDENTIALS);
        }, 0);
        taskTimers.setTimeout(() => {
            try {
                objectStore.count();
                done("active");
            } catch (error) {
                done(error.name);
            }
        }, 0);
    });
    equal("a request from the next timer's callback meets an inactive transaction", seen, "TransactionInactiveError");
    db.close();
});

// 19. review round 4 (nit): an operation's closing message is written only while its connection is still the page's.
// Another tab deletes everything while this tab's own "Delete everything" (or "Delete") is finishing; that tab's
// message is the newer news, and the older confirmation must not be written over it
await section("19. a closing message never overwrites another tab's newer one", async () => {
    const DELETING = "Another wallet tab is deleting everything";
    const after = (history, message) => history.slice(history.findIndex((entry) => entry.startsWith(DELETING)) + 1)
        .filter((entry) => entry.startsWith(message));

    // "Delete everything": its list read after reopening is held while the other tab's delete begins
    const fake = new FakeIndexedDB();
    await seedRecords(fake, 2);
    const wallet = openWallet(fake);
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    await settle();
    const history = statusHistory(wallet);
    const reopenList = fake.hold("getAll", "credentials");
    const pressed = wallet.el("deleteAll").fire("click");
    await reopenList.reached;
    storeOn(fake).deleteEverything();
    const told = await waitFor(() => history.some((entry) => entry.startsWith(DELETING)));
    check("probe: the other tab's delete reached this tab while its own was finishing", told, JSON.stringify(history));
    reopenList.release();
    await pressed;
    await waitFor(() => wallet.el("storageStatus").textContent.startsWith("Another wallet tab deleted everything"));
    equal("this tab's \"was deleted\" is never written after the other tab's message", after(history,
        "Everything kept in this browser was deleted"), []);
    check("the status is the other tab's outcome", wallet.el("storageStatus").textContent.startsWith("Another wallet tab deleted everything"),
        JSON.stringify(history));

    // "Delete": its delete request is held while the other tab's delete begins
    const single = new FakeIndexedDB();
    await seedRecords(single, 2);
    const one = openWallet(single);
    await settle();
    const oneHistory = statusHistory(one);
    await listButtons(one)[0].fire("click");
    const removal = single.hold("delete", "credentials");
    const deleting = one.el("delete").fire("click");
    await removal.reached;
    storeOn(single).deleteEverything();
    const heard = await waitFor(() => oneHistory.some((entry) => entry.startsWith(DELETING)));
    check("probe: the other tab's delete reached this tab while its Delete was finishing", heard, JSON.stringify(oneHistory));
    removal.release();
    await deleting;
    await waitFor(() => one.el("storageStatus").textContent.startsWith("Another wallet tab deleted everything"));
    equal("this tab's \"Deleted …\" is never written after the other tab's message", after(oneHistory, "Deleted "), []);
    check("the status is the other tab's outcome", one.el("storageStatus").textContent.startsWith("Another wallet tab deleted everything"),
        JSON.stringify(oneHistory));
});

// --------------------------------------------------------------------------------------------- P5-03c sections

await section("20. X.509 certificates, signatures and the verifier's chain (P5-03c)", async () => {
    const leaf = X509.parse(derOf("verifier"));
    equal("the leaf's subject is the fixture's", leaf.subject.text, "C=IN, O=Inji Demo Certify, CN=Wallet Fixture Verifier");
    equal("the leaf's issuer is the test CA", leaf.issuer.text, "C=IN, O=Inji Demo Certify, CN=Wallet Fixture Verifier CA");
    equal("the leaf's validity is read as the certificate wrote it",
        [leaf.notBefore.toISOString(), leaf.notAfter.toISOString()],
        ["2026-01-01T00:00:00.000Z", "2036-01-01T00:00:00.000Z"]);
    equal("its dNSName and URI subject alternative names are read (RFC 5280 4.2.1.6)",
        leaf.sans, { dnsNames: ["verifier.example"], uris: ["https://verifier.example/v1/certify/offer/wallet"] });
    equal("it is a version 3 leaf, not a CA, and can only sign",
        [leaf.version, leaf.ca, leaf.keyUsageText], [3, false, "digitalSignature"]);
    equal("its key is the P-256 EC key it carries", leaf.publicKey, { kind: "ec", curve: "P-256" });
    equal("its AKI is the CA's SKI (RFC 5280 4.2.1.1)", hex(leaf.aki), hex(X509.parse(derOf("ca")).ski));
    equal("its own SKI is 20 bytes", leaf.ski.length, 20);
    equal("the CA's basic constraints carry cA and pathLen 2",
        [X509.parse(derOf("ca")).ca, X509.parse(derOf("ca")).pathLength], [true, 2]);
    equal("the intermediate's pathLen is 0", X509.parse(derOf("intermediate")).pathLength, 0);
    equal("the RSA leaf's key is named by its size", X509.parse(derOf("rsa-leaf")).publicKey, { kind: "rsa", bits: 2048 });

    // each certificate's signature with the next one's key (RFC 5280 6.1.3 (a)(1))
    const issuedBy = async (child, parent) => {
        try {
            return await X509.verifyIssuedBy(X509.parse(derOf(child)), X509.parse(derOf(parent)));
        } catch (error) {
            return "threw: " + error.message;
        }
    };
    equal("the CA's signature on the leaf verifies", await issuedBy("verifier", "ca"), true);
    equal("another leaf under the same CA verifies too", await issuedBy("other", "ca"), true);
    equal("the expired leaf's signature is still the CA's (validity is a separate check)", await issuedBy("expired", "ca"), true);
    equal("the other.example leaf did not sign the verifier leaf", await issuedBy("verifier", "other"), false);
    equal("the impostor CA did not sign the leaf", await issuedBy("verifier", "impostor-ca"), false);
    equal("the intermediate is signed by the CA", await issuedBy("intermediate", "ca"), true);
    equal("the leaf under the intermediate is signed by it", await issuedBy("leaf-under-intermediate", "intermediate"), true);
    equal("the CA did not sign that leaf", await issuedBy("leaf-under-intermediate", "ca"), false);
    equal("the RSA chain verifies", await issuedBy("rsa-leaf", "rsa-ca"), true);
    equal("the P-384 chain verifies", await issuedBy("p384-leaf", "p384-ca"), true);
    equal("the P-521 chain verifies", await issuedBy("p521-leaf", "p521-ca"), true);
    equal("a self-signed certificate verifies with its own key", await issuedBy("self-signed", "self-signed"), true);
    equal("an ECDSA certificate against an RSA key is refused, not answered false",
        /ECDSA certificate is signed by a non-EC key/.test(String(await issuedBy("verifier", "rsa-ca"))), true);

    // validity, and the doubling the check allows for (RFC 5280 6.1.3 (a)(2))
    const stateAt = (name, when, skew) => X509.validityOf(X509.parse(derOf(name)), when, skew);
    equal("the leaf is valid at the harness's instant", stateAt("verifier", NOW, 5 * 60 * 1000), "valid");
    equal("the expired leaf is expired", stateAt("expired", NOW, 5 * 60 * 1000), "expired");
    equal("the future leaf is not valid yet", stateAt("future", NOW, 5 * 60 * 1000), "notYetValid");
    equal("five minutes of skew still accepts a leaf that ended a minute ago",
        stateAt("expired", new Date("2020-01-01T00:01:00Z"), 5 * 60 * 1000), "valid");
    equal("and without the skew it does not", stateAt("expired", new Date("2020-01-01T00:01:00Z"), 0), "expired");

    // the DER reader refuses what is not a certificate, and says why
    const parseRefuses = (label, bytes, fragment) => {
        let message = null;
        try {
            X509.parse(bytes);
        } catch (error) {
            message = error.message;
        }
        check(`${label}: refused`, message !== null && fragment.test(message), String(message));
    };
    parseRefuses("a DER SEQUENCE that is not a Certificate", DUMMY_DER, /three elements/);
    parseRefuses("a truncated certificate", derOf("verifier").subarray(0, 60), /DER|runs past the end/);
    parseRefuses("an indefinite length (BER, not DER)", Uint8Array.of(0x30, 0x80, 0x00, 0x00), /indefinite length is BER/);
    parseRefuses("a certificate whose outer tag is not a SEQUENCE", Uint8Array.of(0x04, 0x01, 0x00), /Certificate/);

    // an ECDSA signature in DER as the fixed-width r || s WebCrypto verifies (RFC 3279 2.2.3, RFC 7518 3.4)
    equal("the leaf's DER signature converts to 64 bytes on P-256", X509.derEcdsaToRaw(leaf.signatureValue, 32).length, 64);
    let wide = null;
    try {
        X509.derEcdsaToRaw(cat([0x30, 0x46, 0x02, 0x21], new Uint8Array(33).fill(0x7f), [0x02, 0x21], new Uint8Array(33).fill(0x7f)), 32);
    } catch (error) {
        wide = error.message;
    }
    check("a signature integer wider than its curve is refused", /wider than its curve/.test(String(wide)), String(wide));

    const fingerprint = await X509.fingerprintSha256(derOf("verifier"));
    equal("the fingerprint is 32 colon-separated uppercase hex pairs", /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(fingerprint), true);
    equal("and it is the DER's own SHA-256", fingerprint.replace(/:/g, ""),
        createHash("sha256").update(derOf("verifier")).digest("hex").toUpperCase());
});

await section("21. links: the schemes, the forms and the 8 KiB limit (plan 4.4)", async () => {
    const requestUri = "https://verifier.example/request.jwt/1";
    const query = "client_id=x509_san_dns:verifier.example&request_uri=" + encodeURIComponent(requestUri);
    for (const scheme of ["openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp"]) {
        const parsed = Oid4vp.parseLink(`${scheme}://?${query}`);
        equal(`${scheme}: the link is read as a request_uri request`, [parsed.ok, parsed.kind, parsed.scheme,
            parsed.params.requestUri, parsed.params.clientId],
            [true, "request_uri", scheme, requestUri, "x509_san_dns:verifier.example"]);
    }
    const invitation = Oid4vp.parseLink("https://paradym.id/invitation?request_uri=" + encodeURIComponent(requestUri));
    equal("an https invitation link is read, and it names no client_id", [invitation.ok, invitation.kind,
        invitation.params.clientId, invitation.scheme], [true, "request_uri", undefined, "https"]);
    const byValue = Oid4vp.parseLink("openid4vp://?client_id=x509_hash:" + leafHashOf("verifier") + "&request="
        + jar(withMembers({ client_id: "x509_hash:" + leafHashOf("verifier") })));
    equal("a link carrying the request object itself is read as by_value", [byValue.ok, byValue.kind, byValue.params.request.split(".").length],
        [true, "by_value", 3]);
    const pasted = Oid4vp.parseLink(jar(withMembers({})));
    equal("a request object pasted by itself is read as by_value with no scheme", [pasted.ok, pasted.kind, pasted.scheme],
        [true, "by_value", null]);
    equal("request_uri_method=post is accepted and get is the default",
        [Oid4vp.parseLink(`openid4vp://?${query}&request_uri_method=post`).params.requestUriMethod,
            Oid4vp.parseLink(`openid4vp://?${query}`).params.requestUriMethod], ["post", "get"]);
    const redirectClientId = "redirect_uri:https://verifier.example/response";
    const plainLink = Oid4vp.parseLink("openid4vp://?client_id=" + encodeURIComponent(redirectClientId)
        + "&response_uri=" + encodeURIComponent("https://verifier.example/response") + "&nonce=n1");
    equal("a redirect_uri: link's plain parameters are read as a plain request",
        [plainLink.ok, plainLink.kind, plainLink.params.plain.nonce], [true, "plain", "n1"]);
    const extra = Oid4vp.parseLink(`openid4vp://?${query}&flow=qr`);
    check("a link parameter this page does not read is a finding, not a refusal",
        extra.ok === true && extra.findings.some((finding) => finding.includes("\"flow\"")), JSON.stringify(extra.findings));

    const refusesLink = (label, text, fragment) => {
        const result = Oid4vp.parseLink(text);
        check(`${label}: refused`, result.ok === false && fragment.test(String(result.message)),
            result.ok ? "it was accepted" : result.message);
    };
    refusesLink("a link with neither request_uri nor request", "openid4vp://?client_id=x509_san_dns:verifier.example",
        /neither request_uri nor request/);
    refusesLink("a link carrying both request and request_uri",
        "openid4vp://?request=" + jar(withMembers({})) + "&request_uri=" + encodeURIComponent(requestUri),
        /both request and request_uri/);
    refusesLink("a link over 8 KiB", "openid4vp://?request_uri=" + encodeURIComponent("https://verifier.example/" + "a".repeat(9000)),
        /8 KiB limit/);
    refusesLink("a scheme that is not a wallet invocation scheme", "ftp://verifier.example/request",
        /not a wallet invocation scheme/);
    refusesLink("request_uri_method=put", `openid4vp://?${query}&request_uri_method=put`, /accepts get or post/);
    refusesLink("an empty field", "   ", /the field is empty/);
    refusesLink("neither a link nor a request object", "please present your licence", /neither a link nor a request object/);
});

await section("22. fetching the request object, once (plan 4.4)", async () => {
    const requestUri = "https://verifier.example/request.jwt/1";
    const relayUrl = "https://credentials.example/v1/certify/offer/wallet/relay";
    const text = jar(withMembers({}));

    const get = scriptedFetch({ [requestUri]: { status: 200, body: text, contentType: "application/oauth-authz-req+jwt" } });
    const fetched = new Set();
    const answer = await Oid4vp.fetchRequest({ requestUri, method: "get", pageUrl: PUBLIC_PAGE, relayHosts: [], relayUrl,
        fetched, fetchImpl: get.impl });
    equal("a 200 answer is read", [answer.ok, answer.text, answer.via], [true, text, "direct"]);
    equal("one GET, with the JWT Accept header and redirect: \"error\"",
        [get.calls.length, get.calls[0].method, get.calls[0].headers.Accept, get.calls[0].redirect, get.calls[0].body],
        [1, "GET", "application/oauth-authz-req+jwt", "error", undefined]);
    const again = await Oid4vp.fetchRequest({ requestUri, method: "get", pageUrl: PUBLIC_PAGE, relayHosts: [], relayUrl,
        fetched, fetchImpl: get.impl });
    equal("a second fetch of the same request_uri is refused and makes no request",
        [again.ok, again.state, get.calls.length], [false, "alreadyFetched", 1]);

    const nonce = "wallet-nonce-".padEnd(43, "x");
    const post = scriptedFetch({ [requestUri]: { status: 200, body: text, contentType: "application/oauth-authz-req+jwt" } });
    const posted = await Oid4vp.fetchRequest({ requestUri, method: "post", walletNonce: nonce, pageUrl: PUBLIC_PAGE,
        relayHosts: [], relayUrl, fetched: new Set(), fetchImpl: post.impl });
    const form = post.calls[0].body;
    equal("a posted request carries wallet_nonce and nothing else, form-encoded",
        [posted.ok, post.calls[0].method, post.calls[0].headers["Content-Type"],
            form instanceof URLSearchParams ? [...form.keys()] : "not a form", form.get("wallet_nonce")],
        [true, "POST", "application/x-www-form-urlencoded", ["wallet_nonce"], nonce]);
    equal("and it still asks for the JWT media type", post.calls[0].headers.Accept, "application/oauth-authz-req+jwt");

    for (const status of [404, 500]) {
        const failing = scriptedFetch({ [requestUri]: { status, body: "no" } });
        const refused = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: [], relayUrl,
            fetched: new Set(), fetchImpl: failing.impl });
        check(`a ${status} answer stops the process (VP 5.10.2)`,
            refused.ok === false && new RegExp("answered " + status).test(refused.message), refused.message);
    }
    const redirecting = scriptedFetch({ [requestUri]: "throw" });
    const redirected = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: [], relayUrl,
        fetched: new Set(), fetchImpl: redirecting.impl });
    equal("a redirect is an explicit unreachable state, never a fetch of where it points (redirect: \"error\")",
        [redirected.ok, redirected.state], [false, "unreachable"]);
    check("and the state says what to do about a verifier without CORS", /CORS/.test(redirected.message), redirected.message);

    const insecure = scriptedFetch({});
    equal("an http request_uri on an https page is refused before any request",
        [(await Oid4vp.fetchRequest({ requestUri: "http://verifier.example/r", pageUrl: PUBLIC_PAGE, relayHosts: [],
            relayUrl, fetched: new Set(), fetchImpl: insecure.impl })).ok, insecure.calls.length], [false, 0]);
    const local = scriptedFetch({ "http://localhost:8090/request.jwt": { status: 200, body: text, contentType: "application/jwt" } });
    equal("and it is allowed while the page itself is served from localhost",
        (await Oid4vp.fetchRequest({ requestUri: "http://localhost:8090/request.jwt", pageUrl: LOCAL_PAGE, relayHosts: [],
            relayUrl, fetched: new Set(), fetchImpl: local.impl })).ok, true);

    const relayed = scriptedFetch({ [relayUrl]: { status: 200, contentType: "application/json",
        body: JSON.stringify({ status: 200, content_type: "application/oauth-authz-req+jwt", body: text }) } });
    const viaRelay = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: ["verifier.example"],
        relayUrl, fetched: new Set(), fetchImpl: relayed.impl });
    equal("a listed host is read through the relay only, never directly",
        [viaRelay.ok, viaRelay.via, relayed.calls.length, relayed.calls[0].url], [true, "relay", 1, relayUrl]);
    equal("the relay request names the operation, the uri and the method, and carries no verifier header",
        [JSON.parse(relayed.calls[0].body), relayed.calls[0].headers.Accept],
        [{ op: "request-object", uri: requestUri, method: "get" }, "application/json"]);
    const relayedPost = scriptedFetch({ [relayUrl]: { status: 200, body: JSON.stringify({ status: 200, body: text }) } });
    await Oid4vp.fetchRequest({ requestUri, method: "post", walletNonce: nonce, pageUrl: PUBLIC_PAGE,
        relayHosts: ["verifier.example"], relayUrl, fetched: new Set(), fetchImpl: relayedPost.impl });
    equal("a posted request through the relay forwards wallet_nonce and nothing else",
        JSON.parse(relayedPost.calls[0].body), { op: "request-object", uri: requestUri, method: "post", wallet_nonce: nonce });
    const relayError = scriptedFetch({ [relayUrl]: { status: 200, body: JSON.stringify({ status: 400, body: "" }) } });
    const relayedRefusal = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: ["verifier.example"],
        relayUrl, fetched: new Set(), fetchImpl: relayError.impl });
    check("a verifier error reported through the relay stops the process",
        relayedRefusal.ok === false && /answered 400/.test(relayedRefusal.message), relayedRefusal.message);
    const relayDown = scriptedFetch({ [relayUrl]: { status: 502, body: "no" } });
    const relayedDown = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: ["verifier.example"],
        relayUrl, fetched: new Set(), fetchImpl: relayDown.impl });
    check("a relay that answers an error is refused", relayedDown.ok === false && /relay answered 502/.test(relayedDown.message),
        relayedDown.message);

    const oversized = scriptedFetch({ [requestUri]: { status: 200, body: "a".repeat(64 * 1024 + 1) } });
    const tooLarge = await Oid4vp.fetchRequest({ requestUri, pageUrl: PUBLIC_PAGE, relayHosts: [], relayUrl,
        fetched: new Set(), fetchImpl: oversized.impl });
    check("a request object over 64 KiB is refused after it is read", tooLarge.ok === false && /64 KiB limit/.test(tooLarge.message),
        tooLarge.message);
});

await section("23. the request checks R1-R11 and the findings (plan 4.5)", async () => {
    const good = await checkRequestOf(jar(withMembers({})));
    equal("the control request passes every check", [good.ok, good.error, good.card.chainLength], [true, null, 1]);
    equal("its card names the client_id and the leaf's subject and issuer",
        [good.card.clientId, good.card.subject.map((a) => a.short).join(","), good.card.issuer.map((a) => a.short).join(",")],
        ["x509_san_dns:verifier.example", "C,O,CN", "C,O,CN"]);
    check("its card carries the leaf's and the topmost certificate's SHA-256",
        good.card.fingerprints.leaf === await X509.fingerprintSha256(derOf("verifier"))
            && good.card.fingerprints.top === good.card.fingerprints.leaf, JSON.stringify(good.card.fingerprints));
    equal("the card shows the response_uri's host", good.card.responseUriHost, "verifier.example");
    equal("a request with aud and state raises no finding about them",
        good.findings.filter((finding) => /no aud|no state/.test(finding)), []);

    // R1 and the limits of plan 4.4
    refusesWith("a request object of 64 KiB + 1", await checkRequestOf("a".repeat(64 * 1024 + 1)), "R1", /64 KiB limit/);
    refusesWith("a request object that is not three parts", await checkRequestOf("only.two"), "R1", /not a compact JWS of three parts/);
    refusesWith("a request object whose payload is not JSON", await checkRequestOf("eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0In0.bm90IGpzb24.sig"),
        "R1", /not base64url JSON/);
    refusesWith("a 6-certificate x5c", await checkRequestOf(jar(withMembers({}), { x5c: new Array(6).fill(x5cOf("verifier")) })),
        "R1", /6 certificates, over the limit of 5/);
    refusesWith("a DCQL query with 21 credential queries",
        await checkRequestOf(jar(withMembers({ dcql_query: { credentials: Array.from({ length: 21 }, (_, index) =>
            ({ id: "q" + index, format: "mso_mdoc", meta: { doctype_value: DOC_TYPE } })) } }))),
        "R1", /21 credential queries, over the limit of 20/);
    refusesWith("a credential query with 101 claims",
        await checkRequestOf(jar(withMembers({ dcql_query: { credentials: [{ id: "q1", format: "mso_mdoc",
            meta: { doctype_value: DOC_TYPE }, claims: new Array(101).fill({ path: [MDL_NAMESPACE, "family_name"] }) }] } }))),
        "R1", /101 claims, over the limit of 100/);
    let deep = {};
    for (let level = 0, cursor = deep; level < 20; level++) { cursor.next = {}; cursor = cursor.next; }
    refusesWith("a request object nested more than 16 levels", await checkRequestOf(jar(withMembers({ extension: deep }))),
        "R1", /over the limit of 16/);

    // R2: the JWS type VP section 5 requires
    refusesWith("a request object with no typ", await checkRequestOf(jar(withMembers({}), { header: { typ: undefined } })),
        "R2", /typ is absent/);
    refusesWith("typ JWT", await checkRequestOf(jar(withMembers({}), { header: { typ: "JWT" } })), "R2", /"JWT"/);

    // R3 and R4: the link's and the object's client_id, and the echoed wallet_nonce (VP 5.10.1)
    refusesWith("a link whose client_id differs from the request object's",
        await checkRequestOf(jar(withMembers({})), { link: linkParams({ clientId: "x509_san_dns:other.example" }) }),
        "R3", /must be identical/);
    refusesWith("wallet_nonce missing in the request object",
        await checkRequestOf(jar(withMembers({})), { link: linkParams({ walletNonce: "sent-by-the-wallet" }) }),
        "R4", /carries none/);
    refusesWith("wallet_nonce different in the request object",
        await checkRequestOf(jar(withMembers({ wallet_nonce: "another" })), { link: linkParams({ walletNonce: "sent-by-the-wallet" }) }),
        "R4", /carries "another"/);
    equal("the echoed wallet_nonce is accepted",
        (await checkRequestOf(jar(withMembers({ wallet_nonce: "sent-by-the-wallet" })),
            { link: linkParams({ walletNonce: "sent-by-the-wallet" }) })).ok, true);

    // R5: the audience and the object's own lifetime (VP 5.8, RFC 9101 10.2)
    refusesWith("aud https://other.example", await checkRequestOf(jar(withMembers({ aud: "https://other.example" }))),
        "R5", /static discovery/);
    refusesWith("exp in the past", await checkRequestOf(jar(withMembers({ exp: Math.floor(NOW.getTime() / 1000) - 1 }))),
        "R5", /expired at/);
    refusesWith("iat more than five minutes ahead",
        await checkRequestOf(jar(withMembers({ iat: Math.floor(NOW.getTime() / 1000) + 301 }))), "R5", /more than 5 minutes ahead/);
    equal("iat 299 seconds ahead is accepted, inside the five-minute skew",
        (await checkRequestOf(jar(withMembers({ iat: Math.floor(NOW.getTime() / 1000) + 299 })))).ok, true);
    const noAud = await checkRequestOf(jar(withMembers({ aud: undefined })));
    check("no aud is a finding, not a refusal (Multipaz sends none)",
        noAud.ok === true && noAud.findings.some((finding) => finding.startsWith("no aud")), JSON.stringify(noAud.findings));
    const noState = await checkRequestOf(jar(withMembers({ state: undefined })));
    check("no state is a finding", noState.ok === true && noState.findings.some((finding) => finding.startsWith("no state")),
        JSON.stringify(noState.findings));

    // R6 and R7: the client identifier bound to the certificate, and the JWS signed with its key (VP 5.9.3)
    refusesWith("x509_san_dns:verifier.example signed by the other.example leaf",
        await checkRequestOf(jar(withMembers({}), { keyName: "other" })), "R6",
        /dNSName subject alternative names are \[other.example\]/);
    refusesWith("a tampered JAR signature under x509_san_dns", await checkRequestOf(jar(withMembers({}), { tamper: true })),
        "R6", /does not verify with the leaf certificate's public key/);
    refusesWith("x509_san_dns with no x5c", await checkRequestOf(jar(withMembers({}), { x5c: null })), "R6", /carries no x5c/);
    refusesWith("an x509_san_dns value that is not a DNS name",
        await checkRequestOf(jar(withMembers({ client_id: "x509_san_dns:not a name" })),
            { link: linkParams({ clientId: "x509_san_dns:not a name" }) }), "R6", /is not a DNS name/);
    const otherHash = "x509_hash:" + leafHashOf("other");
    refusesWith("x509_hash of another certificate",
        await checkRequestOf(jar(withMembers({ client_id: otherHash })), { link: linkParams({ clientId: otherHash }) }),
        "R7", /the SHA-256 of the leaf certificate in x5c is/);
    const verifierHash = "x509_hash:" + leafHashOf("verifier");
    refusesWith("a tampered JAR signature under x509_hash",
        await checkRequestOf(jar(withMembers({ client_id: verifierHash }), { tamper: true }),
            { link: linkParams({ clientId: verifierHash }) }), "R7", /does not verify/);
    refusesWith("an x509_hash value that is not 43 characters",
        await checkRequestOf(jar(withMembers({ client_id: "x509_hash:short" })), { link: linkParams({ clientId: "x509_hash:short" }) }),
        "R7", /not the 43-character base64url SHA-256/);

    // R9: the prefixes this wallet refuses (VP 5.9.3, D-P5-03-9)
    for (const [label, clientId, fragment] of [
        ["the origin: prefix", "origin:https://verifier.example", /MUST NOT accept it/],
        ["a signed redirect_uri: request", "redirect_uri:https://verifier.example/response", /cannot be used with a signed request/],
        ["the decentralized_identifier: prefix", "decentralized_identifier:did:web:verifier.example", /not supported by this demo wallet/],
        ["the verifier_attestation: prefix", "verifier_attestation:abc", /not supported by this demo wallet/],
        ["the openid_federation: prefix", "openid_federation:https://verifier.example", /not supported by this demo wallet/],
        ["a pre-registered client_id (no prefix)", "demo-verifier", /pre-registered/],
    ]) {
        refusesWith(label, await checkRequestOf(jar(withMembers({ client_id: clientId })), { link: linkParams({ clientId }) }),
            "R9", fragment);
    }

    // R10: the algorithm, and the chain
    refusesWith("alg: none", await checkRequestOf(jar(withMembers({}), { header: { alg: "none" }, sign: false })),
        "R10", /alg: none is not a signature/);
    refusesWith("alg: ES256K", await checkRequestOf(jar(withMembers({}), { header: { alg: "ES256K" } })), "R10", /verifies ES256/);
    refusesWith("an empty third part under a valid alg", await checkRequestOf(jar(withMembers({}), { sign: false })),
        "R1", /third part is empty/);
    refusesWith("an expired leaf", await checkRequestOf(jar(withMembers({}),
        { keyName: "expired", x5c: [x5cOf("expired"), x5cOf("ca")] })), "R10", /is expired/);
    refusesWith("a leaf that is not valid yet", await checkRequestOf(jar(withMembers({}),
        { keyName: "future", x5c: [x5cOf("future"), x5cOf("ca")] })), "R10", /not valid yet/);
    refusesWith("a chain whose second certificate has the issuer's name and not its key",
        await checkRequestOf(jar(withMembers({}), { x5c: [x5cOf("verifier"), x5cOf("ca-twin")] })), "R10",
        /is not signed by certificate 1/);
    refusesWith("a chain whose second certificate is another CA",
        await checkRequestOf(jar(withMembers({}), { keyName: "leaf-under-intermediate",
            x5c: [x5cOf("leaf-under-intermediate"), x5cOf("ca")] })), "R10", /does not link/);
    refusesWith("a certificate that does not parse",
        await checkRequestOf(jar(withMembers({}), { x5c: [Buffer.from("not a certificate").toString("base64")] })),
        "R10", /does not parse as an X.509 certificate/);
    refusesWith("an x5c entry encoded as base64url",
        await checkRequestOf(jar(withMembers({}), { x5c: ["AAAA-_AA"] })), "R10", /requires base64, not base64url/);
    const chain3 = await checkRequestOf(jar(withMembers({}),
        { keyName: "leaf-under-intermediate", x5c: [x5cOf("leaf-under-intermediate"), x5cOf("intermediate"), x5cOf("ca")] }));
    equal("a three-certificate chain that links is accepted", [chain3.ok, chain3.card.chainLength], [true, 3]);
    equal("its card shows the topmost certificate's fingerprint, which is the CA's",
        chain3.card.fingerprints.top, await X509.fingerprintSha256(derOf("ca")));
    for (const [label, alg, keyName] of [["ES384", "ES384", "p384-leaf"], ["ES512", "ES512", "p521-leaf"],
        ["RS256", "RS256", "rsa-leaf"], ["PS256", "PS256", "rsa-leaf"]]) {
        const signed = await checkRequestOf(jar(withMembers({}), { alg, keyName }));
        equal(`a JAR signed with ${label} verifies with its chain`, signed.ok, true);
    }
    const selfSigned = await checkRequestOf(jar(withMembers({}), { keyName: "self-signed" }));
    check("a self-signed leaf is a finding, not a refusal (HAIP 1.0 section 5)",
        selfSigned.ok === true && selfSigned.findings.some((finding) => finding.includes("is self-signed")),
        JSON.stringify(selfSigned.findings));
    check("and the card labels the chain as one certificate", selfSigned.card.chainLength === 1);

    // R8: the response_uri and the host its prefix permits (VP 5.9.3, 8.2)
    refusesWith("response_uri on other.example under x509_san_dns:verifier.example",
        await checkRequestOf(jar(withMembers({ response_uri: "https://other.example/response" }))),
        "R8", /response_uri is on other.example/);
    refusesWith("response_uri over http on an https page",
        await checkRequestOf(jar(withMembers({ response_uri: "http://verifier.example/response" }))),
        "R8", /http is allowed only while this page is served from localhost/);
    equal("the same response_uri is accepted while the page is served from localhost",
        (await checkRequestOf(jar(withMembers({ response_uri: "http://verifier.example/response" })), { pageUrl: LOCAL_PAGE })).ok,
        true);
    refusesWith("a request object with no response_uri", await checkRequestOf(jar(withMembers({ response_uri: undefined }))),
        "R8", /carries no response_uri/);

    // R11: the response type and mode this wallet implements (VP 5.6, 8.2)
    refusesWith("response_type=id_token", await checkRequestOf(jar(withMembers({ response_type: "id_token" }))),
        "R11", /section 5.6 has vp_token/);
    refusesWith("response_mode=query", await checkRequestOf(jar(withMembers({ response_mode: "query" }))),
        "R11", /implements direct_post and direct_post.jwt/);

    // the findings of plan 4.5: shown, never blocking
    const haipPlain = await checkRequestOf(jar(withMembers({ response_mode: "direct_post" })), { link: linkParams({ scheme: "haip-vp" }) });
    check("a haip-vp link whose request is not direct_post.jwt is a finding",
        haipPlain.ok === true && haipPlain.findings.some((finding) => finding.startsWith("a haip-vp link")),
        JSON.stringify(haipPlain.findings));
    const mediaType = await checkRequestOf(jar(withMembers({})), { contentType: "application/json" });
    check("a request object served as application/json is a finding",
        mediaType.ok === true && mediaType.findings.some((finding) => finding.includes("media type")),
        JSON.stringify(mediaType.findings));
    const algValues = await checkRequestOf(jar(withMembers({ client_metadata: { vp_formats_supported:
        { mso_mdoc: { issuerauth_alg_values: [-9] } } } })), { keptIssuerAuthAlgs: [-7] });
    check("issuerauth_alg_values that do not list the held credential's algorithm is a finding",
        algValues.ok === true && algValues.findings.some((finding) => finding.includes("issuerauth_alg_values")),
        JSON.stringify(algValues.findings));
    const requestHost = await checkRequestOf(jar(withMembers({})), { link: linkParams({ requestUri: "https://elsewhere.example/r" }) });
    check("a request_uri on a host that is not the client's DNS name is a finding (VP 15.8.1)",
        requestHost.ok === true && requestHost.findings.some((finding) => finding.startsWith("the request_uri is on")),
        JSON.stringify(requestHost.findings));
    const unknown = await checkRequestOf(jar(withMembers({ presentation_definition: { id: "x" } })));
    check("a request parameter this page does not read is a finding",
        unknown.ok === true && unknown.findings.some((finding) => finding.includes("presentation_definition")),
        JSON.stringify(unknown.findings));
    const missingClientId = await checkRequestOf(jar(withMembers({})), { link: linkParams({ clientId: undefined }) });
    check("a link that named no client_id says so in the findings, and the object's is used",
        missingClientId.ok === true && missingClientId.request.clientId === "x509_san_dns:verifier.example"
            && missingClientId.findings.some((finding) => finding.includes("named no client_id")),
        JSON.stringify(missingClientId.findings));

    // a redirect_uri: request, which cannot be signed, through the plain path
    const redirectClientId = "redirect_uri:https://verifier.example/response";
    const plain = await Oid4vp.checkRequest({
        plain: { client_id: redirectClientId, response_uri: "https://verifier.example/response", nonce: "n1", state: "s1",
            response_mode: "direct_post", dcql_query: { credentials: [] } },
        link: linkParams({ clientId: redirectClientId, kind: "plain" }),
        pageUrl: PUBLIC_PAGE,
        now: NOW,
    });
    equal("a redirect_uri: request's plain parameters are accepted, unsigned", [plain.ok, plain.request.signed], [true, false]);
    check("and the findings say the request is unsigned", plain.findings.some((finding) => finding.includes("unsigned")),
        JSON.stringify(plain.findings));
    const plainElsewhere = await Oid4vp.checkRequest({
        plain: { client_id: redirectClientId, response_uri: "https://other.example/response", nonce: "n1" },
        link: linkParams({ clientId: redirectClientId, kind: "plain" }), pageUrl: PUBLIC_PAGE, now: NOW,
    });
    refusesWith("a redirect_uri: request whose response_uri is not the client_id", plainElsewhere, "R8", /they must be the same URI/);
});

await section("24. the four error cases, and the button that sends one (plan 4.5, VP 8.5)", async () => {
    const cases = [
        ["no nonce", withMembers({ nonce: undefined }), "invalid_request", /no nonce/],
        ["redirect_uri with direct_post.jwt", withMembers({ redirect_uri: "https://verifier.example/done" }), "invalid_request",
            /redirect_uri together with direct_post.jwt/],
        ["no dcql_query", withMembers({ dcql_query: undefined }), "invalid_request", /carries no dcql_query/],
        ["only a scope", withMembers({ dcql_query: undefined, scope: "org.iso.18013.5.1.mDL" }), "invalid_scope", /only the scope/],
        ["transaction_data", withMembers({ transaction_data: ["a"] }), "invalid_transaction_data", /does not process transaction_data/],
    ];
    for (const [label, members, error, fragment] of cases) {
        const checked = await checkRequestOf(jar(members));
        check(`${label}: the checks pass and the wallet owes an error response`,
            checked.ok === true && checked.error !== null && checked.error.error === error, JSON.stringify(checked.error));
        check(`${label}: the error names the reason`,
            checked.ok === true && fragment.test(checked.error.description), checked.ok ? JSON.stringify(checked.error) : checked.message);
    }

    // and on the page, once per case: the error block with its button, and the form the press sends
    for (const [label, members, error] of cases) {
        const wallet = openWallet(new FakeIndexedDB(), {
            clock: NOW,
            respond: (request) => (request.method === "POST" ? { status: 200, body: "{}" } : undefined),
        });
        check(`${label}: the wallet page's scripts ran`, wallet.scriptError === null,
            wallet.scriptError && String(wallet.scriptError.stack));
        const answered = (request) => request.method === "POST" && request.url === "https://verifier.example/response";
        await waitFor(() => wallet.el("readRequest").disabled === false);
        wallet.el("requestText").value = jar(members);
        await wallet.el("readRequest").fire("click");
        await waitFor(() => wallet.el("verifierCard").hidden === false);
        equal(`${label}: the card is shown, with the error beside it`,
            [wallet.el("verifierCard").hidden, wallet.el("requestError").hidden], [false, false]);
        equal(`${label}: the error block names the error`,
            wallet.el("errorSummary").textContent.startsWith(error + ": "), true);
        equal(`${label}: nothing has been sent to response_uri before the press`, wallet.requests.filter(answered).length, 0);
        await wallet.el("sendError").fire("click");
        const sent = wallet.requests.filter(answered);
        equal(`${label}: the press sends exactly one POST to response_uri`, sent.length, 1);
        equal(`${label}: it carries error, error_description and state as a form`,
            [sent[0].headers["Content-Type"], sent[0].body.get("error"),
                sent[0].body.get("error_description").length > 0, sent[0].body.get("state")],
            ["application/x-www-form-urlencoded", error, true, "state-p503c"]);
        check(`${label}: and the page reports the verifier's answer`, /answered 200/.test(wallet.el("errorStatus").textContent),
            wallet.el("errorStatus").textContent);
        await wallet.el("sendError").fire("click");
        equal(`${label}: a second press sends nothing`, wallet.requests.filter(answered).length, 1);
    }
});

await section("25. the hosted request objects' shapes (plan 4.12)", async () => {
    const eudiText = readFileSync(resolve(HOSTED_DIR, "eudi.request.jwt"), "utf8").trim();
    check("the EUDI-shaped request object is about 23 KB, as EUDI's is", eudiText.length > 20000 && eudiText.length < 30000,
        String(eudiText.length));
    const eudiHash = "x509_hash:" + leafHashOf("verifier");
    const eudi = await checkRequestOf(eudiText, { link: linkParams({ clientId: eudiHash }) });
    equal("it passes R1-R11 under the pinned clock", [eudi.ok, eudi.error], [true, null]);
    equal("its card shows the leaf's subject, issuer and fingerprint",
        [eudi.card.subject.map((a) => a.short + "=" + a.value).join(", "), eudi.card.fingerprints.leaf],
        ["C=IN, O=Inji Demo Certify, CN=Wallet Fixture Verifier", await X509.fingerprintSha256(derOf("verifier"))]);
    equal("it raises no finding about aud or state", eudi.findings.filter((finding) => /no aud|no state/.test(finding)), []);
    equal("its card names the client_name the verifier gives itself", eudi.card.clientName, "EUDI Reference Verifier (fixture)");
    check("its verifier_info registration certificate is shown, labelled unverified",
        eudi.card.verifierInfo !== null && eudi.card.verifierInfo[0].type === "registration_cert"
            && eudi.card.verifierInfo[0].text.length > 100, JSON.stringify(eudi.card.verifierInfo && eudi.card.verifierInfo[0] && eudi.card.verifierInfo[0].text.slice(0, 40)));
    equal("the request object is 23 KB without the page fetching anything else", eudi.request.responseMode, "direct_post.jwt");

    const multipazText = readFileSync(resolve(HOSTED_DIR, "multipaz.request.jwt"), "utf8").trim();
    const multipaz = await checkRequestOf(multipazText, { link: linkParams({ clientId: "x509_san_dns:verifier.example" }) });
    equal("the Multipaz-shaped request object passes R1-R11 under the pinned clock", [multipaz.ok, multipaz.error], [true, null]);
    check("it raises the findings plan 2.1 records: no aud and no state",
        multipaz.ok && multipaz.findings.some((finding) => finding.startsWith("no aud"))
            && multipaz.findings.some((finding) => finding.startsWith("no state")), JSON.stringify(multipaz.findings));
    equal("its client_id is the x509_san_dns prefix Multipaz sends", multipaz.request.prefix, "x509_san_dns");
    equal("its response_uri is on the client's DNS name", multipaz.card.responseUriHost, "verifier.example");
    const stale = await checkRequestOf(multipazText, { link: linkParams({ clientId: "x509_san_dns:verifier.example" }),
        now: new Date("2027-06-01T00:00:00Z") });
    refusesWith("the same Multipaz-shaped object a year later", stale, "R5", /expired at/);
});

await section("26. an x5chain only in the protected header is refused (ISO 18013-5 9.1.2.4)", async () => {
    // the protected header carries alg and the chain; the unprotected one is empty, so only one bucket has label 33
    const inProtected = shapedMdl({ protectedRaw: cat(head(5, 2), head(0, 1), head(1, 6), head(0, 33), bstr(DUMMY_DER)),
        unprotectedRaw: () => head(5, 0) });
    equal("readIssuerSigned still reads it from either bucket, and records which one it was (P5-03a's deferral)",
        [Mdoc.readIssuerSigned(inProtected.bytes).issuerAuth.x5chainHeader,
            Mdoc.readIssuerSigned(inProtected.bytes).issuerAuth.x5chain.length], ["protected", 1]);
    let refused = null;
    try {
        Mdoc.issuerChain(inProtected.bytes);
    } catch (error) {
        refused = error.message;
    }
    check("issuerChain refuses that placement, naming the clause",
        refused !== null && /unprotected header/.test(refused) && /9\.1\.2\.4/.test(refused), String(refused));
    check("the refusal is about the header, before any certificate is read (the bytes are not a certificate at all)",
        refused !== null && !/DER|runs past|parse/.test(refused), String(refused));
    const inUnprotected = shapedMdl({});
    equal("an unprotected x5chain is returned as the DER it carries",
        Mdoc.issuerChain(inUnprotected.bytes).map(hex), [hex(DUMMY_DER)]);
    equal("and the recorded bucket is the unprotected one",
        Mdoc.readIssuerSigned(inUnprotected.bytes).issuerAuth.x5chainHeader, "unprotected");
    const recorded = readFileSync(resolve(FIXTURES, "mdl-a.issuersigned"));
    equal("Certify's own IssuerSigned puts its chain in the unprotected header, and issuerChain returns it",
        [Mdoc.readIssuerSigned(recorded).issuerAuth.x5chainHeader, Mdoc.issuerChain(recorded).length], ["unprotected", 1]);
});

await section("27. the wallet page takes a request in (plan 4.4, I9)", async () => {
    const requestUri = "https://verifier.example/request.jwt/1";
    const text = jar(withMembers({}));
    const sameDevice = "https://credentials.example/v1/certify/offer/wallet?client_id=x509_san_dns:verifier.example&request_uri="
        + encodeURIComponent(requestUri);
    const wallet = openWallet(new FakeIndexedDB(), {
        clock: NOW,
        pageUrl: sameDevice,
        respond: (request) => (request.url === requestUri
            ? { status: 200, body: text, contentType: "application/oauth-authz-req+jwt" } : undefined),
    });
    check("the wallet page's scripts ran", wallet.scriptError === null, wallet.scriptError && String(wallet.scriptError.stack));
    const read = await waitFor(() => wallet.el("verifierCard").hidden === false);
    check("a same-device invocation is read on load and its card is shown", read, wallet.el("intakeStatus").textContent);
    equal("the page fetched the request object exactly once", wallet.requests.filter((request) => request.url === requestUri).length, 1);
    equal("the address bar was replaced with the bare wallet URL, so a reload cannot fetch again",
        wallet.replacedUrls, ["/v1/certify/offer/wallet"]);
    equal("nothing was sent to response_uri", wallet.requests.filter((request) => request.url === "https://verifier.example/response").length, 0);
    check("the card says there is no trust list (plan section 6, deviation 1)",
        /No trusted list/.test(wallet.el("noTrustList").textContent), wallet.el("noTrustList").textContent);
    equal("the card's table carries the client_id and both names",
        [wallet.el("verifierTable").textContent.includes("x509_san_dns:verifier.example"),
            wallet.el("verifierTable").textContent.includes("Wallet Fixture Verifier"),
            wallet.el("verifierTable").textContent.includes("Wallet Fixture Verifier CA")], [true, true, true]);

    const before = wallet.requests.length;
    wallet.el("requestText").value = "openid4vp://?client_id=x509_san_dns:verifier.example&request_uri="
        + encodeURIComponent(requestUri);
    await wallet.el("readRequest").fire("click");
    check("a second read of the same request_uri says it was already fetched",
        /already fetched/.test(wallet.el("intakeStatus").textContent), wallet.el("intakeStatus").textContent);
    equal("and nothing is requested", wallet.requests.length - before, 0);

    const fragmentUri = "https://verifier.example/request.jwt/2";
    const fromFragment = openWallet(new FakeIndexedDB(), {
        clock: NOW,
        pageUrl: "https://credentials.example/v1/certify/offer/wallet#://?client_id=x509_san_dns:verifier.example&request_uri="
            + encodeURIComponent(fragmentUri),
        respond: (request) => (request.url === fragmentUri
            ? { status: 200, body: text, contentType: "application/oauth-authz-req+jwt" } : undefined),
    });
    const fragmentRead = await waitFor(() => fromFragment.el("verifierCard").hidden === false);
    check("the `#://?…` form Multipaz produces is read the same way", fragmentRead, fromFragment.el("intakeStatus").textContent);
    equal("and its fragment is taken out of the address bar too", fromFragment.replacedUrls, ["/v1/certify/offer/wallet"]);

    const pasted = openWallet(new FakeIndexedDB(), { clock: NOW });
    await waitFor(() => pasted.el("readRequest").disabled === false);
    pasted.el("requestText").value = jar(withMembers({ client_id: "x509_hash:" + leafHashOf("verifier") }));
    await pasted.el("readRequest").fire("click");
    check("a pasted request object goes through the same checks",
        pasted.el("verifierCard").hidden === false && /x509_hash/.test(pasted.el("verifierTable").textContent),
        pasted.el("intakeStatus").textContent);
    equal("and it makes no request at all", pasted.requests.filter((request) => request.url.startsWith("https://verifier.example")).length, 0);
    pasted.el("requestText").value = jar(withMembers({}), { tamper: true });
    await pasted.el("readRequest").fire("click");
    check("a tampered request object is refused on the page, naming R6", /^R6: /.test(pasted.el("intakeStatus").textContent),
        pasted.el("intakeStatus").textContent);
    equal("and the card is hidden again", pasted.el("verifierCard").hidden, true);
    pasted.el("requestText").value = "present your licence";
    await pasted.el("readRequest").fire("click");
    check("a field that is neither a link nor a request object says so", /neither a link nor a request object/.test(pasted.el("intakeStatus").textContent),
        pasted.el("intakeStatus").textContent);

    const plain = openWallet(new FakeIndexedDB(), { clock: NOW });
    await waitFor(() => plain.el("readRequest").disabled === false);
    plain.el("requestText").value = "openid4vp://?client_id=" + encodeURIComponent("redirect_uri:https://verifier.example/response")
        + "&response_uri=" + encodeURIComponent("https://verifier.example/response") + "&nonce=n1&state=s1&dcql_query="
        + encodeURIComponent(JSON.stringify({ credentials: [] }));
    await plain.el("readRequest").fire("click");
    check("a redirect_uri: link's plain parameters reach a card with no certificate",
        plain.el("verifierCard").hidden === false
            && plain.el("verifierTable").textContent.includes("none: this request is not signed"),
        plain.el("intakeStatus").textContent);
    equal("and it is not treated as an error case", plain.el("requestError").hidden, true);

    const off = openWallet(new FakeIndexedDB(), {
        clock: NOW,
        walletConfig: false,
        pageUrl: sameDevice,
    });
    await waitFor(() => off.el("storageStatus").textContent.includes("switched off"));
    equal("with the wallet switched off (I4) the page reads no request at all",
        off.requests.filter((request) => request.url !== "https://credentials.example/v1/certify/offer/wallet/config").length, 0);
    check("and it says so", off.el("storageStatus").textContent.includes("switched off"), off.el("storageStatus").textContent);
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
}

export { storageConformance, walletDeleteScenarios };
