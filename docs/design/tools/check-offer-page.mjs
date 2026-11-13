#!/usr/bin/env node
/*
 * Behaviour check of the credential offer page's demo-subject wiring (F-15), and of the page's own behaviour around it:
 * the REAL `certify-service/src/main/resources/static/offer/index.html` is loaded, its inline script evaluated in a
 * throwaway VM with a minimal fake DOM, a stub `fetch` and a stub `QRCode`, and the page is driven the way a visitor
 * drives it (choose a configuration, choose a subject, press "Create offer", let the page be the wallet).
 *
 * Plain Node (20 or later, the version CI pins), no npm dependencies, no browser, no server:
 * `node docs/design/tools/check-offer-page.mjs`. One line per check, then
 * `check-offer-page: all N checks passed`; a non-zero exit when anything fails.
 *
 * Why it exists: round 1 of the F-15 review found that the JUnit page tests asserted source strings, which stayed green
 * while two real defects shipped (a `[hidden]` attribute that the page's own `label { display: block }` overrode, so a
 * stray subject label was always visible; and an "Other" sentinel value that a configured subject id could collide
 * with). Those two checks below are the regression tests for exactly those defects.
 *
 * Faithfulness (F-18). Round 2 of the F-15 review found the harness could pass where a real browser fails, so the fake
 * DOM now answers the way a browser does wherever the page depends on it (the page itself gains the F-18 spec fixes to
 * its wallet and prints a subject label once when it repeats the id):
 *   - `getElementById` returns null for an id the markup does not declare (it never invents an element), an id comes
 *     from an attribute whose name is exactly `id` (a `data-id` is not one), comments and raw-text content are not
 *     markup, and the first element with an id wins, so a page that looks up a missing id fails here as it throws in a
 *     browser;
 *   - a `<select>` tracks per-option selectedness and derives `value`/`selectedIndex` from it: a value no `<option>`
 *     carries reads back "" with `selectedIndex` -1, removing the selected option selects the first remaining one, a
 *     re-appended option marked selected takes the selection back, and an option without a `value` reads its text with
 *     whitespace collapsed;
 *   - `appendChild` moves a node out of its previous parent, `innerHTML = ""` clears the text as well as the children,
 *     and a disabled control dispatches no click;
 *   - the `QRCode` stub draws a child into the container it is handed, so the published QR can be located and a
 *     replaced one is seen to leave nothing behind;
 *   - the page's own wallet runs for real against the documents the live stack serves (issuer metadata and RFC 8414
 *     authorization server metadata at their well-known locations, the endpoints they name): Node's WebCrypto signs a
 *     P-256 proof, this file verifies that signature with an independent key check, and the token form, the
 *     transaction code, `authorization_details`, the nonce and the credential request are all asserted.
 *
 * `OFFER_PAGE_HTML=<path>` evaluates another copy of the page. It exists for negative controls (break a copy in /tmp
 * and watch this file fail); a broken copy is never committed.
 *
 * What this harness CANNOT check:
 *   - computed CSS and layout. The `[hidden]` check below is a static assertion over the stylesheet's text, not a
 *     rendered cascade, so a later rule, a specificity question, a media query or anything geometric (positions, sizes,
 *     overflow, z-index, scroll) is out of reach; so is whether the page looks right;
 *   - real QR rendering or scanning, image decoding, `Blob` URLs and portrait rendering (the `Cbor` stub is a stub);
 *   - CSP, CORS, cookies, TLS, real network timing, retries, and the clipboard;
 *   - focus, keyboard, tab order, pointer and drag-and-drop behaviour, form submission, and navigation;
 *   - anything about the issuer: every `fetch` answer is a fixture, so server behaviour (status codes, bodies, headers)
 *     is only as faithful as the fixtures below (their shapes are the ones the live stack serves, read from
 *     `docs/design/tools/smoke_mdl.py` and the server's metadata builders).
 */
import { createPublicKey, verify, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PAGE = process.env.OFFER_PAGE_HTML
    ? resolve(process.env.OFFER_PAGE_HTML)
    : resolve(REPO, "certify-service/src/main/resources/static/offer/index.html");
const html = readFileSync(PAGE, "utf8");

const SUBJECT_LABEL = "Subject (the record id the data provider resolves, e.g. the CSV row id)";
const CLAIMS_LABEL = "Or claims as JSON (used when the subject is empty)";
const CLAIMS_LABEL_WITH_CHOICE = "Or claims as JSON (used when \"Other\" is chosen and the subject is left empty)";

let checks = 0;
let failures = 0;

function check(name, ok, detail) {
    checks++;
    if (ok) {
        console.log(`ok    ${name}`);
    } else {
        failures++;
        console.log(`FAIL  ${name}${detail === undefined ? "" : " — " + detail}`);
    }
}

function equal(name, actual, expected) {
    const same = JSON.stringify(actual) === JSON.stringify(expected);
    check(name, same, same ? undefined : `got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}`);
}

/** Compares two flat objects by their members, not by the order the page happened to write them in. */
function equalFields(name, actual, expected) {
    const members = (value) => JSON.stringify(Object.keys(value || {}).sort().map((key) => [key, value[key]]));
    const same = actual !== undefined && members(actual) === members(expected);
    check(name, same, same ? undefined : `got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}`);
}

/* ---------------------------------------------------------------- fake DOM */

class Element {
    constructor(tag) {
        this.tagName = tag;
        this.children = [];
        this.parent = null;
        this.listeners = new Map();
        this._value = undefined;
        this._text = "";
        this.selected = false;
        this.hidden = false;
        this.disabled = false;
        this.checked = false;
        this.className = "";
        this.style = {};
        this.href = "";
        this.alt = "";
        this.src = "";
        this.innerHTMLWrites = [];
    }

    get isSelect() {
        return this.tagName === "select";
    }

    // a browser's textContent is the element's text and nothing else: setting it drops the children (the page clears
    // the subject dropdown's options this way, so a fake that kept them would hide the re-filter it performs)
    get textContent() {
        return this._text;
    }

    set textContent(text) {
        this._text = String(text);
        this.clearChildren();
    }

    /** The selected option of a select, or null: a browser derives value and selectedIndex from per-option selectedness. */
    selectedOption() {
        return this.children.find((child) => child.tagName === "option" && child.selected) || null;
    }

    /** Makes `option` the only selected option of this select (null selects none). */
    selectOnly(option) {
        for (const child of this.children) {
            if (child.tagName === "option") child.selected = child === option;
        }
    }

    /**
     * A browser's `value`: a select reads the value of the option that is selected ("" when none is), and an option
     * without a `value` attribute reads its own text with its whitespace collapsed. Setting a select's value marks the
     * matching option selected and leaves nothing selected when none matches (so `value` reads "" and `selectedIndex`
     * is -1) — the F-18 finding.
     */
    get value() {
        if (this.isSelect) {
            const option = this.selectedOption();
            return option === null ? "" : option.value;
        }
        if (this._value !== undefined) return String(this._value);
        return this.tagName === "option" ? this._text.replace(/\s+/g, " ").trim() : "";
    }

    set value(value) {
        const text = String(value);
        if (!this.isSelect) {
            this._value = text;
            return;
        }
        this.selectOnly(this.children.find((child) => child.tagName === "option" && child.value === text) || null);
    }

    get selectedIndex() {
        if (!this.isSelect) return -1;
        return this.children.findIndex((child) => child.tagName === "option" && child.selected);
    }

    set selectedIndex(index) {
        if (!this.isSelect) return;
        const at = Number(index);
        this.selectOnly(at >= 0 && at < this.children.length ? this.children[at] : null);
    }

    clearChildren() {
        // a detached option keeps its own selectedness, which is what lets a re-appended option take the selection back
        for (const child of this.children) child.parent = null;
        this.children = [];
    }

    appendChild(child) {
        // a browser moves the node out of its previous parent rather than copying it (the page relies on this to move
        // the QR the stub drew into the container it publishes)
        if (child.parent) child.parent.removeChild(child);
        child.parent = this;
        this.children.push(child);
        if (this.isSelect && child.tagName === "option") {
            // inserting an option runs the selectedness setting algorithm: a selected one takes the selection of a
            // single select, and a select with nothing selected selects its first option
            if (child.selected) this.selectOnly(child);
            else if (this.selectedOption() === null) this.selectOnly(this.children.find((o) => o.tagName === "option") || null);
        }
        return child;
    }

    removeChild(child) {
        const index = this.children.indexOf(child);
        if (index < 0) return child;
        this.children.splice(index, 1);
        child.parent = null;
        // removing the selected option leaves the first remaining one selected (Chrome), so no removal blanks a select
        if (this.isSelect && child.selected && this.selectedOption() === null) {
            this.selectOnly(this.children.find((o) => o.tagName === "option") || null);
        }
        return child;
    }

    get firstChild() {
        return this.children.length ? this.children[0] : null;
    }

    addEventListener(type, listener) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(listener);
    }

    // the page only ever clears a container with innerHTML; anything else would be a way for server text to become
    // markup, so every assignment is recorded and the checks below look for a non-empty one
    set innerHTML(value) {
        this.innerHTMLWrites.push(String(value));
        this._text = "";
        this.clearChildren();
    }

    get innerHTML() {
        return "";
    }

    async fire(type) {
        // a disabled control does not dispatch events (the page disables Create and the wallet while they work)
        if (this.disabled) return;
        const listeners = this.listeners.get(type) || [];
        for (const listener of listeners) await listener({ type, target: this });
    }
}

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr"]);

/** The attributes of one start tag by name: `data-id="x"` is an attribute named `data-id`, never one named `id`. */
function tagAttributes(attributes) {
    const found = new Map();
    for (const match of attributes.matchAll(/([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
        const [, name, doubleQuoted, singleQuoted, unquoted] = match;
        found.set(name.toLowerCase(), doubleQuoted !== undefined ? doubleQuoted
            : singleQuoted !== undefined ? singleQuoted : unquoted !== undefined ? unquoted : "");
    }
    return found;
}

/**
 * The elements the markup declares, nested as the markup nests them (so a select owns its options), with the state the
 * markup gives them (hidden, disabled, selected, value, the text between the tags). Only declared ids are returned:
 * anything else is absent, exactly as `document.getElementById` answers in a browser. Comments and raw-text content are
 * not markup, and a duplicate id answers with its first element, as a browser does.
 */
function markupElements(markup) {
    const elements = new Map();
    const stack = [];
    const source = markup
        .replace(/<!--[\s\S]*?-->/g, "")
        .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "");
    const tags = /<(\/?)([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*?)(\/?)>/g;
    let cursor = 0;
    for (const match of source.matchAll(tags)) {
        const text = source.slice(cursor, match.index);
        // `matchAll` iterates a copy of the regular expression, so `tags.lastIndex` stays 0: the next text starts
        // after the tag that was just matched
        cursor = match.index + match[0].length;
        if (text && stack.length) stack[stack.length - 1]._text += text;
        const [, closing, rawName, attributeText, selfClosing] = match;
        const tag = rawName.toLowerCase();
        if (closing) {
            for (let i = stack.length - 1; i >= 0; i--) {
                if (stack[i].tagName === tag) {
                    stack.length = i;
                    break;
                }
            }
            continue;
        }
        const attributes = tagAttributes(attributeText);
        const element = new Element(tag);
        element.hidden = attributes.has("hidden");
        element.disabled = attributes.has("disabled");
        element.checked = attributes.has("checked");
        element.selected = attributes.has("selected");
        if (attributes.has("value")) element._value = attributes.get("value");
        if (stack.length) stack[stack.length - 1].appendChild(element);
        const id = attributes.get("id");
        if (id !== undefined && !elements.has(id)) elements.set(id, element);
        if (!VOID.has(tag) && !selfClosing) stack.push(element);
    }
    return elements;
}

/* ---------------------------------------------------------------- fixtures: the documents the live stack serves */

const GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
// the mDL deployment's identifiers (config/certify-default.properties: mosip.certify.identifier = domain.url; the
// /oid4vci identifier appends the servlet path and /oid4vci, and certify-nginx maps each document's well-known location)
const DOMAIN = "https://credentials.example";
const OID4VCI_ISSUER = DOMAIN + "/v1/certify/oid4vci";
const LEGACY_ISSUER = DOMAIN;
const AS = DOMAIN;
const TOKEN_ENDPOINT = DOMAIN + "/v1/certify/oauth/token";
const OID4VCI_NONCE_ENDPOINT = OID4VCI_ISSUER + "/nonce";
const OID4VCI_CREDENTIAL_ENDPOINT = OID4VCI_ISSUER + "/credential";
const LEGACY_NONCE_ENDPOINT = DOMAIN + "/v1/certify/nonce";
const LEGACY_CREDENTIAL_ENDPOINT = DOMAIN + "/v1/certify/issuance/credential";
const OFFER_DOCUMENT = DOMAIN + "/v1/certify/credential-offer-data/";

const CONFIGURATIONS = {
    mdl: { format: "ldp_vc" },
    demo: { format: "ldp_vc" },
    farmer: { format: "ldp_vc" },
};

/** The compatibility document the page loads for its configuration dropdown (its credentials never leave the page). */
const METADATA = { credential_configurations_supported: CONFIGURATIONS };

/** The /oid4vci document (Oid4vciDiscoveryController): its own identity, this surface's endpoints, the deployment's AS. */
const OID4VCI_DOCUMENT = {
    credential_issuer: OID4VCI_ISSUER,
    authorization_servers: [AS],
    credential_endpoint: OID4VCI_CREDENTIAL_ENDPOINT,
    nonce_endpoint: OID4VCI_NONCE_ENDPOINT,
    notification_endpoint: OID4VCI_ISSUER + "/notification",
    credential_configurations_supported: CONFIGURATIONS,
};

/** The compatibility document (CredentialIssuerMetadataBuilder): the deployment identifier and its own endpoints. */
const LEGACY_DOCUMENT = {
    credential_issuer: LEGACY_ISSUER,
    authorization_servers: [LEGACY_ISSUER],
    credential_endpoint: LEGACY_CREDENTIAL_ENDPOINT,
    nonce_endpoint: LEGACY_NONCE_ENDPOINT,
    credential_configurations_supported: CONFIGURATIONS,
};

const DEFAULT_ISSUER_METADATA = { [OID4VCI_ISSUER]: OID4VCI_DOCUMENT, [LEGACY_ISSUER]: LEGACY_DOCUMENT };

/** The RFC 8414 document the live stack serves (F-17 evidence: no authorization_code it cannot complete). */
const AS_DOCUMENT = {
    issuer: AS,
    token_endpoint: TOKEN_ENDPOINT,
    jwks_uri: DOMAIN + "/v1/certify/.well-known/jwks.json",
    grant_types_supported: [GRANT],
    dpop_signing_alg_values_supported: ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"],
    "pre-authorized_grant_anonymous_access_supported": true,
};

const DEFAULT_AS_METADATA = { [AS]: AS_DOCUMENT };

/** OpenID4VCI 1.0 section 6.1: the shape PreAuthorizedCodeService#buildTxCodeInfo publishes for an entered code. */
const TX_CODE = { length: 4, input_mode: "numeric", description: "Please enter the transaction code provided to you" };

/** RFC 8414 section 3 / OpenID4VCI 1.0 section 12.2.2: the well-known segment goes between the host and the path. */
function wellKnown(identifier, suffix) {
    const url = new URL(identifier);
    return url.origin + "/.well-known/" + suffix + url.pathname.replace(/\/+$/, "");
}

/** A deep link whose `credential_offer_uri` parameter names an offer document, as the page's POST answer carries it. */
const deepLink = (name) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(OFFER_DOCUMENT + name)}`;

/** An offer document as PreAuthorizedCodeService publishes it (OpenID4VCI 1.0 section 4.1.1). */
const offerDocument = (credentialIssuer, configurationId, code, txCode) => ({
    credential_issuer: credentialIssuer,
    credential_configuration_ids: [configurationId],
    grants: { [GRANT]: Object.assign({ "pre-authorized_code": code }, txCode ? { tx_code: txCode } : {}) },
});

/** An offer the issuer returned by value: the deep link plus the same document, so the page fetches nothing. */
const offerByValue = (name, document) => ({ credential_offer_uri: deepLink(name), credential_offer: document });

/** An offer the issuer returned by reference: only the deep link, whose parameter the page must fetch. */
const offerByReference = (name) => ({ credential_offer_uri: deepLink(name) });

const OFFER = offerByValue("abc", offerDocument(OID4VCI_ISSUER, "demo", "abc"));
const REFERRED_OFFER = offerDocument(OID4VCI_ISSUER, "demo", "ref-code");

const SUBJECTS = [
    { id: "mdl-demo-1", label: "Asha Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-2", label: "Ravi Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-3", label: "Meera Test", credential_configuration_ids: ["mdl"] },
    { id: "farmer-1", label: "Farmer", credential_configuration_ids: ["farmer"] },
    { id: "__other__", label: "Sentinel", credential_configuration_ids: ["farmer"] },
];

/**
 * Opens the page: the markup's elements, the inline script evaluated against them, and the requests it makes on load
 * (the configuration document and the demo-subject list; the wallet's metadata is read when it redeems an offer).
 *
 * @param demo the answer to `GET /offer/demo-subjects`: a JSON value, a raw string, `false` for a 404, or `null` for a
 *             fetch that throws
 * @param options the page source (`html`), the issuer metadata documents by issuer (`issuerMetadata`), the
 *                authorization server documents by server (`asMetadata`), the answer to `POST /pre-authorized-data`
 *                (`offer`, or `offers` consumed one per click, the last one repeating), the answers to the by-reference
 *                offer fetch (`offerFetches`, an entry of `"throw"` being a fetch that rejects), and the `token`,
 *                `nonce` and `credential` answers of the page's wallet
 */
function openPage(demo, options = {}) {
    const source = options.html === undefined ? html : options.html;
    const elements = markupElements(source);
    const created = [];
    const requests = [];
    const missingIds = [];

    const document = {
        // a browser has no element for an id the markup does not declare; returning an invented one let page bugs pass
        getElementById(id) {
            const element = elements.get(id);
            if (element === undefined) missingIds.push(id);
            return element === undefined ? null : element;
        },
        createElement(tag) {
            const element = new Element(tag);
            created.push(element);
            return element;
        },
    };

    const answer = (status, body) => ({
        status,
        text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    });

    const tokenAnswer = options.token || { status: 200, body: { access_token: "at-f18", token_type: "Bearer" } };
    const nonceAnswer = options.nonce || { status: 200, body: { c_nonce: "nonce-f18" } };
    const credentialAnswer = options.credential
        || { status: 200, body: { credentials: [{ credential: "ldp-credential" }], notification_id: "notification-f18" } };
    const offers = options.offers ? options.offers.slice() : null;
    const offerFetches = (options.offerFetches || []).slice();
    const nextOffer = () => {
        if (!offers) return options.offer === undefined ? OFFER : options.offer;
        return offers.length > 1 ? offers.shift() : offers[0];
    };
    const nextOfferFetch = () => {
        if (!offerFetches.length) return { status: 404, body: "not found" };
        return offerFetches.length > 1 ? offerFetches.shift() : offerFetches[0];
    };

    const issuerMetadata = options.issuerMetadata || DEFAULT_ISSUER_METADATA;
    const asMetadata = options.asMetadata || DEFAULT_AS_METADATA;
    const issuerDocuments = new Map(Object.entries(issuerMetadata)
        .map(([issuer, document]) => [wellKnown(issuer, "openid-credential-issuer"), document]));
    const asDocuments = new Map(Object.entries(asMetadata)
        .map(([server, document]) => [wellKnown(server, "oauth-authorization-server"), document]));
    // the page must post to the endpoints the documents advertise, so those are the only ones a POST is answered on
    const nonceEndpoints = new Set(Object.values(issuerMetadata).map((entry) => entry && entry.nonce_endpoint).filter(Boolean));
    const credentialEndpoints = new Set(Object.values(issuerMetadata).map((entry) => entry && entry.credential_endpoint).filter(Boolean));
    const tokenEndpoints = new Set(Object.values(asMetadata).map((entry) => entry && entry.token_endpoint).filter(Boolean));

    const fetch = async (url, init = {}) => {
        const target = String(url);
        const method = (init.method || "GET").toUpperCase();
        const form = init.body instanceof URLSearchParams ? init.body : undefined;
        requests.push({
            method,
            url: target,
            headers: Object.assign({}, init.headers || {}),
            body: form ? form.toString() : init.body,
            form: form ? Object.fromEntries(form.entries()) : undefined,
        });
        // OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section 3: the documents of the offer's issuer and of its
        // authorization server, each at its well-known location
        if (method === "GET" && issuerDocuments.has(target)) return answer(200, issuerDocuments.get(target));
        if (method === "GET" && asDocuments.has(target)) return answer(200, asDocuments.get(target));
        // the page's own configuration list, loaded from its own surface
        if (method === "GET" && target.endsWith("/.well-known/openid-credential-issuer")) return answer(200, METADATA);
        if (method === "GET" && target.endsWith("/offer/demo-subjects")) {
            if (demo === null) throw new TypeError("fetch failed");
            if (demo === false) return answer(404, "not found");
            return answer(200, demo);
        }
        // the page fetches the document a by-reference offer names, at the absolute URL in the deep link
        if (method === "GET" && target.startsWith(OFFER_DOCUMENT)) {
            const next = nextOfferFetch();
            if (next === "throw") throw new TypeError("fetch failed");
            return answer(next.status, next.body);
        }
        if (method === "POST" && target.endsWith("/pre-authorized-data")) return answer(200, nextOffer());
        if (method === "POST" && tokenEndpoints.has(target)) return answer(tokenAnswer.status, tokenAnswer.body);
        if (method === "POST" && nonceEndpoints.has(target)) return answer(nonceAnswer.status, nonceAnswer.body);
        if (method === "POST" && credentialEndpoints.has(target)) return answer(credentialAnswer.status, credentialAnswer.body);
        return answer(404, "not found");
    };

    // the real library draws a QR into the container it is given; this stub appends a stand-in whose src names the
    // encoded text, so a check can say which offer's QR is where
    class QRCode {
        constructor(container, options) {
            const image = document.createElement("img");
            image.src = "qr:" + options.text;
            image.alt = "QR code";
            container.appendChild(image);
        }
    }
    QRCode.CorrectLevel = { L: 1, M: 2, Q: 3, H: 4 };

    const context = vm.createContext({
        location: { pathname: "/v1/certify/offer/" },
        document,
        fetch,
        QRCode,
        Cbor: { decode: () => ({}) },
        navigator: { clipboard: { writeText: async () => {} } },
        console: { log: () => {}, warn: () => {}, error: () => {} },
        setTimeout,
        clearTimeout,
        // the page's wallet: URL/URLSearchParams for the documents and links, WebCrypto for the proof, and the base64
        // helpers it encodes with
        URL,
        URLSearchParams,
        Blob,
        crypto: webcrypto,
        TextEncoder,
        TextDecoder,
        btoa,
        atob,
    });
    const inline = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)]
        .map((match) => match[1]).find((script) => script.includes("(function () {"));
    if (!inline) throw new Error("the page's inline script is missing");
    // a page that looks up an id the markup does not declare throws here, as it does in a browser; the checks report it
    let scriptError = null;
    try {
        vm.runInContext(inline, context, { filename: "static/offer/index.html" });
    } catch (error) {
        scriptError = error;
    }

    const page = {
        el: (id) => document.getElementById(id),
        created,
        requests,
        missingIds,
        scriptError,
        /** Lets every pending promise of the page's load finish. */
        async settle() {
            for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done));
        },
        /** Presses "Create offer" and returns the parsed body of the POST it made (an empty object, and a failed
         *  check, when it made none). */
        async createOffer() {
            const button = page.el("create");
            if (button === null) {
                check("the page has the Create button the checks press (#create)", false, "the markup declares no #create");
                return {};
            }
            const before = requests.filter((request) => request.method === "POST").length;
            await button.fire("click");
            const posts = requests.filter((request) => request.method === "POST");
            if (posts.length <= before) {
                check("the page creates an offer when Create offer is pressed", false, "it made no POST");
                return {};
            }
            return JSON.parse(posts[posts.length - 1].body);
        },
        /** Presses the in-page wallet button ("Run the pre-authorized code flow here"). */
        async runWallet() {
            const button = page.el("wallet");
            if (button === null) {
                check("the page has the wallet button the checks press (#wallet)", false, "the markup declares no #wallet");
                return;
            }
            await button.fire("click");
        },
        innerHTMLOfEverything() {
            return [...elements.values(), ...created].flatMap((element) => element.innerHTMLWrites);
        },
        createdTags() {
            return created.map((element) => element.tagName);
        },
    };
    return page;
}

const options = (page) => page.el("subjectChoice").children.map((option) => [option.value, option.textContent]);

/** A property of a declared element, or undefined when the markup declares no such element (never a crash). */
const prop = (page, id, name) => {
    const element = page.el(id);
    return element === null ? undefined : element[name];
};

/** The last request the page made that matches, or undefined. */
const find = (page, method, pattern) => page.requests.filter((request) => request.method === method && pattern.test(request.url)).pop();

/** The last metadata document the page fetched on its own behalf (the documents are absolute, the page's own is not). */
const metadataRequest = (page, suffix) => page.requests
    .filter((request) => request.method === "GET" && request.url.startsWith("http") && request.url.includes("/.well-known/" + suffix))
    .pop();

const tokenRequest = (page) => page.requests.filter((request) => request.method === "POST" && request.form && request.form.grant_type).pop();
const nonceRequest = (page) => page.requests.filter((request) => request.method === "POST" && /\/nonce$/.test(request.url)).pop();
const credentialRequest = (page) => page.requests
    .filter((request) => request.method === "POST" && typeof request.body === "string" && request.body.includes("\"proofs\""))
    .pop();

/** The stand-in QR images published in the page's `#qr` container, by the text they encode. */
const qrImages = (page) => page.el("qr").children.filter((child) => child.tagName === "img").map((child) => child.src);

const decodePart = (part) => {
    try {
        return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    } catch (error) {
        return {};
    }
};

/** Verifies a compact JWS proof against the JWK it carries, independently of how the page signed it. */
function proofVerifies(proof) {
    try {
        const [header, claims, signature] = String(proof).split(".");
        const jwk = decodePart(header).jwk;
        const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
        return verify("sha256", Buffer.from(header + "." + claims), { key, dsaEncoding: "ieee-p1363" },
            Buffer.from(signature, "base64url")) === true;
    } catch (error) {
        return false;
    }
}

/**
 * Everything the checks say about one wallet run's credential request: the body names the credential the offer (or the
 * access token's `authorization_details`) allows, and the proof is a strict compact JWS carrying a public P-256 key,
 * the offer issuer as `aud`, the nonce when the issuer gave one, and no `iss` (anonymous pre-authorized flow).
 */
function checkCredentialRequest(label, request, expected) {
    const body = request && typeof request.body === "string" ? JSON.parse(request.body) : undefined;
    check(`${label}: the credential request carries exactly one proof`, !!(body && body.proofs && body.proofs.jwt
        && body.proofs.jwt.length === 1), body);
    const proof = body && body.proofs && body.proofs.jwt && body.proofs.jwt[0];
    check(`${label}: the proof is a strict compact JWS (three base64url segments, no padding)`,
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(proof)), String(proof).slice(0, 48));
    const [headerPart, claimsPart] = String(proof).split(".");
    const header = headerPart ? decodePart(headerPart) : {};
    const claims = claimsPart ? decodePart(claimsPart) : {};
    const jwk = header.jwk || {};
    equal(`${label}: the proof header marks an OpenID4VCI proof signed with the key it carries`,
        [header.typ, header.alg, jwk.kty, jwk.crv, typeof jwk.x, typeof jwk.y],
        ["openid4vci-proof+jwt", "ES256", "EC", "P-256", "string", "string"]);
    equal(`${label}: the proof publishes a public key only (no private "d")`, "d" in jwk, false);
    equal(`${label}: aud is the credential issuer the offer named`, claims.aud, expected.audience);
    equal(`${label}: iss is absent in the anonymous pre-authorized flow`, "iss" in claims, false);
    equal(`${label}: the proof binds the nonce the issuer answered with`, "nonce" in claims ? claims.nonce : null,
        expected.nonce === undefined ? null : expected.nonce);
    check(`${label}: the proof has an issued-at time`, Number.isInteger(claims.iat) && claims.iat > 0, claims.iat);
    check(`${label}: the proof's signature verifies with the key it carries`, proofVerifies(proof));
    equal(`${label}: the credential request carries the access token`, request && request.headers.Authorization,
        "Bearer " + (expected.token === undefined ? "at-f18" : expected.token));
    const fields = body || {};
    if (expected.credentialIdentifier) {
        equal(`${label}: the credential is named by credential_identifier, never by a configuration id`,
            [fields.credential_identifier, "credential_configuration_id" in fields], [expected.credentialIdentifier, false]);
    } else {
        equal(`${label}: the credential is named by the configuration id the offer carries`,
            [fields.credential_configuration_id, "credential_identifier" in fields], [expected.configurationId, false]);
    }
}

/* ---------------------------------------------------------------- the page as it was */

async function unchanged(name, demo) {
    const page = openPage(demo);
    await page.settle();
    const el = page.el;
    check(`${name}: no dropdown`, el("subjectChoice").hidden === true);
    check(`${name}: no dropdown label`, el("subjectChoiceLabel").hidden === true);
    check(`${name}: the typed subject field is shown`, el("subject").hidden === false);
    check(`${name}: its label is shown`, el("subjectLabel").hidden === false);
    equal(`${name}: the typed label is the original text`, el("subjectLabel").textContent, SUBJECT_LABEL);
    equal(`${name}: the claims label is the original text`, el("claimsLabel").textContent, CLAIMS_LABEL);
    equal(`${name}: no options were built`, options(page), []);
    const markup = page.innerHTMLOfEverything().filter((written) => written !== "");
    equal(`${name}: no server value went through innerHTML`, markup, []);
    equal(`${name}: the load reported no error`, el("offerStatus").textContent, "");
    el("subject").value = "typed-1";
    const body = await page.createOffer();
    equal(`${name}: the typed id is still what the offer sends`, body, {
        credential_configuration_id: "demo",
        expires_in: 600,
        issuer: "legacy",
        subject: "typed-1",
    });
}

/* ---------------------------------------------------------------- checks */

// 1. the CSS rule the labels depend on: the page's own `label { display: block }` beats the UA's `[hidden]` rule
check("[hidden] is display:none !important in the page's stylesheet",
    /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(html));

// 2. the state a deployment without demo subjects shows
const untouched = openPage({ subjects: [] });
const initial = untouched.el;
check("the page's inline script runs against the markup's own ids", untouched.scriptError === null,
    untouched.scriptError && String(untouched.scriptError.message));
check("before the fetch: the dropdown ships hidden", initial("subjectChoice").hidden === true);
check("before the fetch: the dropdown label ships hidden", initial("subjectChoiceLabel").hidden === true);
check("before the fetch: the typed field and its label ship visible",
    initial("subject").hidden === false && initial("subjectLabel").hidden === false);
check("before the fetch: the offer URI and document stay hidden", initial("offerUri").hidden === true && initial("offerDoc").hidden === true);
check("before the fetch: the wallet's results stay hidden", initial("credential").hidden === true && initial("mdocView").hidden === true);
check("before the fetch: the deep link stays hidden", initial("open").hidden === true);

// 3. everything that is not a well-formed list leaves the page exactly as it was
await unchanged("empty list", { subjects: [] });
await unchanged("404", false);
await unchanged("a fetch that throws", null);
await unchanged("a list that is not JSON", "<html>not json</html>");
await unchanged("subjects is not an array", { subjects: {} });
await unchanged("label is a number", { subjects: [{ id: "x", label: 42, credential_configuration_ids: [] }] });
await unchanged("an id that is not a subject id", { subjects: [{ id: "bad id", label: "Bad", credential_configuration_ids: [] }] });
await unchanged("an id with markup", { subjects: [{ id: "<script>", label: "Bad", credential_configuration_ids: [] }] });
await unchanged("a configuration id that is not a string",
    { subjects: [{ id: "x", label: "X", credential_configuration_ids: [1] }] });
await unchanged("one bad entry among good ones", { subjects: [SUBJECTS[0], { id: "x", label: 42, credential_configuration_ids: [] }] });

// 4. the dropdown with configured subjects
{
    const page = openPage({ subjects: SUBJECTS });
    await page.settle();
    const el = page.el;
    check("subjects: the dropdown is shown", el("subjectChoice").hidden === false);
    check("subjects: its label is shown", el("subjectChoiceLabel").hidden === false);
    check("subjects: the typed field is hidden while a listed subject is chosen",
        el("subject").hidden === true && el("subjectLabel").hidden === true);
    equal("subjects: the claims label explains when claims apply", el("claimsLabel").textContent, CLAIMS_LABEL_WITH_CHOICE);

    // the configuration the page starts on is the first of the document's, "demo"
    equal("demo: only the subjects that name it, then Other", options(page), [
        ["mdl-demo-1", "Asha Demo (mdl-demo-1)"],
        ["mdl-demo-2", "Ravi Demo (mdl-demo-2)"],
        ["", "Other (type a subject id)"],
    ]);
    equal("demo: the first match is preselected", el("subjectChoice").value, "mdl-demo-1");
    equal("demo: the offer sends the preselected subject", (await page.createOffer()).subject, "mdl-demo-1");

    // re-filter on a configuration change
    el("configuration").value = "mdl";
    await el("configuration").fire("change");
    equal("mdl: the subjects that name it or apply to every configuration", options(page), [
        ["mdl-demo-1", "Asha Demo (mdl-demo-1)"],
        ["mdl-demo-2", "Ravi Demo (mdl-demo-2)"],
        ["mdl-demo-3", "Meera Test (mdl-demo-3)"],
        ["", "Other (type a subject id)"],
    ]);
    equal("mdl: the choice is kept when it is still offered", el("subjectChoice").value, "mdl-demo-1");
    el("subjectChoice").value = "mdl-demo-2";
    el("configuration").value = "demo";
    await el("configuration").fire("change");
    equal("re-filter: a still-valid choice is kept", el("subjectChoice").value, "mdl-demo-2");
    el("configuration").value = "mdl";
    await el("configuration").fire("change");
    el("subjectChoice").value = "mdl-demo-3";
    el("configuration").value = "demo";
    await el("configuration").fire("change");
    equal("re-filter: a choice the new configuration does not offer is replaced by the first match",
        el("subjectChoice").value, "mdl-demo-1");

    // "Other" reveals the typed field
    el("subjectChoice").value = "";
    await el("subjectChoice").fire("change");
    check("other: the typed subject field is revealed", el("subject").hidden === false && el("subjectLabel").hidden === false);
    equal("other: the dropdown stays on screen", el("subjectChoice").hidden, false);
    equal("other: the offer sends the typed id", (await (async () => {
        el("subject").value = "typed-9";
        return page.createOffer();
    })()).subject, "typed-9");

    // Other with an empty subject: the claims are what the offer carries
    el("subject").value = "";
    el("claims").value = '{"fullName": "Gorge Cooper", "dateOfBirth": "1990-05-25"}';
    equal("other: an empty subject falls through to the claims", await page.createOffer(), {
        credential_configuration_id: "demo",
        expires_in: 600,
        issuer: "legacy",
        claims: { fullName: "Gorge Cooper", dateOfBirth: "1990-05-25" },
    });

    // a configured subject id that could have been mistaken for the "Other" sentinel
    el("configuration").value = "farmer";
    await el("configuration").fire("change");
    equal("farmer: a subject id `__other__` is listed like any other", options(page), [
        ["farmer-1", "Farmer (farmer-1)"],
        ["__other__", "Sentinel (__other__)"],
        ["", "Other (type a subject id)"],
    ]);
    el("subjectChoice").value = "__other__";
    await el("subjectChoice").fire("change");
    el("subject").value = "typed-but-not-sent";
    equal("the `__other__` subject id is sent as itself, not taken as the Other option",
        (await page.createOffer()).subject, "__other__");

    // the POST body is the shape /pre-authorized-data has always taken
    el("configuration").value = "mdl";
    await el("configuration").fire("change");
    el("txCode").value = "1234";
    el("expires").value = "900";
    el("byValue").checked = true;
    equal("the POST body keeps the original shape", await page.createOffer(), {
        credential_configuration_id: "mdl",
        expires_in: 900,
        issuer: "legacy",
        offer_by_value: true,
        tx_code: "1234",
        subject: "mdl-demo-1",
    });
    el("txCode").value = "";
    el("expires").value = "600";
    el("byValue").checked = false;

    // and the page's other hidden elements still behave
    check("a created offer reveals its URI and document", el("offerUri").hidden === false && el("offerDoc").hidden === false);
    check("a created offer reveals its deep link", el("open").hidden === false);
    check("a created offer leaves the wallet's results hidden until used",
        el("credential").hidden === true && el("mdocView").hidden === true);
    equal("subjects: the page looked up only ids the markup declares", page.missingIds, []);
}

// 5. a label is display text, whatever it contains
{
    const label = '<img src=x onerror=alert(1)> "quoted" <b>bold</b>';
    const page = openPage({ subjects: [{ id: "evil-1", label, credential_configuration_ids: [] }] });
    await page.settle();
    const el = page.el;
    equal("a label with markup becomes an option's text", options(page), [
        ["evil-1", `${label} (evil-1)`],
        ["", "Other (type a subject id)"],
    ]);
    const images = page.createdTags().filter((tag) => tag === "img");
    equal("no element was built from the label", images, []);
    equal("no label reached innerHTML", page.innerHTMLOfEverything().filter((written) => written !== ""), []);
    check("the label is text on the option, not markup",
        page.el("subjectChoice").children[0]?.textContent.includes("<img src=x onerror=alert(1)>"));
}

// 6. a subject configured for another configuration leaves the page as it was: the dropdown hidden, the typed field and
//    the original claims label in place (this is the state a deployment whose subjects name other configurations shows,
//    not a reload: the page never reloads itself)
{
    const page = openPage({ subjects: [{ id: "only-1", label: "Only", credential_configuration_ids: ["farmer"] }] });
    await page.settle();
    equal("a configuration with no subject hides the dropdown again", page.el("subjectChoice").hidden, true);
    equal("and shows the typed field", page.el("subject").hidden, false);
    equal("and restores the claims label", page.el("claimsLabel").textContent, CLAIMS_LABEL);
}

// 7. the markup parser and the DOM rules the page depends on
{
    const parsed = markupElements(`<div id="first"><!-- <span id="in-a-comment"> --><script>var trap = '<b id="in-a-script">';</script>` +
        `<style>#in-a-style { color: red }</style><button data-id="not-an-id">x</button><span id="first">y</span></div>`);
    equal("an attribute named data-id is not an id", parsed.has("not-an-id"), false);
    equal("an id inside an HTML comment is not declared", parsed.has("in-a-comment"), false);
    equal("raw text inside a script is not markup", parsed.has("in-a-script"), false);
    equal("raw text inside a style is not markup", parsed.has("in-a-style"), false);
    equal("the first element with an id wins, as in a browser", parsed.get("first") && parsed.get("first").tagName, "div");

    const cleared = new Element("div");
    cleared.textContent = "old text";
    cleared.appendChild(new Element("span"));
    cleared.innerHTML = "";
    equal("innerHTML = \"\" clears the text and the children", [cleared.textContent, cleared.children.length], ["", 0]);

    const disabledControl = new Element("button");
    let clicks = 0;
    disabledControl.addEventListener("click", () => { clicks++; });
    disabledControl.disabled = true;
    await disabledControl.fire("click");
    equal("a disabled control does not dispatch a click", clicks, 0);
}

// 8. a <select>'s selection is per-option selectedness, as in a browser (HTML selectedness setting algorithm)
{
    const select = new Element("select");
    const option = (value) => {
        const element = new Element("option");
        element.value = value;
        element.textContent = value;
        return element;
    };
    const a = option("a"), b = option("b"), c = option("c");
    select.appendChild(a);
    select.appendChild(b);
    select.appendChild(c);
    equal("a select selects its first option while nothing is", [select.value, select.selectedIndex], ["a", 0]);
    select.value = "b";
    equal("a value an option carries selects that option", [select.value, select.selectedIndex], ["b", 1]);
    select.value = "no-such-option";
    equal("a value no option carries leaves nothing selected", [select.value, select.selectedIndex], ["", -1]);
    select.value = "b";
    select.removeChild(b);
    equal("removing the selected middle option selects the first one", [select.value, select.selectedIndex], ["a", 0]);
    select.value = "c";
    select.removeChild(c);
    equal("removing the selected last option selects the first one", [select.value, select.selectedIndex], ["a", 0]);
    select.appendChild(b);
    equal("a re-appended option still marked selected is the selection again", [select.value, select.selectedIndex], ["b", 1]);

    const other = new Element("select");
    const x = option("x"), y = option("y");
    other.appendChild(x);
    other.appendChild(y);
    other.value = "y";
    select.appendChild(y);
    equal("a moved option takes its selection with it", [select.value, select.children.includes(y)], ["y", true]);
    equal("and the select it left selects what is left", other.value, "x");

    const bare = new Element("option");
    bare.textContent = "  a   b  ";
    equal("an option without a value reads its text, whitespace collapsed", bare.value, "a b");
}

// 9. the page against that DOM: no invented elements, and an unofferable select value takes the Other path
{
    const page = openPage({ subjects: SUBJECTS });
    await page.settle();
    const el = page.el;
    equal("an id the markup does not declare has no element", el("no-such-element"), null);

    const choice = el("subjectChoice");
    const offered = choice.children.map((option) => option.value);
    choice.value = "no-such-subject";
    equal("a select value that matches no option reads back empty", [choice.value, choice.selectedIndex], ["", -1]);
    choice.value = offered[0];
    equal("a value one of its options carries still selects it", [choice.value, choice.selectedIndex], [offered[0], 0]);
    choice.value = offered[offered.length - 1];
    equal("the last option can be selected too", choice.value, offered[offered.length - 1]);

    // what that means for the page: an unofferable value is not a subject, so the offer falls back to the typed id (the
    // "Other" path) instead of sending a value no option carries
    choice.value = "no-such-subject";
    el("subject").value = "typed-after-a-stale-choice";
    equal("an unofferable select value falls through to the typed subject",
        (await page.createOffer()).subject, "typed-after-a-stale-choice");
    choice.value = "no-such-subject";
    el("subject").value = "";
    el("claims").value = '{"fullName": "Typed Fallback"}';
    equal("an unofferable select value with an empty subject falls through to the claims",
        (await page.createOffer()).claims, { fullName: "Typed Fallback" });
    el("claims").value = "";
}

// 10. a subject whose label repeats its id is shown as the id alone (F-18 nit 6), and so is a subject with no label
{
    const page = openPage({
        subjects: [
            { id: "same-1", label: "same-1", credential_configuration_ids: [] },
            { id: "quiet-1", label: "", credential_configuration_ids: [] },
            { id: "named-1", label: "Named", credential_configuration_ids: [] },
        ],
    });
    await page.settle();
    equal("a label equal to the id is not repeated", options(page), [
        ["same-1", "same-1"],
        ["quiet-1", "quiet-1"],
        ["named-1", "Named (named-1)"],
        ["", "Other (type a subject id)"],
    ]);
}

// 11. the published QR: the stub draws into the container it is given, and a new offer replaces the old QR
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("qr-one", offerDocument(OID4VCI_ISSUER, "demo", "code-one")),
            offerByValue("qr-two", offerDocument(OID4VCI_ISSUER, "demo", "code-two"))],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "qr-subject";
    await page.createOffer();
    equal("qr: the first offer's QR is published into the page's container",
        qrImages(page), ["qr:" + deepLink("qr-one")]);
    await page.createOffer();
    equal("qr: the container holds the current offer's QR and no other",
        qrImages(page), ["qr:" + deepLink("qr-two")]);
}

// 12. an offer by reference: the page fetches the document its deep link names, and publishes it
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByReference("by-reference")],
        offerFetches: [{ status: 200, body: REFERRED_OFFER }],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "reference-subject";
    await page.createOffer();
    const fetched = find(page, "GET", /credential-offer-data\/by-reference$/);
    check("by reference: the page fetched the offer document the deep link names",
        fetched !== undefined && fetched.url === OFFER_DOCUMENT + "by-reference", fetched && fetched.url);
    equal("by reference: the deep link is published", el("offerUri").textContent, deepLink("by-reference"));
    check("by reference: the fetched document is published",
        el("offerDoc").hidden === false && el("offerDoc").textContent.includes("ref-code"));
    check("by reference: the fetched grant enables the wallet", el("wallet").disabled === false);
    equal("by reference: the QR carries the deep link", qrImages(page), ["qr:" + deepLink("by-reference")]);
    equal("by reference: the page looked up only ids the markup declares", page.missingIds, []);
}

// 13. a replacement the page cannot complete leaves the previous offer, its document, its QR and the wallet's offer in
//     place — after a first offer has been published, which is the state these refusals have to preserve
for (const [label, answer] of [
    ["404", { status: 404, body: "not found" }],
    ["a fetch that throws", "throw"],
    ["a document without the pre-authorized grant", { status: 200, body: { grants: {} } }],
]) {
    const page = openPage({ subjects: [] }, {
        offers: [offerByReference("kept"), offerByReference("broken")],
        offerFetches: [{ status: 200, body: REFERRED_OFFER }, answer],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "kept-subject";
    await page.createOffer();
    const keptUri = el("offerUri").textContent;
    const keptDocument = el("offerDoc").textContent;
    const keptQr = qrImages(page);
    equal(`${label}: the previous offer was published first`, [keptUri, keptQr],
        [deepLink("kept"), ["qr:" + deepLink("kept")]]);

    await page.createOffer();
    // a rejected fetch reaches the page's outer catch and a refused one its by-reference message: either way the page
    // reports the failure and publishes nothing
    check(`${label}: the failed replacement is reported`,
        el("offerStatus").className.includes("bad"), el("offerStatus").textContent);
    equal(`${label}: the previous deep link stays`, el("offerUri").textContent, keptUri);
    equal(`${label}: the previous document stays`, el("offerDoc").textContent, keptDocument);
    equal(`${label}: the previous QR stays`, qrImages(page), keptQr);
    check(`${label}: the wallet stays enabled`, el("wallet").disabled === false);
    equal(`${label}: the Create button is usable again`, prop(page, "create", "disabled"), false);

    // and the wallet still redeems the offer that is on screen, not the one that failed
    await page.runWallet();
    equalFields(`${label}: the wallet redeems the kept offer's pre-authorized code`,
        tokenRequest(page) && tokenRequest(page).form, { grant_type: GRANT, "pre-authorized_code": "ref-code" });
    checkCredentialRequest(`${label}: the wallet redeems the kept offer's configuration`,
        credentialRequest(page), { audience: OID4VCI_ISSUER, nonce: "nonce-f18", configurationId: "demo" });
}

// 14. a first offer the page cannot publish leaves nothing published, and its disabled wallet dispatches nothing
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByReference("no-grant")],
        offerFetches: [{ status: 200, body: { grants: {} } }],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "no-grant-subject";
    await page.createOffer();
    check("a document without the pre-authorized grant is refused",
        el("offerStatus").textContent.includes("could not be fetched"), el("offerStatus").textContent);
    equal("and nothing is published", [el("offerUri").hidden, el("wallet").disabled], [true, true]);
    equal("and no QR is drawn", qrImages(page), []);
    const before = page.requests.length;
    await page.runWallet();
    equal("a disabled wallet button dispatches no click", page.requests.slice(before), []);
}

// 15. the page's own wallet: the metadata documents, the token form, the nonce, a real P-256 proof, the credential
{
    const page = openPage({ subjects: [] }, { offers: [offerByValue("wallet", offerDocument(OID4VCI_ISSUER, "demo", "code-f18"))] });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    el("txCode").value = "";
    await page.createOffer();
    check("wallet: the pre-authorized grant enables the wallet button", el("wallet").disabled === false);
    await page.runWallet();

    equal("wallet: the offer issuer's metadata is read at its well-known location (12.2.2)",
        metadataRequest(page, "openid-credential-issuer") && metadataRequest(page, "openid-credential-issuer").url,
        "https://credentials.example/.well-known/openid-credential-issuer/v1/certify/oid4vci");
    equal("wallet: its authorization server's metadata is read at its well-known location (RFC 8414 section 3)",
        metadataRequest(page, "oauth-authorization-server") && metadataRequest(page, "oauth-authorization-server").url,
        "https://credentials.example/.well-known/oauth-authorization-server");

    const token = tokenRequest(page);
    equal("wallet: the token request goes to the token endpoint the AS metadata advertises", token && token.url, TOKEN_ENDPOINT);
    equal("wallet: the token request is a form", token && token.headers["Content-Type"], "application/x-www-form-urlencoded");
    equalFields("wallet: the token form carries the grant and the pre-authorized code, and no tx_code", token && token.form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-f18",
    });

    const nonce = nonceRequest(page);
    equal("wallet: the c_nonce is fetched from the metadata's nonce_endpoint", nonce && nonce.url, OID4VCI_NONCE_ENDPOINT);
    equal("wallet: the nonce request has no body", nonce && nonce.body, undefined);

    const request = credentialRequest(page);
    equal("wallet: the credential request goes to the metadata's credential_endpoint",
        request && request.url, OID4VCI_CREDENTIAL_ENDPOINT);
    equal("wallet: the credential request is JSON", request && request.headers["Content-Type"], "application/json");
    check("wallet: the page sends no DPoP header of its own", request !== undefined && !("DPoP" in request.headers));
    checkCredentialRequest("wallet", request, { audience: OID4VCI_ISSUER, nonce: "nonce-f18", configurationId: "demo" });
    check("wallet: the issued credential is shown",
        el("credential").hidden === false && el("credential").textContent.includes("ldp-credential"),
        el("credential").textContent);
    check("wallet: the flow reports success", el("walletStatus").textContent.includes("Credential issued"),
        el("walletStatus").textContent);
    equal("wallet: the page looked up only ids the markup declares", page.missingIds, []);
}

// 16. section 6.1: the transaction code is sent for exactly the offers whose grant names one, with the value entered
//     for that offer
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-tx", offerDocument(OID4VCI_ISSUER, "demo", "code-tx", TX_CODE))],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    el("txCode").value = "1234";
    equal("tx_code: the offer itself carries the transaction code", (await page.createOffer()).tx_code, "1234");
    el("txCode").value = ""; // edited after the offer was created: the offer still asks for the value it was made with
    await page.runWallet();
    equalFields("tx_code: the token form carries the value entered for this offer", tokenRequest(page) && tokenRequest(page).form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-tx",
        tx_code: "1234",
    });
}
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-no-tx", offerDocument(OID4VCI_ISSUER, "demo", "code-plain"))],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    el("txCode").value = "";
    await page.createOffer();
    el("txCode").value = "9999"; // filled, but this offer's grant names no transaction code
    await page.runWallet();
    equalFields("tx_code: an offer whose grant names none never sends the field", tokenRequest(page) && tokenRequest(page).form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-plain",
    });
}

// 17. section 8.2: an access token that names credential identifiers is redeemed with credential_identifier
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-authz", offerDocument(OID4VCI_ISSUER, "demo", "code-authz"))],
        token: {
            status: 200,
            body: {
                access_token: "at-f18",
                token_type: "Bearer",
                authorization_details: [{ type: "openid_credential", credential_identifiers: ["credential-identifier-1"] }],
            },
        },
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    checkCredentialRequest("authorization_details", credentialRequest(page), {
        audience: OID4VCI_ISSUER,
        nonce: "nonce-f18",
        credentialIdentifier: "credential-identifier-1",
    });
}

// 18. a compatibility-surface offer: its own metadata, the AS it names (itself), and aud = the issuer the offer named
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-legacy", offerDocument(LEGACY_ISSUER, "demo", "code-legacy"))],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    equal("legacy offer: the offer issuer's own metadata is read at its well-known location",
        metadataRequest(page, "openid-credential-issuer") && metadataRequest(page, "openid-credential-issuer").url,
        "https://credentials.example/.well-known/openid-credential-issuer");
    equal("legacy offer: the authorization server falls back to the credential issuer",
        metadataRequest(page, "oauth-authorization-server") && metadataRequest(page, "oauth-authorization-server").url,
        "https://credentials.example/.well-known/oauth-authorization-server");
    equal("legacy offer: the credential is requested at the endpoint its metadata advertises",
        credentialRequest(page) && credentialRequest(page).url, LEGACY_CREDENTIAL_ENDPOINT);
    equal("legacy offer: the nonce comes from the endpoint its metadata advertises",
        nonceRequest(page) && nonceRequest(page).url, LEGACY_NONCE_ENDPOINT);
    checkCredentialRequest("legacy offer", credentialRequest(page), {
        audience: LEGACY_ISSUER,
        nonce: "nonce-f18",
        configurationId: "demo",
    });
    check("legacy offer: the issued credential is shown", el("credential").hidden === false && el("walletStatus").textContent.includes("Credential issued"),
        el("walletStatus").textContent);
}

// 19. an authorization server with a path of its own: RFC 8414 puts the well-known segment between host and path
{
    const as = "https://as.example/v1/esignet";
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-as-path", offerDocument(OID4VCI_ISSUER, "demo", "code-as"))],
        issuerMetadata: {
            [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { authorization_servers: [as] }),
        },
        asMetadata: {
            [as]: {
                issuer: as,
                token_endpoint: as + "/oauth/token",
                grant_types_supported: [GRANT],
            },
        },
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    equal("AS with a path: its metadata is read at the RFC 8414 location",
        metadataRequest(page, "oauth-authorization-server") && metadataRequest(page, "oauth-authorization-server").url,
        "https://as.example/.well-known/oauth-authorization-server/v1/esignet");
    equal("AS with a path: the token request goes to its token endpoint",
        tokenRequest(page) && tokenRequest(page).url, as + "/oauth/token");
    equalFields("AS with a path: the token form still carries the grant", tokenRequest(page) && tokenRequest(page).form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-as",
    });
}

// 20. section 7: the nonce endpoint is optional, and any 2xx from it is an answer
{
    const withoutNonce = Object.assign({}, OID4VCI_DOCUMENT);
    delete withoutNonce.nonce_endpoint;
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-no-nonce", offerDocument(OID4VCI_ISSUER, "demo", "code-no-nonce"))],
        issuerMetadata: { [OID4VCI_ISSUER]: withoutNonce },
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    equal("no nonce_endpoint: the wallet asks for no c_nonce", nonceRequest(page), undefined);
    checkCredentialRequest("no nonce_endpoint", credentialRequest(page), {
        audience: OID4VCI_ISSUER,
        nonce: undefined,
        configurationId: "demo",
    });
}
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-nonce-201", offerDocument(OID4VCI_ISSUER, "demo", "code-201"))],
        nonce: { status: 201, body: { c_nonce: "nonce-201" } },
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    checkCredentialRequest("a 201 nonce answer", credentialRequest(page), {
        audience: OID4VCI_ISSUER,
        nonce: "nonce-201",
        configurationId: "demo",
    });
    check("a 201 nonce answer: the credential is issued", el("walletStatus").textContent.includes("Credential issued"),
        el("walletStatus").textContent);
}

console.log();
if (failures) {
    console.log(`check-offer-page: ${failures} of ${checks} checks FAILED`);
    process.exit(1);
}
console.log(`check-offer-page: all ${checks} checks passed`);
