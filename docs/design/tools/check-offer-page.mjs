#!/usr/bin/env node
/*
 * Behaviour check of the credential offer page's demo-subject wiring (F-15), and of the page's own behaviour around it:
 * the REAL `certify-service/src/main/resources/static/offer/index.html` is loaded, its inline script evaluated in a
 * throwaway VM with a minimal fake DOM, a stub `fetch` and a stub `QRCode`, and the page is driven the way a visitor
 * drives it (choose a configuration, choose a subject, press "Create offer", let the page be the wallet).
 *
 * Plain Node (18 or later), no npm dependencies, no browser, no server: `node docs/design/tools/check-offer-page.mjs`.
 * One line per check, then `check-offer-page: all N checks passed`; a non-zero exit when anything fails.
 *
 * Why it exists: round 1 of the F-15 review found that the JUnit page tests asserted source strings, which stayed green
 * while two real defects shipped (a `[hidden]` attribute that the page's own `label { display: block }` overrode, so a
 * stray subject label was always visible; and an "Other" sentinel value that a configured subject id could collide
 * with). Those two checks below are the regression tests for exactly those defects.
 *
 * Faithfulness (F-18). Round 2 of the F-15 review found the harness could pass where a real browser fails, so the fake
 * DOM now answers the way a browser does wherever the page depends on it (the page itself changes only in the subject
 * label, which F-18 nit 6 prints once when it repeats the id):
 *   - `getElementById` returns null for an id the markup does not declare (it never invents an element), so a page
 *     that looks up a missing id fails here as it throws in a browser;
 *   - a `<select>` whose `value` is set to something no `<option>` carries reads back "" with `selectedIndex` -1, and
 *     the first appended option becomes the selection, as in a single-select;
 *   - `appendChild` moves a node out of its previous parent, so the page's `while (qr.firstChild) container.appendChild(...)`
 *     moves children exactly as a browser does;
 *   - the `QRCode` stub draws a child into the container it is handed, so the published QR can be located;
 *   - the page's own wallet runs for real: Node's WebCrypto signs a P-256 proof, and this file verifies that signature
 *     with an independent key check.
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
 *     is only as faithful as the fixtures below.
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
        this._selectedIndex = tag === "select" ? -1 : undefined;
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

    /**
     * A browser's `value`: a select reads the selected option's value, "" when nothing is selected; an option without a
     * `value` attribute reads its own text. Setting a select's value selects the matching option and leaves
     * `selectedIndex` at -1 (so `value` reads "") when no option matches — the F-18 finding.
     */
    get value() {
        if (this.isSelect) {
            const option = this.children[this._selectedIndex];
            return option === undefined ? "" : option.value;
        }
        if (this._value !== undefined) return String(this._value);
        return this.tagName === "option" ? this._text.trim() : "";
    }

    set value(value) {
        const text = String(value);
        if (!this.isSelect) {
            this._value = text;
            return;
        }
        this._selectedIndex = this.children.findIndex((child) => child.tagName === "option" && child.value === text);
    }

    get selectedIndex() {
        return this.isSelect ? this._selectedIndex : -1;
    }

    set selectedIndex(index) {
        if (!this.isSelect) return;
        const at = Number(index);
        this._selectedIndex = at >= 0 && at < this.children.length ? at : -1;
    }

    clearChildren() {
        for (const child of this.children) child.parent = null;
        this.children = [];
        // no options left means nothing is selected, as in a browser
        if (this.isSelect) this._selectedIndex = -1;
    }

    appendChild(child) {
        // a browser moves the node out of its previous parent rather than copying it (the page relies on this to move
        // the QR the stub drew into the container it publishes)
        if (child.parent) child.parent.removeChild(child);
        child.parent = this;
        this.children.push(child);
        // a single-select with no selection selects its first option as soon as it has one
        if (this.isSelect && this._selectedIndex < 0) this._selectedIndex = 0;
        return child;
    }

    removeChild(child) {
        const index = this.children.indexOf(child);
        if (index < 0) return child;
        this.children.splice(index, 1);
        child.parent = null;
        if (this.isSelect) {
            if (!this.children.length) this._selectedIndex = -1;
            else if (index < this._selectedIndex) this._selectedIndex--;
            else if (this._selectedIndex >= this.children.length) this._selectedIndex = this.children.length - 1;
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
        this.clearChildren();
    }

    get innerHTML() {
        return "";
    }

    async fire(type) {
        const listeners = this.listeners.get(type) || [];
        for (const listener of listeners) await listener({ type, target: this });
    }
}

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr"]);

function applyMarkupAttributes(element, attributes) {
    element.hidden = /(^|\s)hidden(\s|=|$)/.test(attributes);
    element.disabled = /(^|\s)disabled(\s|=|$)/.test(attributes);
    element.checked = /(^|\s)checked(\s|=|$)/.test(attributes);
    const value = /\bvalue="([^"]*)"/.exec(attributes);
    if (value) element._value = value[1];
}

/**
 * The elements the markup declares, nested as the markup nests them (so a select owns its options), with the state the
 * markup gives them (hidden, disabled, value, the text between the tags). Only declared ids are returned: anything else
 * is absent, exactly as `document.getElementById` answers in a browser. The inline script is removed first: its `<`
 * comparisons are not markup.
 */
function markupElements(markup) {
    const elements = new Map();
    const stack = [];
    const source = markup.replace(/<script\b[\s\S]*?<\/script>/gi, "");
    const tags = /<(\/?)([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*?)(\/?)>/g;
    let cursor = 0;
    for (const match of source.matchAll(tags)) {
        const text = source.slice(cursor, match.index);
        // `matchAll` iterates a copy of the regular expression, so `tags.lastIndex` stays 0: the next text starts
        // after the tag that was just matched
        cursor = match.index + match[0].length;
        if (text && stack.length) stack[stack.length - 1]._text += text;
        const [, closing, rawName, attributes, selfClosing] = match;
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
        const element = new Element(tag);
        applyMarkupAttributes(element, attributes);
        if (stack.length) stack[stack.length - 1].appendChild(element);
        const id = /\bid="([^"]*)"/.exec(attributes);
        if (id) elements.set(id[1], element);
        if (!VOID.has(tag) && !selfClosing) stack.push(element);
    }
    return elements;
}

/* ---------------------------------------------------------------- fixtures */

const GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const TOKEN_ENDPOINT = "https://issuer.example/token";
const ISSUER = "https://issuer.example/oid4vci";
const OFFER_DOCUMENT = "https://issuer.example/v1/certify/credential-offer-data/";

const METADATA = {
    credential_configurations_supported: {
        mdl: { format: "ldp_vc" },
        demo: { format: "ldp_vc" },
        farmer: { format: "ldp_vc" },
    },
};

/** A deep link whose `credential_offer_uri` parameter names an offer document, as the page's POST answer carries it. */
const deepLink = (name) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(OFFER_DOCUMENT + name)}`;

/** An offer the issuer returned by value: the deep link plus the document, so the page fetches nothing. */
const offerByValue = (name, code) => ({
    credential_offer_uri: deepLink(name),
    credential_offer: { grants: { [GRANT]: { "pre-authorized_code": code } } },
});

/** An offer the issuer returned by reference: only the deep link, whose parameter the page must fetch. */
const offerByReference = (name) => ({ credential_offer_uri: deepLink(name) });

const OFFER = offerByValue("abc", "abc");
const REFERRED_OFFER = { grants: { [GRANT]: { "pre-authorized_code": "ref-code" } } };

const SUBJECTS = [
    { id: "mdl-demo-1", label: "Asha Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-2", label: "Ravi Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-3", label: "Meera Test", credential_configuration_ids: ["mdl"] },
    { id: "farmer-1", label: "Farmer", credential_configuration_ids: ["farmer"] },
    { id: "__other__", label: "Sentinel", credential_configuration_ids: ["farmer"] },
];

/**
 * Opens the page: the markup's elements, the inline script evaluated against them, and the four requests it makes on
 * load (two metadata documents, the authorization server metadata, the demo-subject list).
 *
 * @param demo the answer to `GET /offer/demo-subjects`: a JSON value, a raw string, `false` for a 404, or `null` for a
 *             fetch that throws
 * @param options the page source (`html`), the answer to `POST /pre-authorized-data` (`offer`, or `offers` consumed one
 *                per click, the last one repeating), the answers to the by-reference offer fetch (`offerFetches`), and
 *                the `token`, `nonce` and `credential` answers of the page's wallet
 */
function openPage(demo, options = {}) {
    const elements = markupElements(options.html === undefined ? html : options.html);
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
        if (method === "GET" && target.endsWith("/.well-known/oauth-authorization-server")) {
            return answer(200, { token_endpoint: TOKEN_ENDPOINT });
        }
        if (method === "GET" && target.endsWith("/oid4vci/.well-known/openid-credential-issuer")) {
            return answer(200, { credential_issuer: ISSUER, credential_configurations_supported: {} });
        }
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
        if (method === "POST" && target === TOKEN_ENDPOINT) return answer(tokenAnswer.status, tokenAnswer.body);
        if (method === "POST" && target.endsWith("/oid4vci/nonce")) return answer(nonceAnswer.status, nonceAnswer.body);
        if (method === "POST" && target.endsWith("/oid4vci/credential")) {
            return answer(credentialAnswer.status, credentialAnswer.body);
        }
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
        // the page's wallet: URL/URLSearchParams for the offer fetch, WebCrypto for the proof, and the base64 helpers
        URL,
        URLSearchParams,
        Blob,
        crypto: webcrypto,
        TextEncoder,
        TextDecoder,
        btoa,
        atob,
    });
    const inline = [...(options.html === undefined ? html : options.html).matchAll(/<script>([\s\S]*?)<\/script>/g)]
        .map((match) => match[1]).find((source) => source.includes("(function () {"));
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

/** The last request the page made that matches, or undefined. */
const find = (page, method, pattern) => page.requests.filter((request) => request.method === method && pattern.test(request.url)).pop();

/** The stand-in QR images published in the page's `#qr` container, by the text they encode. */
const qrImages = (page) => page.el("qr").children.filter((child) => child.tagName === "img").map((child) => child.src);

const decodePart = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

/** Verifies a compact JWS proof against the JWK it carries, independently of how the page signed it. */
function proofVerifies(proof) {
    const [header, claims, signature] = String(proof).split(".");
    const jwk = decodePart(header).jwk;
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
    return verify("sha256", Buffer.from(header + "." + claims), { key, dsaEncoding: "ieee-p1363" },
        Buffer.from(signature, "base64url"));
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
        page.el("subjectChoice").children[0].textContent.includes("<img src=x onerror=alert(1)>"));
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

// 7. the page against a browser's DOM: no invented elements, and a select's value means what it means in a browser
{
    const page = openPage({ subjects: SUBJECTS });
    await page.settle();
    const el = page.el;
    equal("an id the markup does not declare has no element", el("no-such-element"), null);

    // a select whose value matches no option reads back "", as a browser's does (selectedIndex -1)
    const choice = el("subjectChoice");
    const offered = choice.children.map((option) => option.value);
    choice.value = "no-such-subject";
    equal("a select value that matches no option reads back empty", choice.value, "");
    equal("and its selectedIndex is -1", choice.selectedIndex, -1);
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

// 8. a subject whose label repeats its id is shown as the id alone (F-18 nit 6), and so is a subject with no label
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

// 9. the published QR: the stub draws into the container it is given, and a new offer replaces the old QR
{
    const page = openPage({ subjects: [] }, { offers: [offerByValue("qr-one", "code-one"), offerByValue("qr-two", "code-two")] });
    await page.settle();
    const el = page.el;
    el("subject").value = "qr-subject";
    await page.createOffer();
    equal("qr: the first offer's QR is published into the page's container",
        qrImages(page), ["qr:" + deepLink("qr-one")]);
    equal("qr: the container holds nothing else", el("qr").children.length, 1);
    await page.createOffer();
    equal("qr: the next offer's QR replaces it", qrImages(page), ["qr:" + deepLink("qr-two")]);
    equal("qr: no QR of the previous offer is left behind", el("qr").children.length, 1);
}

// 10. an offer by reference: the page fetches the document its deep link names, and publishes it
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

// 11. a by-reference offer that cannot be fetched leaves the previous offer, its document and its QR in place
{
    const page = openPage({ subjects: [] }, {
        offers: [offerByReference("kept"), offerByReference("broken")],
        offerFetches: [{ status: 200, body: REFERRED_OFFER }, { status: 404, body: "not found" }],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "kept-subject";
    await page.createOffer();
    const keptUri = el("offerUri").textContent;
    const keptDocument = el("offerDoc").textContent;
    const keptQr = qrImages(page);
    equal("a failed replacement: the previous offer was published first", keptUri, deepLink("kept"));

    await page.createOffer();
    check("a failed by-reference fetch is reported", el("offerStatus").textContent.includes("could not be fetched"),
        el("offerStatus").textContent);
    equal("a failed by-reference fetch keeps the previous deep link", el("offerUri").textContent, keptUri);
    equal("a failed by-reference fetch keeps the previous document", el("offerDoc").textContent, keptDocument);
    equal("a failed by-reference fetch keeps the previous QR", qrImages(page), keptQr);
    check("a failed by-reference fetch keeps the wallet enabled", el("wallet").disabled === false);
    check("a failed by-reference fetch re-enables the Create button", el("create").disabled === false);
}

// 12. a by-reference document without the pre-authorized grant is not an offer the page publishes
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
}

// 13. the page's own wallet: token form, c_nonce, a real P-256 proof, and the credential request
{
    const page = openPage({ subjects: [] }, { offers: [offerByValue("wallet", "code-f18")] });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    el("txCode").value = "";
    await page.createOffer();
    check("wallet: the pre-authorized grant enables the wallet button", el("wallet").disabled === false);
    await page.runWallet();

    const token = find(page, "POST", /\/token$/);
    check("wallet: the token request goes to the token endpoint the AS metadata advertises",
        token !== undefined && token.url === TOKEN_ENDPOINT, token && token.url);
    equal("wallet: the token request is a form", token && token.headers["Content-Type"],
        "application/x-www-form-urlencoded");
    equalFields("wallet: the token form carries the grant and the pre-authorized code, and no tx_code", token && token.form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-f18",
    });

    const nonce = find(page, "POST", /\/oid4vci\/nonce$/);
    check("wallet: a c_nonce is fetched with POST /oid4vci/nonce and no body",
        nonce !== undefined && nonce.body === undefined, nonce && nonce.body);

    const request = find(page, "POST", /\/oid4vci\/credential$/);
    check("wallet: the credential is requested at /oid4vci/credential",
        request !== undefined && request.url === "/v1/certify/oid4vci/credential", request && request.url);
    equal("wallet: the credential request carries the token in the Authorization header",
        request && request.headers.Authorization, "Bearer at-f18");
    check("wallet: the page sends no DPoP header of its own", request !== undefined && !("DPoP" in request.headers));
    equal("wallet: the credential request is JSON", request && request.headers["Content-Type"], "application/json");

    const body = JSON.parse(request.body);
    equal("wallet: the credential request names the configuration the page offered",
        body.credential_configuration_id, "demo");
    equal("wallet: the proof travels in proofs.jwt", Array.isArray(body.proofs && body.proofs.jwt)
        && body.proofs.jwt.length, 1);

    const proof = body.proofs.jwt[0];
    const proofHeader = decodePart(proof.split(".")[0]);
    const proofClaims = decodePart(proof.split(".")[1]);
    equal("wallet: the proof header's typ marks an OpenID4VCI proof", proofHeader.typ, "openid4vci-proof+jwt");
    equal("wallet: the proof's alg matches the P-256 key it carries",
        [proofHeader.alg, proofHeader.jwk && proofHeader.jwk.kty, proofHeader.jwk && proofHeader.jwk.crv],
        ["ES256", "EC", "P-256"]);
    equal("wallet: the proof's audience is the credential issuer", proofClaims.aud, ISSUER);
    equal("wallet: the proof carries the c_nonce the nonce endpoint answered", proofClaims.nonce, "nonce-f18");
    check("wallet: the proof has an issued-at time", Number.isInteger(proofClaims.iat) && proofClaims.iat > 0, proofClaims.iat);
    check("wallet: the proof's signature verifies with the key it carries", proofVerifies(proof) === true);
    check("wallet: the issued credential is shown",
        el("credential").hidden === false && el("credential").textContent.includes("ldp-credential"),
        el("credential").textContent);
    check("wallet: the flow reports success", el("walletStatus").textContent.includes("Credential issued"),
        el("walletStatus").textContent);
    equal("wallet: the page looked up only ids the markup declares", page.missingIds, []);
}

// 14. the wallet sends the transaction code the visitor typed, and only then
{
    const page = openPage({ subjects: [] }, { offers: [offerByValue("wallet-tx", "code-tx")] });
    await page.settle();
    const el = page.el;
    el("subject").value = "wallet-subject";
    el("txCode").value = "1234";
    equal("wallet tx_code: the offer itself carries the transaction code",
        (await page.createOffer()).tx_code, "1234");
    await page.runWallet();
    const token = find(page, "POST", /\/token$/);
    equalFields("wallet tx_code: the token form carries the entered transaction code", token && token.form, {
        grant_type: GRANT,
        "pre-authorized_code": "code-tx",
        tx_code: "1234",
    });
}

console.log();
if (failures) {
    console.log(`check-offer-page: ${failures} of ${checks} checks FAILED`);
    process.exit(1);
}
console.log(`check-offer-page: all ${checks} checks passed`);
