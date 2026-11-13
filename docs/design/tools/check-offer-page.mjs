#!/usr/bin/env node
/*
 * Behaviour check of the credential offer page's demo-subject wiring (F-15), and of the page's own behaviour around it:
 * the REAL `certify-service/src/main/resources/static/offer/index.html` is loaded, its inline script evaluated in a
 * throwaway VM with a minimal fake DOM, a stub `fetch` and a stub `QRCode`, and the page is driven the way a visitor
 * drives it (choose a configuration, choose a subject, press "Create offer", let the page be the wallet).
 *
 * Plain Node (20 or later, the version CI pins), no npm dependencies, no browser, no server:
 * `node docs/design/tools/check-offer-page.mjs`. One line per check, then
 * `check-offer-page: all N checks passed`; a non-zero exit when anything fails. A page that breaks the harness (an
 * element renamed, a handler that throws) gives FAIL lines and the summary, never an uncaught exception: every numbered
 * section runs inside `section()`, which records an exception as a failed check, and the summary is printed in a
 * `finally`.
 *
 * Why it exists: round 1 of the F-15 review found that the JUnit page tests asserted source strings, which stayed green
 * while two real defects shipped (a `[hidden]` attribute that the page's own `label { display: block }` overrode, so a
 * stray subject label was always visible; and an "Other" sentinel value that a configured subject id could collide
 * with). Those two checks below are the regression tests for exactly those defects.
 *
 * Faithfulness (F-18). The F-15 and F-18 reviews found the harness could pass where a real browser fails, so the fake
 * DOM answers the way a browser does wherever the page depends on it:
 *   - the markup is tokenised the way the HTML parser does for what the page uses: an id comes from an attribute whose
 *     name is exactly `id` (a `data-id` is not one, an empty id is none, a duplicate attribute keeps its first
 *     occurrence), comments and doctypes are not markup, `script`/`style` content is raw text and `textarea`/`title`
 *     content is RCDATA (text with character references decoded: a tag inside them is text, never an element), the
 *     containing element and its attributes are kept, the first element with an id wins, a new `<option>` closes an
 *     open one, and only the page's inline scripts (no `src`) are run, in document order;
 *   - `getElementById` returns null for an id the markup does not declare (it never invents an element), so a page
 *     that looks up a missing id fails here as it throws in a browser;
 *   - nodes are elements and text nodes: `textContent` reads the text of every descendant and setting it replaces the
 *     children, `firstChild` sees text nodes, `appendChild` moves a node out of its previous parent, `innerHTML = ""`
 *     clears everything (and reading `innerHTML` throws, because nothing here serialises markup);
 *   - a `<select>` keeps per-option selectedness and runs the HTML selectedness setting algorithm: `value` and
 *     `selectedIndex` are derived from it over the list of options (optgroups included), setting a value no option
 *     carries leaves nothing selected ("" and -1), `option.selected = true` deselects the other options of a single
 *     select and `selected = false` asks for a reset, an inserted selected option takes the selection, and inserting or
 *     removing options leaves the first option that is not disabled selected when nothing is; an option without a
 *     `value` reads its text with whitespace collapsed, and a `textarea` reads its text until its value is set;
 *   - a disabled control dispatches no click;
 *   - `fetch` follows the Fetch standard's redirect modes for a 3xx with a `Location`: "follow" (the default) re-sends
 *     the request there (301/302 turn a POST, 303 anything but GET/HEAD, into a GET without a body; 307/308 keep the
 *     method and the body; a cross-origin hop drops `Authorization`), "error" rejects with a TypeError and requests
 *     nothing at `Location`, "manual" answers an opaque redirect (status 0);
 *   - the `QRCode` stub draws a child into the container it is handed, so the published QR can be located and a
 *     replaced one is seen to leave nothing behind;
 *   - the page's own wallet runs for real against the documents the live stack serves (issuer metadata and RFC 8414
 *     authorization server metadata at their well-known locations, the endpoints they name): Node's WebCrypto signs a
 *     P-256 proof, this file verifies that signature with an independent key check, and the token form, the
 *     transaction code, `authorization_details`, the nonce and the credential request are all asserted, as are the
 *     refusals (metadata whose identity does not match, relative or downgraded endpoints) that must send nothing.
 *
 * `OFFER_PAGE_HTML=<path>` evaluates another copy of the page. It exists for negative controls (break a copy in a
 * scratch directory and watch this file fail); a broken copy is never committed.
 *
 * What this harness CANNOT check:
 *   - computed CSS and layout. The `[hidden]` check below is a static assertion over the stylesheet's text, not a
 *     rendered cascade, so a later rule, a specificity question, a media query or anything geometric (positions, sizes,
 *     overflow, z-index, scroll) is out of reach; so is whether the page looks right;
 *   - the full HTML parser: only the tokenisation rules listed above are modelled (plus newline normalisation and the
 *     newline dropped right after `<textarea>`, `<pre>` and `<listing>`; no foster parenting, no other implied end tags,
 *     no `<select>` content restrictions, a small set of named character references); a page that relies on anything
 *     else is not modelled faithfully;
 *   - user interaction: a visitor cannot pick a disabled `<option>`, which the harness asserts as the option's
 *     `disabled` flag and the page's own refusal, not through a real picker; focus, keyboard, tab order, pointer and
 *     drag-and-drop behaviour, form submission and navigation;
 *   - real QR rendering or scanning, image decoding, `Blob` URLs and portrait rendering (the `Cbor` stub is a stub);
 *   - CSP, CORS (no preflight, and a cross-origin answer is readable here where a browser would make it opaque),
 *     cookies, TLS, real network timing, retries, and the clipboard. Of redirects, only the three modes above are
 *     modelled: not the CORS checks a cross-origin hop of a non-simple request needs, `Location` parsing edge cases,
 *     or more than 20 hops;
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
const MDOC_SURFACE_HINT = "ISO mdoc credentials are issued on the OpenID4VCI 1.0 surface only";

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

/**
 * Runs one numbered section of checks. An exception (a page whose element was renamed, a handler that throws, a check
 * that reads a property of null) is recorded as a failed check of that section, and the next section still runs.
 */
async function section(name, body) {
    try {
        await body();
    } catch (error) {
        const where = error && error.stack ? error.stack.split("\n").slice(0, 2).join(" | ") : String(error);
        check(`${name}: the section ran to its end`, false, where);
    }
}

/* ---------------------------------------------------------------- fake DOM */

/** A text node: the text an element's `textContent` is made of. */
class Text {
    constructor(data) {
        this.nodeType = 3;
        this.data = String(data);
        this.parent = null;
    }

    get textContent() {
        return this.data;
    }

    set textContent(text) {
        this.data = String(text);
    }
}

/** An option is disabled by its own attribute or by a disabled optgroup it is a child of (HTML 4.10.10). */
const optionDisabled = (option) => option.disabled
    || (option.parent !== null && option.parent.tagName === "optgroup" && option.parent.disabled);

class Element {
    constructor(tag) {
        this.nodeType = 1;
        this.tagName = tag;
        this.childNodes = [];
        this.parent = null;
        this.attributes = new Map();
        this.listeners = new Map();
        this._value = undefined;
        this._selected = false;
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

    /** The element children (a browser's `children`; text nodes are in `childNodes` only). */
    get children() {
        return this.childNodes.filter((node) => node instanceof Element);
    }

    get firstChild() {
        return this.childNodes.length ? this.childNodes[0] : null;
    }

    /** A select's list of options: its option children and the option children of its optgroup children, in tree order. */
    get options() {
        if (!this.isSelect) return [];
        const list = [];
        for (const child of this.children) {
            if (child.tagName === "option") list.push(child);
            else if (child.tagName === "optgroup") list.push(...child.children.filter((option) => option.tagName === "option"));
        }
        return list;
    }

    /** The select whose list of options this option is in, or null. */
    ownerSelect() {
        if (this.tagName !== "option" || this.parent === null) return null;
        if (this.parent.isSelect) return this.parent;
        const group = this.parent;
        return group.tagName === "optgroup" && group.parent !== null && group.parent.isSelect ? group.parent : null;
    }

    /** The select whose list of options changes when `node` is inserted into or removed from this element, or null. */
    selectFor(node) {
        if (!(node instanceof Element) || (node.tagName !== "option" && node.tagName !== "optgroup")) return null;
        if (this.isSelect) return this;
        if (this.tagName === "optgroup" && node.tagName === "option" && this.parent !== null && this.parent.isSelect) return this.parent;
        return null;
    }

    // a browser's textContent is the text of every descendant, in tree order; setting it replaces the children with one
    // text node (the page clears the subject dropdown's options this way, so a fake that kept them would hide the
    // re-filter it performs)
    get textContent() {
        return this.childNodes.map((node) => node.textContent).join("");
    }

    set textContent(text) {
        this.removeAllChildren();
        const value = String(text);
        if (value) this.appendChild(new Text(value));
    }

    get selected() {
        return this._selected;
    }

    /**
     * HTML 4.10.10: setting an option's selectedness to true in a single select sets every other option's to false;
     * either way the option then asks for a reset, which runs the select's selectedness setting algorithm.
     */
    set selected(value) {
        this._selected = !!value;
        const select = this.ownerSelect();
        if (select === null) return;
        if (this._selected) select.selectOnly(this);
        select.runSelectednessSetting();
    }

    /** Makes `option` the only selected option of this select (null selects none). */
    selectOnly(option) {
        for (const candidate of this.options) candidate._selected = candidate === option;
    }

    /**
     * HTML 4.10.7, the selectedness setting algorithm of a single select of display size 1: with nothing selected the
     * first option that is not disabled is selected; with more than one, only the last one stays selected.
     */
    runSelectednessSetting() {
        const options = this.options;
        const selected = options.filter((option) => option._selected);
        if (!selected.length) {
            const first = options.find((option) => !optionDisabled(option));
            if (first) first._selected = true;
        } else if (selected.length > 1) {
            const last = selected[selected.length - 1];
            for (const option of selected) option._selected = option === last;
        }
    }

    /**
     * A browser's `value`: a select reads the value of its first selected option ("" when none is), an option without
     * a `value` attribute reads its text with ASCII whitespace stripped and collapsed, and a textarea reads its text
     * until a script sets its value. Setting a select's value deselects every option and selects the first one whose
     * value matches, if any (no reset runs, so an unmatched value leaves nothing selected: "" and -1).
     */
    get value() {
        if (this.isSelect) {
            const option = this.options.find((candidate) => candidate._selected);
            return option === undefined ? "" : option.value;
        }
        if (this._value !== undefined) return this._value;
        if (this.tagName === "option") return this.textContent.replace(/[\t\n\f\r ]+/g, " ").trim();
        if (this.tagName === "textarea") return this.textContent;
        return "";
    }

    set value(value) {
        const text = String(value);
        if (!this.isSelect) {
            this._value = text;
            return;
        }
        const options = this.options;
        for (const option of options) option._selected = false;
        const match = options.find((option) => option.value === text);
        if (match) match._selected = true;
    }

    get selectedIndex() {
        if (!this.isSelect) return -1;
        return this.options.findIndex((option) => option._selected);
    }

    /** Indexes the list of options (not the children): every option deselected, then the one at the index selected. */
    set selectedIndex(index) {
        if (!this.isSelect) return;
        const options = this.options;
        for (const option of options) option._selected = false;
        const at = Number(index);
        if (Number.isInteger(at) && at >= 0 && at < options.length) options[at]._selected = true;
    }

    appendChild(node) {
        // a browser moves the node out of its previous parent rather than copying it (the page relies on this to move
        // the QR the stub drew into the container it publishes)
        if (node.parent) node.parent.removeChild(node);
        node.parent = this;
        this.childNodes.push(node);
        const select = this.selectFor(node);
        if (select !== null) {
            // an inserted option whose selectedness is true takes the selection of a single select, then the
            // selectedness setting algorithm runs because the list of options changed
            const inserted = node.tagName === "option" ? [node] : node.children.filter((option) => option.tagName === "option");
            const chosen = inserted.filter((option) => option._selected);
            if (chosen.length) select.selectOnly(chosen[chosen.length - 1]);
            select.runSelectednessSetting();
        }
        return node;
    }

    removeChild(node) {
        const index = this.childNodes.indexOf(node);
        if (index < 0) throw new Error("NotFoundError: the node to be removed is not a child of this node");
        this.childNodes.splice(index, 1);
        node.parent = null;
        // a detached option keeps its own selectedness, which is what lets a re-appended option take the selection back;
        // the select runs the selectedness setting algorithm, so removing the selected option selects the first
        // remaining option that is not disabled
        const select = this.selectFor(node);
        if (select !== null) select.runSelectednessSetting();
        return node;
    }

    removeAllChildren() {
        for (const node of this.childNodes.slice()) this.removeChild(node);
    }

    addEventListener(type, listener) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(listener);
    }

    // the page only ever clears a container with innerHTML; anything else would be a way for server text to become
    // markup, so every assignment is recorded and the checks below look for a non-empty one
    set innerHTML(value) {
        this.innerHTMLWrites.push(String(value));
        this.removeAllChildren();
    }

    // nothing here serialises markup, so a page that reads innerHTML is told rather than handed a made-up answer
    get innerHTML() {
        throw new Error("the fake DOM does not serialise innerHTML; the page must not depend on reading it");
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
// HTML 13.1.2: raw text elements (content is text, nothing decoded) and escapable raw text elements (RCDATA: text with
// character references decoded); neither ever contains elements
const RAW_TEXT = new Set(["script", "style"]);
const RCDATA = new Set(["textarea", "title"]);

const NAMED_REFERENCES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };

/** Decodes the character references the page could use (numeric ones and a few named ones); others stay as written. */
function decodeReferences(text) {
    return text.replace(/&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(amp|lt|gt|quot|apos|nbsp));/g, (whole, decimal, hex, name) => {
        if (name) return NAMED_REFERENCES[name];
        const code = decimal ? Number(decimal) : parseInt(hex, 16);
        return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "�";
    });
}

/** The attributes of one start tag by name: `data-id="x"` is an attribute named `data-id`, never one named `id`. */
function tagAttributes(attributes) {
    const found = new Map();
    for (const match of attributes.matchAll(/([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
        const [, rawName, doubleQuoted, singleQuoted, unquoted] = match;
        const name = rawName.toLowerCase();
        // a duplicate attribute is a parse error and is dropped: the first occurrence is the attribute
        if (found.has(name)) continue;
        const value = doubleQuoted !== undefined ? doubleQuoted
            : singleQuoted !== undefined ? singleQuoted : unquoted !== undefined ? unquoted : "";
        found.set(name, decodeReferences(value));
    }
    return found;
}

/**
 * Parses the markup into elements and text nodes, nested as the markup nests them (so a select owns its options),
 * with the state the markup gives them (hidden, disabled, selected, value, class). Returns the declared ids (the first
 * element with a non-empty id wins, as `document.getElementById` answers in a browser), the script elements in
 * document order, and the root.
 */
function parseMarkup(markup) {
    // HTML 13.2.3.5: the input stream's CR LF and lone CR become LF before tokenisation
    markup = markup.replace(/\r\n?/g, "\n");
    const ids = new Map();
    const scripts = [];
    const root = new Element("#document");
    const stack = [root];
    const current = () => stack[stack.length - 1];
    // HTML 13.2.6.4.7: a newline right after a `<pre>` or `<listing>` start tag is dropped
    let dropNewline = null;
    const appendText = (raw) => {
        const text = dropNewline !== null && dropNewline === current() && raw.startsWith("\n") ? raw.slice(1) : raw;
        dropNewline = null;
        if (text) current().appendChild(new Text(decodeReferences(text)));
    };
    // a comment (to `-->`, or to the end when unterminated), a doctype or other `<!` declaration, or a tag
    const token = /<!--[\s\S]*?(?:-->|$)|<![^>]*>|<(\/?)([a-zA-Z][^\t\n\f\r />]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
    let cursor = 0;
    let match;
    while ((match = token.exec(markup)) !== null) {
        appendText(markup.slice(cursor, match.index));
        cursor = token.lastIndex;
        if (match[2] === undefined) continue; // a comment or a declaration: not markup
        const tag = match[2].toLowerCase();
        if (match[1] === "/") {
            for (let i = stack.length - 1; i > 0; i--) {
                if (stack[i].tagName === tag) {
                    stack.length = i;
                    break;
                }
            }
            continue;
        }
        // the implied end tags of the elements the page uses: a new option closes an open option, a new optgroup closes
        // an open option and optgroup, a new li closes an open li
        if ((tag === "option" || tag === "optgroup") && current().tagName === "option") stack.pop();
        if (tag === "optgroup" && current().tagName === "optgroup") stack.pop();
        if (tag === "li" && current().tagName === "li") stack.pop();

        const attributes = tagAttributes(match[3]);
        const element = new Element(tag);
        element.attributes = attributes;
        element.hidden = attributes.has("hidden");
        element.disabled = attributes.has("disabled");
        element.checked = attributes.has("checked");
        element._selected = attributes.has("selected");
        if (attributes.has("class")) element.className = attributes.get("class");
        if (attributes.has("value") && tag !== "textarea" && tag !== "select") element._value = attributes.get("value");
        current().appendChild(element);
        const id = attributes.get("id");
        if (id !== undefined && id !== "" && !ids.has(id)) ids.set(id, element);

        if (RAW_TEXT.has(tag) || RCDATA.has(tag)) {
            // everything up to the element's own end tag is text: a tag inside a textarea, a title, a script or a
            // style is never an element (the containing element and its attributes are kept)
            const end = new RegExp("</" + tag + "(?=[\\t\\n\\f\\r />])", "gi");
            end.lastIndex = cursor;
            const found = end.exec(markup);
            const stop = found ? found.index : markup.length;
            let content = markup.slice(cursor, stop);
            // HTML 13.2.6.4.7: a newline right after a `<textarea>` start tag is dropped
            if (tag === "textarea" && content.startsWith("\n")) content = content.slice(1);
            if (content) element.appendChild(new Text(RCDATA.has(tag) ? decodeReferences(content) : content));
            const close = found ? markup.indexOf(">", stop) : -1;
            cursor = close < 0 ? markup.length : close + 1;
            token.lastIndex = cursor;
            if (tag === "script") scripts.push(element);
            continue;
        }
        // a `/` before `>` does not close a non-void HTML element: it is parsed as an open tag
        if (!VOID.has(tag)) stack.push(element);
        if (tag === "pre" || tag === "listing") dropNewline = element;
    }
    appendText(markup.slice(cursor));
    return { ids, scripts, root };
}

/** The declared ids of a piece of markup (see parseMarkup). */
const markupElements = (markup) => parseMarkup(markup).ids;

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
const ATTACKER = "https://attacker.example";

const CONFIGURATIONS = {
    mdl: { format: "ldp_vc" },
    demo: { format: "ldp_vc" },
    farmer: { format: "ldp_vc" },
    // an ISO/IEC 18013-5 configuration, which the compatibility surface cannot issue (D5)
    mdoc: { format: "mso_mdoc" },
};

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
    // RFC 8414 section 3.1: the path's terminating "/" (one) is removed
    return url.origin + "/.well-known/" + suffix + url.pathname.replace(/\/$/, "");
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
 * Opens the page: the markup's elements, the inline scripts evaluated against them, and the requests it makes on load
 * (the configuration document and the demo-subject list; the wallet's metadata is read when it redeems an offer).
 * Never throws: a page whose script throws reports it in `scriptError`, as a browser reports it in the console.
 *
 * @param demo the answer to `GET /offer/demo-subjects`: a JSON value, a raw string, `false` for a 404, or `null` for a
 *             fetch that throws
 * @param options the page source (`html`), the configurations the page's own document lists (`configurations`), the
 *                issuer metadata documents by issuer (`issuerMetadata`), the authorization server documents by server
 *                (`asMetadata`), the answer to `POST /pre-authorized-data` (`offer`, or `offers` consumed one per
 *                click, the last one repeating) and a promise it waits for before answering (`offerGate`), the answers
 *                to the by-reference offer fetch (`offerFetches`, an entry of `"throw"` being a fetch that rejects),
 *                the `token`, `nonce` and `credential` answers of the page's wallet, a promise the issuer metadata
 *                GET waits for (`metadataGate`), redirects by URL or by `"METHOD URL"` (`redirects`: `{ status,
 *                location }`), the page's own URL (`pageUrl`) and the issuer identifier its own document names
 *                (`ownIssuer`)
 */
function openPage(demo, options = {}) {
    const source = options.html === undefined ? html : options.html;
    const { ids: elements, scripts } = parseMarkup(source);
    const created = [];
    const requests = [];
    const missingIds = [];

    const document = {
        // a browser has no element for an id the markup does not declare; returning an invented one let page bugs pass
        getElementById(id) {
            const element = elements.get(String(id));
            if (element === undefined) missingIds.push(id);
            return element === undefined ? null : element;
        },
        createElement(tag) {
            const element = new Element(String(tag).toLowerCase());
            created.push(element);
            return element;
        },
        createTextNode(data) {
            return new Text(data);
        },
    };

    const answer = (status, body) => ({
        status,
        text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    });

    const pageUrl = new URL(options.pageUrl || DOMAIN + "/v1/certify/offer/");
    const ownMetadata = {
        credential_issuer: options.ownIssuer || LEGACY_ISSUER,
        credential_configurations_supported: options.configurations || CONFIGURATIONS,
    };
    const redirects = new Map(Object.entries(options.redirects || {}));
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

    /** The answer the stack gives to one request (no redirect involved). */
    const respond = async (method, target) => {
        // OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section 3: the documents of the offer's issuer and of its
        // authorization server, each at its well-known location
        if (method === "GET" && issuerDocuments.has(target)) {
            if (options.metadataGate) await options.metadataGate;
            return answer(200, issuerDocuments.get(target));
        }
        if (method === "GET" && asDocuments.has(target)) return answer(200, asDocuments.get(target));
        // the page's own configuration list, loaded from its own surface
        if (method === "GET" && target === "/v1/certify/.well-known/openid-credential-issuer") return answer(200, ownMetadata);
        if (method === "GET" && target === "/v1/certify/offer/demo-subjects") {
            if (demo === null) throw new TypeError("fetch failed");
            if (demo === false) return answer(404, "not found");
            return answer(200, demo);
        }
        // the page fetches the document a by-reference offer names (an absolute URL, or a path on its own origin)
        if (method === "GET" && /^https?:\/\/[^/]+\/v1\/certify\/credential-offer-data\//.test(target)
            && [new URL(OFFER_DOCUMENT).origin, pageUrl.origin].includes(new URL(target).origin)) {
            const next = nextOfferFetch();
            if (next === "throw") throw new TypeError("fetch failed");
            return answer(next.status, next.body);
        }
        if (method === "POST" && target === "/v1/certify/pre-authorized-data") {
            if (options.offerGate) await options.offerGate;
            return answer(200, nextOffer());
        }
        if (method === "POST" && tokenEndpoints.has(target)) return answer(tokenAnswer.status, tokenAnswer.body);
        if (method === "POST" && nonceEndpoints.has(target)) return answer(nonceAnswer.status, nonceAnswer.body);
        if (method === "POST" && credentialEndpoints.has(target)) return answer(credentialAnswer.status, credentialAnswer.body);
        return answer(404, "not found");
    };

    /**
     * A browser's fetch, as far as the page depends on it: every request is recorded, and a 3xx with a Location (from
     * `options.redirects`) is handled by the request's redirect mode as the Fetch standard's HTTP-redirect fetch does.
     */
    const fetch = async (url, init = {}) => {
        const mode = init.redirect === undefined ? "follow" : init.redirect;
        let method = (init.method || "GET").toUpperCase();
        let headers = Object.assign({}, init.headers || {});
        let body = init.body;
        let target = String(url);
        let redirectedFrom;
        for (let hop = 0; ; hop++) {
            const form = body instanceof URLSearchParams ? body : undefined;
            requests.push({
                method,
                url: target,
                headers: Object.assign({}, headers),
                body: form ? form.toString() : body,
                form: form ? Object.fromEntries(form.entries()) : undefined,
                redirect: mode,
                redirectedFrom,
            });
            const redirect = redirects.get(method + " " + target) || redirects.get(target);
            if (redirect === undefined) return respond(method, target);
            // the answer is a redirect
            if (mode === "error") throw new TypeError("Failed to fetch: the response redirected and the redirect mode is \"error\"");
            if (mode === "manual") return { status: 0, type: "opaqueredirect", text: async () => "" };
            if (hop >= 20) throw new TypeError("Failed to fetch: too many redirects");
            const from = new URL(target, pageUrl);
            const next = new URL(redirect.location, from);
            // 301 and 302 turn a POST into a GET, 303 turns anything but GET and HEAD into one; the body goes with it
            if (((redirect.status === 301 || redirect.status === 302) && method === "POST")
                || (redirect.status === 303 && method !== "GET" && method !== "HEAD")) {
                method = "GET";
                body = undefined;
                for (const name of Object.keys(headers)) {
                    if (/^content-(type|encoding|language|location)$/i.test(name)) delete headers[name];
                }
            }
            // a hop to another origin drops the Authorization header (HTTP-redirect fetch, step 13)
            if (next.origin !== from.origin) {
                for (const name of Object.keys(headers)) if (/^authorization$/i.test(name)) delete headers[name];
            }
            redirectedFrom = target;
            target = next.href;
        }
    };

    // the real library draws a QR into the container it is given; this stub appends a stand-in whose src names the
    // encoded text, so a check can say which offer's QR is where
    class QRCode {
        constructor(container, settings) {
            const image = document.createElement("img");
            image.src = "qr:" + settings.text;
            image.alt = "QR code";
            container.appendChild(image);
        }
    }
    QRCode.CorrectLevel = { L: 1, M: 2, Q: 3, H: 4 };

    const context = vm.createContext({
        location: { href: pageUrl.href, origin: pageUrl.origin, protocol: pageUrl.protocol, pathname: pageUrl.pathname },
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
    // a browser runs every inline script (no src) in document order; the `src` scripts are the QRCode and Cbor stubs
    const inline = scripts.filter((script) => !script.attributes.has("src"));
    // a page that looks up an id the markup does not declare throws here, as it does in a browser; the checks report it
    let scriptError = inline.length ? null : new Error("the page has no inline script");
    for (const script of inline) {
        try {
            vm.runInContext(script.textContent, context, { filename: "static/offer/index.html" });
        } catch (error) {
            if (scriptError === null) scriptError = error;
        }
    }

    const posts = () => requests.filter((request) => request.method === "POST");
    const page = {
        el: (id) => document.getElementById(id),
        fetch,
        created,
        requests,
        missingIds,
        scriptError,
        /** Lets every pending promise of the page's load finish. */
        async settle() {
            for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done));
        },
        /** Presses a control and returns the POSTs the press made. */
        async press(id) {
            const before = posts().length;
            const button = page.el(id);
            if (button === null) {
                check(`the page has the control the checks press (#${id})`, false, `the markup declares no #${id}`);
                return [];
            }
            await button.fire("click");
            return posts().slice(before);
        },
        /** Presses "Create offer" and returns the parsed body of the POST it made (an empty object, and a failed
         *  check, when it made none). */
        async createOffer() {
            const made = await page.press("create");
            if (!made.length) {
                check("the page creates an offer when Create offer is pressed", false, "it made no POST");
                return {};
            }
            return JSON.parse(made[made.length - 1].body);
        },
        /** Presses the in-page wallet button ("Run the pre-authorized code flow here"). */
        async runWallet() {
            await page.press("wallet");
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

/** The requests that carry any of the secrets anywhere (URL, body or headers). */
const carrying = (requests, secrets) => requests.filter((request) => secrets.some((secret) =>
    [request.url, request.body === undefined ? "" : String(request.body), JSON.stringify(request.headers)]
        .some((part) => part.includes(secret))));

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

/**
 * Creates an offer whose grant asks for a transaction code, then runs the wallet against the given documents, and
 * asserts that the redemption was refused before anything secret left the page: no POST at all, neither the
 * pre-authorized code, the transaction code nor an access token in any request, and no request to the attacker's host.
 */
async function refusedRedemption(label, setup) {
    const code = "code-secret-" + label.replace(/[^a-z0-9]+/gi, "-");
    const document = setup.document ? setup.document(code) : offerDocument(setup.offerIssuer || OID4VCI_ISSUER, "demo", code, TX_CODE);
    const page = openPage({ subjects: [] }, Object.assign({ offers: [offerByValue("refused", document)] }, setup.options));
    await page.settle();
    const el = page.el;
    el("subject").value = "refused-subject";
    el("txCode").value = "8642";
    await page.createOffer();
    check(`${label}: the offer is published and the wallet offered`, el("wallet").disabled === false);
    const from = page.requests.length;
    await page.runWallet();
    const sent = page.requests.slice(from);
    equal(`${label}: the wallet made no POST (no token, nonce or credential request)`,
        sent.filter((request) => request.method !== "GET").map((request) => request.url), []);
    equal(`${label}: neither the pre-authorized code, the transaction code nor an access token is sent anywhere`,
        carrying(sent, [code, "8642", "at-f18"]).map((request) => request.method + " " + request.url), []);
    equal(`${label}: nothing is sent to a host the checked metadata did not vouch for`,
        sent.filter((request) => request.url.includes("attacker.example")).map((request) => request.method + " " + request.url), []);
    check(`${label}: the refusal is reported`, el("walletStatus").className.includes("bad")
        && el("walletStatus").textContent.includes(setup.reason), el("walletStatus").textContent);
    check(`${label}: the wallet can be pressed again`, el("wallet").disabled === false);
    return { page, sent };
}

/* ---------------------------------------------------------------- checks */

process.on("unhandledRejection", (reason) => {
    check("no promise of the page or the harness rejects unhandled", false, String(reason && reason.stack ? reason.stack : reason));
    process.exitCode = 1;
});
process.on("uncaughtException", (error) => {
    check("no exception escapes the page or the harness", false, String(error && error.stack ? error.stack : error));
    process.exitCode = 1;
});

try {

// 1. the CSS rule the labels depend on: the page's own `label { display: block }` beats the UA's `[hidden]` rule
await section("1. [hidden] rule", async () => {
    check("[hidden] is display:none !important in the page's stylesheet",
        /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(html));
});

// 2. the state a deployment without demo subjects shows
await section("2. initial state", async () => {
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
});

// 3. everything that is not a well-formed list leaves the page exactly as it was
for (const [name, demo] of [
    ["empty list", { subjects: [] }],
    ["404", false],
    ["a fetch that throws", null],
    ["a list that is not JSON", "<html>not json</html>"],
    ["subjects is not an array", { subjects: {} }],
    ["label is a number", { subjects: [{ id: "x", label: 42, credential_configuration_ids: [] }] }],
    ["an id that is not a subject id", { subjects: [{ id: "bad id", label: "Bad", credential_configuration_ids: [] }] }],
    ["an id with markup", { subjects: [{ id: "<script>", label: "Bad", credential_configuration_ids: [] }] }],
    ["a configuration id that is not a string", { subjects: [{ id: "x", label: "X", credential_configuration_ids: [1] }] }],
    ["one bad entry among good ones", { subjects: [SUBJECTS[0], { id: "x", label: 42, credential_configuration_ids: [] }] }],
]) {
    await section(`3. ${name}`, () => unchanged(name, demo));
}

// 4. the dropdown with configured subjects
await section("4. demo subjects", async () => {
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
    el("subject").value = "typed-9";
    equal("other: the offer sends the typed id", (await page.createOffer()).subject, "typed-9");

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
});

// 5. a label is display text, whatever it contains
await section("5. labels are text", async () => {
    const label = '<img src=x onerror=alert(1)> "quoted" <b>bold</b>';
    const page = openPage({ subjects: [{ id: "evil-1", label, credential_configuration_ids: [] }] });
    await page.settle();
    equal("a label with markup becomes an option's text", options(page), [
        ["evil-1", `${label} (evil-1)`],
        ["", "Other (type a subject id)"],
    ]);
    const images = page.createdTags().filter((tag) => tag === "img");
    equal("no element was built from the label", images, []);
    equal("no label reached innerHTML", page.innerHTMLOfEverything().filter((written) => written !== ""), []);
    check("the label is text on the option, not markup",
        page.el("subjectChoice").children[0]?.textContent.includes("<img src=x onerror=alert(1)>"));
});

// 6. a subject configured for another configuration leaves the page as it was: the dropdown hidden, the typed field and
//    the original claims label in place (this is the state a deployment whose subjects name other configurations shows,
//    not a reload: the page never reloads itself)
await section("6. subjects for another configuration", async () => {
    const page = openPage({ subjects: [{ id: "only-1", label: "Only", credential_configuration_ids: ["farmer"] }] });
    await page.settle();
    equal("a configuration with no subject hides the dropdown again", page.el("subjectChoice").hidden, true);
    equal("and shows the typed field", page.el("subject").hidden, false);
    equal("and restores the claims label", page.el("claimsLabel").textContent, CLAIMS_LABEL);
});

// 7. the markup parser and the DOM rules the page depends on
await section("7. markup parser", async () => {
    const parsed = markupElements(`<div id="first"><!-- <span id="in-a-comment"> --><script>var trap = '<b id="in-a-script">';</script>` +
        `<style>#in-a-style { color: red }</style><button data-id="not-an-id">x</button><span id="first">y</span></div>`);
    equal("an attribute named data-id is not an id", parsed.has("not-an-id"), false);
    equal("an id inside an HTML comment is not declared", parsed.has("in-a-comment"), false);
    equal("raw text inside a script is not markup", parsed.has("in-a-script"), false);
    equal("raw text inside a style is not markup", parsed.has("in-a-style"), false);
    equal("the first element with an id wins, as in a browser", parsed.get("first") && parsed.get("first").tagName, "div");

    // RCDATA (textarea, title) and raw text (script, style): the content is text, the element and its attributes stay
    const { ids, scripts } = parseMarkup(`<title id="t">A &amp; B <b id="in-a-title">x</b></title>` +
        `<textarea id="area" hidden><button id="in-a-textarea">x</button> &lt;ok&gt;</textarea>` +
        `<script id="s" data-x="1">if (a < b) { document.write('<p id="in-script">') }</script>` +
        `<style id="css" media="print">p { color: red }</style><p id="after">after</p>`);
    equal("an element inside a textarea is text, not an element", ids.has("in-a-textarea"), false);
    equal("an element inside a title is text, not an element", ids.has("in-a-title"), false);
    equal("an element written by a script's text is not an element", ids.has("in-script"), false);
    equal("the textarea itself and its attributes are kept",
        [ids.get("area") && ids.get("area").tagName, ids.get("area") && ids.get("area").hidden], ["textarea", true]);
    equal("a textarea's value is its text, character references decoded (RCDATA)",
        ids.get("area") && ids.get("area").value, '<button id="in-a-textarea">x</button> <ok>');
    equal("a title's text decodes character references and keeps tags as text",
        ids.get("t") && ids.get("t").textContent, 'A & B <b id="in-a-title">x</b>');
    equal("a script keeps its attributes and its raw text",
        [scripts.length, scripts[0] && scripts[0].attributes.get("data-x"), scripts[0] && scripts[0].textContent],
        [1, "1", "if (a < b) { document.write('<p id=\"in-script\">') }"]);
    equal("a style element and its attributes are kept",
        [ids.get("css") && ids.get("css").attributes.get("media"), ids.get("css") && ids.get("css").textContent], ["print", "p { color: red }"]);
    equal("markup after a raw text element is parsed again", ids.get("after") && ids.get("after").textContent, "after");

    // a duplicate attribute keeps its first occurrence (the second is a parse error and is dropped)
    const duplicates = markupElements(`<span id="first-id" id="second-id" class="a" class="b"></span>`);
    equal("a duplicate id attribute keeps the first value", [duplicates.has("first-id"), duplicates.has("second-id")], [true, false]);
    equal("any duplicate attribute keeps the first value", duplicates.get("first-id") && duplicates.get("first-id").className, "a");
    equal("an empty id is not an id", markupElements(`<span id="">x</span>`).has(""), false);

    // textContent is the text of every descendant, in tree order
    const nested = markupElements(`<div id="outer">a<span>b<i>c</i></span>d</div>`);
    equal("textContent reads every descendant's text", nested.get("outer") && nested.get("outer").textContent, "abcd");
    const options = parseMarkup(`<select id="s"><option value="1">one<option value="2" selected>two</select>`).ids.get("s");
    equal("a new option closes the open one, and a selected attribute selects it",
        [options && options.options.length, options && options.value], [2, "2"]);

    const cleared = new Element("div");
    cleared.textContent = "old text";
    cleared.appendChild(new Element("span"));
    cleared.innerHTML = "";
    equal("innerHTML = \"\" clears the text and the children", [cleared.textContent, cleared.childNodes.length], ["", 0]);

    const disabledControl = new Element("button");
    let clicks = 0;
    disabledControl.addEventListener("click", () => { clicks++; });
    disabledControl.disabled = true;
    await disabledControl.fire("click");
    equal("a disabled control does not dispatch a click", clicks, 0);
});

// 7b. F-18 round 2: the exact mutation that passed the previous harness. The real Create button is renamed to `data-id`
//     and a button carrying id="create" is hidden inside a textarea (and, separately, a title): a browser has no #create
//     element, so the page's script throws, and the harness must see the same
await section("7b. markup inside RCDATA is not an element", async () => {
    const realButton = '<button id="create">Create offer</button>';
    for (const [where, mutation] of [
        ["a textarea", '<textarea hidden><button id="create"></button></textarea><button data-id="create">Create offer</button>'],
        ["the title", null],
    ]) {
        const mutated = mutation === null
            ? html.replace("<title>Credential offer</title>", '<title>Credential offer<button id="create"></button></title>')
                .replace(realButton, '<button data-id="create">Create offer</button>')
            : html.replace(realButton, mutation);
        check(`mutation inside ${where}: the page copy was mutated`, mutated !== html && !mutated.includes(realButton));
        const page = openPage({ subjects: [] }, { html: mutated });
        equal(`mutation inside ${where}: #create is not an element`, page.el("create"), null);
        check(`mutation inside ${where}: the page's script fails on the missing #create, as in a browser`,
            page.scriptError !== null && /addEventListener|null/.test(String(page.scriptError && page.scriptError.message)),
            page.scriptError && String(page.scriptError.message));
    }
});

// 8. a <select>'s selection is per-option selectedness, as in a browser (HTML selectedness setting algorithm)
await section("8. select semantics", async () => {
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

    // option.selected: setting it true deselects every other option of a single select; false asks for a reset
    const single = new Element("select");
    const p = option("p"), q = option("q"), r = option("r");
    single.appendChild(p);
    single.appendChild(q);
    single.appendChild(r);
    r.selected = true;
    equal("option.selected = true selects that option alone",
        [single.value, [p, q, r].map((entry) => entry.selected)], ["r", [false, false, true]]);
    p.selected = true;
    equal("selecting an earlier option deselects the later one", [single.value, [p, q, r].map((entry) => entry.selected)],
        ["p", [true, false, false]]);
    p.selected = false;
    equal("deselecting the only selected option resets to the first option that is not disabled",
        [single.value, single.selectedIndex], ["p", 0]);

    // disabled options are skipped by the selectedness setting algorithm (but a script can still select one)
    const guarded = new Element("select");
    const off = option("off"), on = option("on"), last = option("last");
    off.disabled = true;
    guarded.appendChild(off);
    equal("a select whose only option is disabled has nothing selected", [guarded.value, guarded.selectedIndex], ["", -1]);
    guarded.appendChild(on);
    guarded.appendChild(last);
    equal("the first option that is not disabled is selected", guarded.value, "on");
    guarded.value = "last";
    guarded.removeChild(last);
    equal("removing the selected option selects the first option that is not disabled", [guarded.value, guarded.selectedIndex], ["on", 1]);
    guarded.value = "off";
    equal("a script can select a disabled option by value", guarded.value, "off");

    // selectedIndex indexes the list of options, not the children (a stray element child is not an option)
    const mixed = new Element("select");
    mixed.appendChild(option("m1"));
    mixed.appendChild(new Element("hr"));
    mixed.appendChild(option("m2"));
    mixed.selectedIndex = 1;
    equal("selectedIndex = 1 selects the second option, not the second child", [mixed.value, mixed.selectedIndex], ["m2", 1]);
    mixed.selectedIndex = 7;
    equal("an index past the options selects nothing", [mixed.value, mixed.selectedIndex], ["", -1]);
});

// 9. the page against that DOM: no invented elements, and an unofferable select value takes the Other path
await section("9. no invented elements", async () => {
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
});

// 10. a subject whose label repeats its id is shown as the id alone (F-18 nit 6), and so is a subject with no label
await section("10. label equal to the id", async () => {
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
});

// 11. the published QR: the stub draws into the container it is given, and a new offer replaces the old QR
await section("11. QR", async () => {
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
    equal("qr: the placeholder text is gone", page.el("qr").textContent, "");
    await page.createOffer();
    equal("qr: the container holds the current offer's QR and no other",
        qrImages(page), ["qr:" + deepLink("qr-two")]);
});

// 12. an offer by reference: the page fetches the document its deep link names, and publishes it
await section("12. by reference", async () => {
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
});

// 13. a replacement the page cannot complete leaves the previous offer, its document, its QR and the wallet's offer in
//     place — after a first offer has been published, which is the state these refusals have to preserve. The same
//     rule (OpenID4VCI 1.0 section 4.1.1: credential_issuer, credential_configuration_ids, a pre-authorized_code) holds
//     for an offer that came by reference and one that came by value
const withoutIssuer = offerDocument(OID4VCI_ISSUER, "demo", "broken-code");
delete withoutIssuer.credential_issuer;
const BROKEN_DOCUMENTS = [
    ["a document without the pre-authorized grant", { credential_issuer: OID4VCI_ISSUER, credential_configuration_ids: ["demo"], grants: {} }],
    ["a grant without a pre-authorized_code", Object.assign(offerDocument(OID4VCI_ISSUER, "demo", "x"),
        { grants: { [GRANT]: { tx_code: TX_CODE } } })],
    ["an empty pre-authorized_code", offerDocument(OID4VCI_ISSUER, "demo", "")],
    ["a document without credential_issuer", withoutIssuer],
    ["empty credential_configuration_ids", Object.assign(offerDocument(OID4VCI_ISSUER, "demo", "broken-code"), { credential_configuration_ids: [] })],
    ["a tx_code that is not an object", offerDocument(OID4VCI_ISSUER, "demo", "broken-code", "1234")],
    ["a document that is not an object", "not an offer"],
];
for (const [label, offers, fetches] of [
    ["404", [offerByReference("kept"), offerByReference("broken")], [{ status: 200, body: REFERRED_OFFER }, { status: 404, body: "not found" }]],
    ["a fetch that throws", [offerByReference("kept"), offerByReference("broken")], [{ status: 200, body: REFERRED_OFFER }, "throw"]],
    ...BROKEN_DOCUMENTS.map(([name, document]) => [`by reference, ${name}`, [offerByReference("kept"), offerByReference("broken")],
        [{ status: 200, body: REFERRED_OFFER }, { status: 200, body: document }]]),
    ...BROKEN_DOCUMENTS.map(([name, document]) => [`by value, ${name}`,
        [offerByValue("kept", REFERRED_OFFER), offerByValue("broken", document)], []]),
    ["by value, a null credential_offer", [offerByValue("kept", REFERRED_OFFER), offerByValue("broken", null)], []],
]) {
    await section(`13. ${label}`, async () => {
        const page = openPage({ subjects: [] }, { offers, offerFetches: fetches });
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
        // a rejected fetch reaches the page's outer catch, a refused one its by-reference message and an unusable
        // document the common validation: either way the page reports the failure and publishes nothing
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
    });
}

// 14. a first offer the page cannot publish leaves nothing published, and its disabled wallet dispatches nothing — by
//     reference and by value alike
for (const [label, offers, fetches] of [
    ["by reference", [offerByReference("no-grant")], [{ status: 200, body: { credential_issuer: OID4VCI_ISSUER, credential_configuration_ids: ["demo"], grants: {} } }]],
    ["by value", [offerByValue("no-grant", { credential_issuer: OID4VCI_ISSUER, credential_configuration_ids: ["demo"], grants: {} })], []],
    ["by value without a code", [offerByValue("no-code", offerDocument(OID4VCI_ISSUER, "demo", ""))], []],
]) {
    await section(`14. first offer unusable, ${label}`, async () => {
        const page = openPage({ subjects: [] }, { offers, offerFetches: fetches });
        await page.settle();
        const el = page.el;
        el("subject").value = "no-grant-subject";
        await page.createOffer();
        check(`${label}: a document without a usable pre-authorized grant is refused`,
            el("offerStatus").className.includes("bad") && el("offerStatus").textContent.includes("not a usable pre-authorized code offer"),
            el("offerStatus").textContent);
        equal(`${label}: and nothing is published`, [el("offerUri").hidden, el("offerDoc").hidden, el("wallet").disabled], [true, true, true]);
        equal(`${label}: and no QR is drawn`, qrImages(page), []);
        const before = page.requests.length;
        await page.runWallet();
        equal(`${label}: a disabled wallet button dispatches no click`, page.requests.slice(before), []);
    });
}

// 15. the page's own wallet: the metadata documents, the token form, the nonce, a real P-256 proof, the credential
await section("15. wallet", async () => {
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
});

// 16. section 6.1: the transaction code is sent for exactly the offers whose grant names one, with the value entered
//     for that offer
await section("16. tx_code", async () => {
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
    {
        // the grant asks for a transaction code, but none was entered when the offer was created: the token endpoint
        // would spend the pre-authorized code on a request that cannot succeed (gap G36), so nothing is sent
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("wallet-tx-missing", offerDocument(OID4VCI_ISSUER, "demo", "code-tx-missing", TX_CODE))],
        });
        await page.settle();
        const el = page.el;
        el("subject").value = "wallet-subject";
        el("txCode").value = "";
        await page.createOffer();
        el("txCode").value = "5555"; // typed afterwards: not the value this offer was created with
        const from = page.requests.length;
        await page.runWallet();
        const sent = page.requests.slice(from);
        equal("tx_code asked but not entered: nothing is sent", sent.map((request) => request.method + " " + request.url), []);
        check("tx_code asked but not entered: the refusal is reported",
            el("walletStatus").className.includes("bad") && el("walletStatus").textContent.includes("transaction code"),
            el("walletStatus").textContent);
    }
});

// 17. section 8.2: an access token that names credential identifiers is redeemed with credential_identifier
await section("17. authorization_details", async () => {
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
    page.el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    checkCredentialRequest("authorization_details", credentialRequest(page), {
        audience: OID4VCI_ISSUER,
        nonce: "nonce-f18",
        credentialIdentifier: "credential-identifier-1",
    });
});

// 18. a compatibility-surface offer: its own metadata, the AS it names (itself), and aud = the issuer the offer named
await section("18. legacy offer", async () => {
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
});
await section("18b. an answer without notification_id", async () => {
    // OpenID4VCI 1.0 section 8.3: notification_id is optional, and the compatibility endpoint returns none (seen end to
    // end on the F-18 round 3 stack, where the page printed "notification id undefined")
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("wallet-no-notification", offerDocument(LEGACY_ISSUER, "demo", "code-no-notification"))],
        credential: { status: 200, body: { credentials: [{ credential: "ldp-credential" }] } },
    });
    await page.settle();
    page.el("subject").value = "wallet-subject";
    await page.createOffer();
    await page.runWallet();
    equal("no notification_id: the success names no notification id", page.el("walletStatus").textContent, "Credential issued (1)");
});

// 19. an authorization server with a path of its own: RFC 8414 puts the well-known segment between host and path
await section("19. AS with a path", async () => {
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
    page.el("subject").value = "wallet-subject";
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
});

// 20. section 7: the nonce endpoint is optional, and any 2xx from it is an answer
await section("20. nonce endpoint", async () => {
    {
        const withoutNonce = Object.assign({}, OID4VCI_DOCUMENT);
        delete withoutNonce.nonce_endpoint;
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("wallet-no-nonce", offerDocument(OID4VCI_ISSUER, "demo", "code-no-nonce"))],
            issuerMetadata: { [OID4VCI_ISSUER]: withoutNonce },
        });
        await page.settle();
        page.el("subject").value = "wallet-subject";
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
});

// 21. F-18 round 2: the transaction code is read when Create is pressed. Editing the field while the issuer has not
//     answered yet changes neither the POST nor the code this offer is redeemed with
await section("21. tx_code snapshot", async () => {
    let release;
    const gate = new Promise((done) => { release = done; });
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("snapshot", offerDocument(OID4VCI_ISSUER, "demo", "code-snapshot", TX_CODE))],
        offerGate: gate,
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "snapshot-subject";
    el("txCode").value = "1234";
    const pending = el("create").fire("click");
    await page.settle();
    check("snapshot: the offer is pending (Create disabled, nothing published)",
        el("create").disabled === true && el("offerUri").hidden === true);
    el("txCode").value = "9999"; // edited while the issuer has not answered
    release();
    await pending;
    await page.settle();
    const post = find(page, "POST", /\/pre-authorized-data$/);
    equal("snapshot: the POST carried the value read when Create was pressed", post && JSON.parse(post.body).tx_code, "1234");
    check("snapshot: the offer was published", el("wallet").disabled === false && el("offerUri").hidden === false);
    await page.runWallet();
    equalFields("snapshot: the wallet redeems with the value read when Create was pressed, not the edited one",
        tokenRequest(page) && tokenRequest(page).form, { grant_type: GRANT, "pre-authorized_code": "code-snapshot", tx_code: "1234" });
});

// 22. OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section 3.3: metadata whose identity is not the identifier it was
//     fetched for is not used, and every endpoint is an absolute URL, https unless its identifier is http. Each refusal
//     happens before the pre-authorized code, the transaction code or an access token leaves the page
await section("22a. issuer metadata names another issuer", () => refusedRedemption("issuer metadata names another issuer", {
    reason: "nothing was sent",
    options: {
        issuerMetadata: {
            [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, {
                credential_issuer: ATTACKER,
                authorization_servers: [ATTACKER],
                credential_endpoint: ATTACKER + "/credential",
                nonce_endpoint: ATTACKER + "/nonce",
            }),
        },
        asMetadata: { [AS]: AS_DOCUMENT, [ATTACKER]: { issuer: ATTACKER, token_endpoint: ATTACKER + "/token" } },
    },
}));
await section("22b. issuer metadata with a trailing slash", () => refusedRedemption("issuer metadata differs by a trailing slash", {
    reason: "nothing was sent",
    options: { issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { credential_issuer: OID4VCI_ISSUER + "/" }) } },
}));
await section("22c. AS metadata names another issuer", () => refusedRedemption("AS metadata names another issuer", {
    reason: "nothing was sent",
    options: { asMetadata: { [AS]: Object.assign({}, AS_DOCUMENT, { issuer: ATTACKER, token_endpoint: ATTACKER + "/token" }) } },
}));
await section("22d. AS metadata without issuer", () => refusedRedemption("AS metadata without an issuer", {
    reason: "nothing was sent",
    options: { asMetadata: { [AS]: Object.assign({}, AS_DOCUMENT, { issuer: undefined }) } },
}));
await section("22e. relative token endpoint", () => refusedRedemption("a relative token_endpoint", {
    reason: "token_endpoint",
    options: { asMetadata: { [AS]: Object.assign({}, AS_DOCUMENT, { token_endpoint: "/v1/certify/oauth/token" }) } },
}));
await section("22f. relative credential endpoint", () => refusedRedemption("a relative credential_endpoint", {
    reason: "credential_endpoint",
    options: { issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { credential_endpoint: "/v1/certify/oid4vci/credential" }) } },
}));
await section("22g. relative nonce endpoint", () => refusedRedemption("a relative nonce_endpoint", {
    reason: "nonce_endpoint",
    options: { issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { nonce_endpoint: "nonce" }) } },
}));
await section("22h. http credential endpoint", () => refusedRedemption("an http credential_endpoint for an https issuer", {
    reason: "credential_endpoint",
    options: { issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT,
        { credential_endpoint: "http://credentials.example/v1/certify/oid4vci/credential" }) } },
}));
await section("22i. http token endpoint", () => refusedRedemption("an http token_endpoint for an https authorization server", {
    reason: "token_endpoint",
    options: { asMetadata: { [AS]: Object.assign({}, AS_DOCUMENT, { token_endpoint: "http://credentials.example/v1/certify/oauth/token" }) } },
}));
await section("22j. http authorization server", () => refusedRedemption("an http authorization server for an https issuer", {
    reason: "authorization server",
    options: {
        issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { authorization_servers: ["http://credentials.example"] }) },
        asMetadata: { "http://credentials.example": Object.assign({}, AS_DOCUMENT,
            { issuer: "http://credentials.example", token_endpoint: "http://credentials.example/v1/certify/oauth/token" }) },
    },
}));

// 23. what the identity rules still allow: endpoints on other origins (no same-origin rule), and a local development
//     stack whose identifiers are http
await section("23. endpoints elsewhere and an http development stack", async () => {
    {
        const api = "https://api.credentials.example";
        const login = "https://login.example/realm";
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("elsewhere", offerDocument(OID4VCI_ISSUER, "demo", "code-elsewhere"))],
            issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, {
                authorization_servers: [login],
                credential_endpoint: api + "/credential",
                nonce_endpoint: api + "/nonce",
            }) },
            asMetadata: { [login]: { issuer: login, token_endpoint: "https://tokens.example/token" } },
        });
        await page.settle();
        page.el("subject").value = "elsewhere-subject";
        await page.createOffer();
        await page.runWallet();
        equal("elsewhere: the token goes to the token endpoint the checked AS metadata names",
            tokenRequest(page) && tokenRequest(page).url, "https://tokens.example/token");
        equal("elsewhere: the nonce and credential endpoints on another origin are used",
            [nonceRequest(page) && nonceRequest(page).url, credentialRequest(page) && credentialRequest(page).url],
            [api + "/nonce", api + "/credential"]);
        check("elsewhere: the credential is issued", page.el("walletStatus").textContent.includes("Credential issued"),
            page.el("walletStatus").textContent);
    }
    {
        const local = "http://127.0.0.1:28191";
        const issuer = local + "/v1/certify/oid4vci";
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("local", offerDocument(issuer, "demo", "code-local"))],
            issuerMetadata: { [issuer]: Object.assign({}, OID4VCI_DOCUMENT, {
                credential_issuer: issuer,
                authorization_servers: [local],
                credential_endpoint: issuer + "/credential",
                nonce_endpoint: issuer + "/nonce",
            }) },
            asMetadata: { [local]: { issuer: local, token_endpoint: local + "/v1/certify/oauth/token" } },
        });
        await page.settle();
        page.el("subject").value = "local-subject";
        await page.createOffer();
        await page.runWallet();
        equal("http development stack: its metadata is read at the 12.2.2 location",
            metadataRequest(page, "openid-credential-issuer") && metadataRequest(page, "openid-credential-issuer").url,
            local + "/.well-known/openid-credential-issuer/v1/certify/oid4vci");
        equal("http development stack: the http endpoints of an http identifier are used",
            [tokenRequest(page) && tokenRequest(page).url, credentialRequest(page) && credentialRequest(page).url],
            [local + "/v1/certify/oauth/token", issuer + "/credential"]);
        checkCredentialRequest("http development stack", credentialRequest(page), { audience: issuer, nonce: "nonce-f18", configurationId: "demo" });
    }
});

// 24. D5: an ISO mdoc (mso_mdoc) configuration is issued on the OpenID4VCI 1.0 surface only, so the legacy surface is
//     unavailable for it; every other format can use either surface
await section("24. mso_mdoc surface", async () => {
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("mdoc", offerDocument(OID4VCI_ISSUER, "mdoc", "code-mdoc")),
            offerByValue("ldp", offerDocument(OID4VCI_ISSUER, "demo", "code-ldp"))],
    });
    await page.settle();
    const el = page.el;
    el("subject").value = "surface-subject";
    equal("ldp_vc: both surfaces are offered and the compatibility one is the default",
        [el("surfaceLegacy").disabled, el("surface").value, el("surfaceHint").hidden], [false, "legacy", true]);

    el("configuration").value = "mdoc";
    await el("configuration").fire("change");
    equal("mso_mdoc: the legacy surface option is disabled", el("surfaceLegacy").disabled, true);
    equal("mso_mdoc: the surface is forced to /oid4vci", el("surface").value, "oid4vci");
    equal("mso_mdoc: the explanation is shown", [el("surfaceHint").hidden, el("surfaceHint").textContent], [false, MDOC_SURFACE_HINT]);
    equal("mso_mdoc: the offer targets /oid4vci", (await page.createOffer()).issuer, "oid4vci");
    await page.runWallet();
    checkCredentialRequest("mso_mdoc on /oid4vci", credentialRequest(page), { audience: OID4VCI_ISSUER, nonce: "nonce-f18", configurationId: "mdoc" });
    check("mso_mdoc on /oid4vci: the IssuerSigned view is shown", el("mdocView").hidden === false);

    // a script (not a visitor: a disabled option cannot be picked) selecting the legacy option is refused by the page
    el("surface").value = "legacy";
    const made = await page.press("create");
    equal("mso_mdoc with the legacy surface forced by a script: no offer is created", made.map((request) => request.url), []);
    check("mso_mdoc with the legacy surface forced by a script: the refusal is explained",
        el("offerStatus").className.includes("bad") && el("offerStatus").textContent.includes(MDOC_SURFACE_HINT),
        el("offerStatus").textContent);

    el("configuration").value = "demo";
    await el("configuration").fire("change");
    equal("back to ldp_vc: the legacy option is available again and the default",
        [el("surfaceLegacy").disabled, el("surface").value, el("surfaceHint").hidden], [false, "legacy", true]);
    el("surface").value = "oid4vci";
    equal("ldp_vc: /oid4vci can be chosen", (await page.createOffer()).issuer, "oid4vci");
    el("surface").value = "legacy";
    equal("ldp_vc: legacy can be chosen", (await page.createOffer()).issuer, "legacy");
});
await section("24b. mso_mdoc first", async () => {
    // a deployment whose first configuration is an mdoc: the page loads with the legacy option already unavailable
    const page = openPage({ subjects: [] }, { configurations: { aamva: { format: "mso_mdoc" }, zfarmer: { format: "ldp_vc" } } });
    await page.settle();
    const el = page.el;
    equal("mso_mdoc on load: the legacy option is disabled and /oid4vci selected",
        [el("configuration").value, el("surfaceLegacy").disabled, el("surface").value, el("surfaceHint").hidden],
        ["aamva", true, "oid4vci", false]);
});

// 25. F-18 round 3: a wallet run redeems the offer that was active when it was pressed. The reviewers' reproduction:
//     offer A (code-A, transaction code 1111) is being redeemed and waits for the issuer metadata when offer B
//     (farmer, transaction code 2222 or none) is created; the run must still send only A's code, transaction code and
//     configuration. The page disables Create while the wallet runs, so the check presses it the way a script (or the
//     round 2 page, which left it enabled) can, to exercise the snapshot itself
for (const [label, txB] of [["B with a transaction code", "2222"], ["B without a transaction code", ""]]) {
    await section(`25. concurrent replacement, ${label}`, async () => {
        let release;
        const gate = new Promise((done) => { release = done; });
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("race-a", offerDocument(OID4VCI_ISSUER, "mdoc", "code-A", TX_CODE)),
                offerByValue("race-b", offerDocument(LEGACY_ISSUER, "farmer", "code-B", txB ? TX_CODE : undefined))],
            metadataGate: gate,
        });
        await page.settle();
        const el = page.el;
        el("subject").value = "race-subject";
        el("configuration").value = "mdoc";
        await el("configuration").fire("change");
        el("txCode").value = "1111";
        const postedA = await page.createOffer();
        equal(`${label}: offer A is created for mdoc with 1111`, [postedA.credential_configuration_id, postedA.tx_code], ["mdoc", "1111"]);
        const running = el("wallet").fire("click");
        await page.settle();
        equal(`${label}: while the wallet waits for the issuer metadata, Create and the wallet are disabled`,
            [el("create").disabled, el("wallet").disabled], [true, true]);

        el("create").disabled = false; // pressed anyway
        el("configuration").value = "farmer";
        await el("configuration").fire("change");
        el("txCode").value = txB;
        const posted = await page.createOffer();
        equal(`${label}: offer B was created and published while A was being redeemed`,
            [posted.credential_configuration_id, posted.tx_code === undefined ? "" : posted.tx_code, el("offerUri").textContent],
            ["farmer", txB, deepLink("race-b")]);
        equal(`${label}: B's creation leaves Create and the wallet disabled while A's run goes on`,
            [el("create").disabled, el("wallet").disabled], [true, true]);

        release();
        await running;
        await page.settle();
        equalFields(`${label}: the token form carries A's code and A's transaction code only`,
            tokenRequest(page) && tokenRequest(page).form, { grant_type: GRANT, "pre-authorized_code": "code-A", tx_code: "1111" });
        checkCredentialRequest(`${label}: the credential request`, credentialRequest(page),
            { audience: OID4VCI_ISSUER, nonce: "nonce-f18", configurationId: "mdoc" });
        equal(`${label}: B's code and transaction code are sent nowhere`,
            carrying(page.requests.filter((request) => !/pre-authorized-data$/.test(request.url)), ["code-B", ...(txB ? [txB] : []), "null"])
                .map((request) => request.method + " " + request.url), []);
        equal(`${label}: the IssuerSigned view follows A's configuration (mso_mdoc), not B's`, el("mdocView").hidden, false);
        equal(`${label}: when the run ends, Create and the wallet (for B) are usable again`,
            [el("create").disabled, el("wallet").disabled], [false, false]);
    });
}

// 26. F-18 round 3: the wallet's requests refuse redirects. fetch's default would re-send a 307 token POST (the
//     pre-authorized code and transaction code) to another origin, and a same-origin 307 credential POST with its
//     Authorization header to a path no metadata advertised
await section("26a. the fetch stub's redirect modes", async () => {
    const page = openPage({ subjects: [] }, {
        redirects: {
            "POST https://credentials.example/a": { status: 307, location: "/b" },
            "POST https://credentials.example/c": { status: 302, location: "/d" },
            "POST https://credentials.example/e": { status: 303, location: "/f" },
            "POST https://credentials.example/g": { status: 307, location: ATTACKER + "/h" },
        },
    });
    await page.settle();
    const sent = (from) => page.requests.slice(from).map((request) => [request.method, request.url, request.body || null,
        request.headers.Authorization || null]);
    let from = page.requests.length;
    await page.fetch("https://credentials.example/a", { method: "POST", body: "x=1", headers: { Authorization: "Bearer t" } });
    equal("follow: a 307 re-sends the method, the body and (same origin) the Authorization header", sent(from), [
        ["POST", "https://credentials.example/a", "x=1", "Bearer t"], ["POST", "https://credentials.example/b", "x=1", "Bearer t"]]);
    from = page.requests.length;
    await page.fetch("https://credentials.example/c", { method: "POST", body: "x=1" });
    equal("follow: a 302 turns a POST into a GET without a body", sent(from).map((entry) => entry.slice(0, 3)), [
        ["POST", "https://credentials.example/c", "x=1"], ["GET", "https://credentials.example/d", null]]);
    from = page.requests.length;
    await page.fetch("https://credentials.example/e", { method: "POST", body: "x=1" });
    equal("follow: a 303 turns a POST into a GET without a body", sent(from).map((entry) => entry.slice(0, 3)), [
        ["POST", "https://credentials.example/e", "x=1"], ["GET", "https://credentials.example/f", null]]);
    from = page.requests.length;
    await page.fetch("https://credentials.example/g", { method: "POST", body: "x=1", headers: { Authorization: "Bearer t" } });
    equal("follow: a cross-origin 307 keeps the body and drops the Authorization header", sent(from), [
        ["POST", "https://credentials.example/g", "x=1", "Bearer t"], ["POST", ATTACKER + "/h", "x=1", null]]);
    from = page.requests.length;
    let error = null;
    try {
        await page.fetch("https://credentials.example/g", { method: "POST", body: "x=1", redirect: "error" });
    } catch (caught) {
        error = caught;
    }
    equal("error: the redirect rejects with a TypeError and nothing is requested at Location",
        [error instanceof TypeError, sent(from).map((entry) => entry[1])], [true, ["https://credentials.example/g"]]);
    from = page.requests.length;
    const manual = await page.fetch("https://credentials.example/g", { method: "POST", body: "x=1", redirect: "manual" });
    equal("manual: an opaque redirect with status 0, and nothing requested at Location",
        [manual.type, manual.status, sent(from).map((entry) => entry[1])], ["opaqueredirect", 0, ["https://credentials.example/g"]]);
});

/** Runs the wallet against a stack that answers one of its requests with a redirect; returns the page and what it sent. */
async function redirectedRun(label, redirects) {
    const code = "code-redirect-" + label.replace(/[^a-z0-9]+/gi, "-");
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("redirected", offerDocument(OID4VCI_ISSUER, "demo", code, TX_CODE))],
        redirects,
    });
    await page.settle();
    page.el("subject").value = "redirect-subject";
    page.el("txCode").value = "8642";
    await page.createOffer();
    const from = page.requests.length;
    await page.runWallet();
    const sent = page.requests.slice(from);
    check(`${label}: every wallet request refuses redirects`, sent.length > 0 && sent.every((request) => request.redirect === "error"),
        JSON.stringify(sent.map((request) => [request.method, request.url, request.redirect])));
    check(`${label}: the refusal is reported and the wallet can be pressed again`,
        page.el("walletStatus").className.includes("bad") && page.el("wallet").disabled === false, page.el("walletStatus").textContent);
    return { page, sent, code };
}

await section("26b. a cross-origin 307 on the token endpoint", async () => {
    const { sent, code } = await redirectedRun("token endpoint 307 to another origin",
        { ["POST " + TOKEN_ENDPOINT]: { status: 307, location: ATTACKER + "/token" } });
    equal("token endpoint 307: nothing reaches the redirect target", sent.filter((request) => request.url.startsWith(ATTACKER))
        .map((request) => request.method + " " + request.url), []);
    equal("token endpoint 307: the code and the transaction code went to the advertised token endpoint only",
        carrying(sent, [code, "8642"]).map((request) => request.method + " " + request.url), ["POST " + TOKEN_ENDPOINT]);
    equal("token endpoint 307: no nonce or credential request follows", [nonceRequest({ requests: sent }), credentialRequest({ requests: sent })],
        [undefined, undefined]);
});

await section("26c. a same-origin 307 on the credential endpoint", async () => {
    const elsewhere = DOMAIN + "/v1/certify/elsewhere";
    const { sent } = await redirectedRun("credential endpoint 307 on the same origin",
        { ["POST " + OID4VCI_CREDENTIAL_ENDPOINT]: { status: 307, location: "/v1/certify/elsewhere" } });
    equal("credential endpoint 307: nothing reaches the redirect target", sent.filter((request) => request.url === elsewhere)
        .map((request) => request.method + " " + request.url), []);
    equal("credential endpoint 307: the access token went to the advertised credential endpoint only",
        carrying(sent, ["at-f18"]).map((request) => request.method + " " + request.url), ["POST " + OID4VCI_CREDENTIAL_ENDPOINT]);
});

await section("26d. redirected nonce endpoint and metadata", async () => {
    const nonce = await redirectedRun("nonce endpoint 307",
        { ["POST " + OID4VCI_NONCE_ENDPOINT]: { status: 307, location: ATTACKER + "/nonce" } });
    equal("nonce endpoint 307: nothing reaches the redirect target, and no credential request follows",
        [nonce.sent.filter((request) => request.url.startsWith(ATTACKER)).length, credentialRequest({ requests: nonce.sent })], [0, undefined]);
    const metadata = await redirectedRun("issuer metadata 302",
        { [wellKnown(OID4VCI_ISSUER, "openid-credential-issuer")]: { status: 302, location: ATTACKER + "/metadata" } });
    equal("issuer metadata 302: no request after it, nothing to the redirect target",
        metadata.sent.map((request) => request.method + " " + request.url), ["GET " + wellKnown(OID4VCI_ISSUER, "openid-credential-issuer")]);
    const as = await redirectedRun("AS metadata 302",
        { [wellKnown(AS, "oauth-authorization-server")]: { status: 302, location: ATTACKER + "/as" } });
    equal("AS metadata 302: no POST, nothing to the redirect target",
        as.sent.filter((request) => request.method !== "GET" || request.url.startsWith(ATTACKER)).length, 0);
});

// 25b. F-18 round 4 (review): the other order of the race. Create is pressed for offer B while A is published, the
//      wallet is pressed for A while B is pending, and B is published mid-run: the run redeems A with A's values
//      only, both buttons stay disabled until it ends, and the next run redeems B.
for (const [label, txB] of [["Create pressed first, B with a transaction code", "2222"], ["Create pressed first, B without one", ""]]) {
    await section(`25b. ${label}`, async () => {
        const options = {
            offers: [offerByValue("race-a", offerDocument(OID4VCI_ISSUER, "mdoc", "code-A", TX_CODE)),
                offerByValue("race-b", offerDocument(LEGACY_ISSUER, "farmer", "code-B", txB ? TX_CODE : undefined))],
        };
        const page = openPage({ subjects: [] }, options);
        await page.settle();
        const el = page.el;
        el("subject").value = "race-subject";
        el("configuration").value = "mdoc";
        await el("configuration").fire("change");
        el("txCode").value = "1111";
        await page.createOffer();
        let releaseOffer, releaseMeta;
        options.offerGate = new Promise((d) => { releaseOffer = d; });
        options.metadataGate = new Promise((d) => { releaseMeta = d; });
        el("configuration").value = "farmer";
        await el("configuration").fire("change");
        el("txCode").value = txB;
        const creating = el("create").fire("click");
        await page.settle();
        equal(`${label}: wallet still enabled for A while B is pending`, el("wallet").disabled, false);
        const running = el("wallet").fire("click");
        await page.settle();
        releaseOffer();
        await creating;
        await page.settle();
        equal(`${label}: B published`, el("offerUri").textContent, deepLink("race-b"));
        equal(`${label}: create+wallet disabled while A runs`, [el("create").disabled, el("wallet").disabled], [true, true]);
        releaseMeta();
        await running;
        await page.settle();
        equalFields(`${label}: token form is A's`, tokenRequest(page) && tokenRequest(page).form,
            { grant_type: GRANT, "pre-authorized_code": "code-A", tx_code: "1111" });
        checkCredentialRequest(`${label}: credential request`, credentialRequest(page),
            { audience: OID4VCI_ISSUER, nonce: "nonce-f18", configurationId: "mdoc" });
        equal(`${label}: B secrets nowhere`, carrying(page.requests.filter((r) => !/pre-authorized-data$/.test(r.url)), ["code-B", ...(txB ? [txB] : [])])
            .map((r) => r.method + " " + r.url), []);
        equal(`${label}: re-enabled after`, [el("create").disabled, el("wallet").disabled], [false, false]);
        // then B is redeemable with B's values
        await page.runWallet();
        await page.settle();
        const forms = page.requests.filter((r) => r.method === "POST" && r.form && r.form.grant_type).map((r) => r.form);
        equalFields(`${label}: next run redeems B`, forms[forms.length - 1],
            Object.assign({ grant_type: GRANT, "pre-authorized_code": "code-B" }, txB ? { tx_code: "2222" } : {}));
    });
}
// 26e. F-18 round 4: the page's own requests refuse redirects too. The Create POST carries the transaction code, and
//      fetch's default would re-send a 307/308 POST, body and all, to wherever Location points.
for (const status of [307, 308]) {
    await section(`26e. a ${status} on the Create POST`, async () => {
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("create-redirect", offerDocument(OID4VCI_ISSUER, "demo", "code-create-redirect", TX_CODE))],
            redirects: { "POST /v1/certify/pre-authorized-data": { status, location: ATTACKER + "/capture" } },
        });
        await page.settle();
        page.el("subject").value = "redirect-subject";
        page.el("txCode").value = "1234";
        const from = page.requests.length;
        page.el("create").fire("click");
        await page.settle();
        const sent = page.requests.slice(from);
        equal(`Create ${status}: the POST refuses redirects`, sent.filter((request) => /pre-authorized-data$/.test(request.url))
            .map((request) => request.redirect), ["error"]);
        equal(`Create ${status}: nothing reaches the redirect target`, sent.filter((request) => request.url.startsWith(ATTACKER))
            .map((request) => request.method + " " + request.url), []);
        equal(`Create ${status}: the transaction code went to /pre-authorized-data only`,
            carrying(sent, ["1234"]).map((request) => request.method + " " + request.url), ["POST /v1/certify/pre-authorized-data"]);
        equal(`Create ${status}: every request of the page, the load included, refuses redirects`,
            page.requests.filter((request) => request.redirect !== "error").map((request) => request.method + " " + request.url), []);
        check(`Create ${status}: nothing is published and Create can be pressed again`,
            page.el("create").disabled === false && page.el("wallet").disabled === true, page.el("offerStatus").textContent);
    });
}

await section("26f. a redirect on the by-reference offer fetch", async () => {
    const page = openPage({ subjects: [] }, {
        offers: [offerByReference("by-ref-redirect")],
        redirects: { [OFFER_DOCUMENT + "by-ref-redirect"]: { status: 302, location: ATTACKER + "/offer" } },
    });
    await page.settle();
    page.el("subject").value = "redirect-subject";
    const from = page.requests.length;
    page.el("create").fire("click");
    await page.settle();
    const sent = page.requests.slice(from);
    equal("by-reference 302: the offer GET refuses redirects", sent.filter((request) => request.url === OFFER_DOCUMENT + "by-ref-redirect")
        .map((request) => request.redirect), ["error"]);
    equal("by-reference 302: nothing reaches the redirect target", sent.filter((request) => request.url.startsWith(ATTACKER)).length, 0);
    check("by-reference 302: nothing is published", page.el("wallet").disabled === true, page.el("offerStatus").textContent);
});

// 27. F-18 round 3: a credential issuer or authorization server identifier with userinfo, a query or a fragment is
//     not an identifier (OpenID4VCI 1.0 section 12.2.1, RFC 8414 section 2), and is refused before anything is sent
for (const [label, issuer] of [
    ["an issuer with userinfo", "https://credentials.example@attacker.example/v1/certify/oid4vci"],
    ["an issuer with a query", OID4VCI_ISSUER + "?tenant=other"],
    ["an issuer with an empty query", OID4VCI_ISSUER + "?"],
    ["an issuer with a fragment", OID4VCI_ISSUER + "#other"],
]) {
    await section(`27. ${label}`, async () => {
        const { sent } = await refusedRedemption(label, { reason: "nothing was sent", offerIssuer: issuer,
            options: { issuerMetadata: Object.assign({}, DEFAULT_ISSUER_METADATA, { [issuer]: Object.assign({}, OID4VCI_DOCUMENT, { credential_issuer: issuer }) }) } });
        equal(`${label}: not even its metadata is requested`, sent.map((request) => request.method + " " + request.url), []);
    });
}
for (const [label, server] of [
    ["an authorization server with userinfo", "https://credentials.example@attacker.example"],
    ["an authorization server with a query", AS + "?realm=other"],
    ["an authorization server with a fragment", AS + "#other"],
]) {
    await section(`27. ${label}`, async () => {
        const { sent } = await refusedRedemption(label, { reason: "nothing was sent", options: {
            issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { authorization_servers: [server] }) },
        } });
        equal(`${label}: only the issuer metadata is requested`, sent.map((request) => request.method + " " + request.url),
            ["GET " + wellKnown(OID4VCI_ISSUER, "openid-credential-issuer")]);
    });
}

// 28. F-18 round 3, OpenID4VCI 1.0 section 4.1.1: a grant's authorization_server picks one of the issuer metadata's
//     authorization_servers, and MUST be one of them
const SECOND_AS = "https://login.credentials.example";
const TWO_SERVERS = { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { authorization_servers: [AS, SECOND_AS] }) };
const BOTH_AS = { [AS]: AS_DOCUMENT, [SECOND_AS]: { issuer: SECOND_AS, token_endpoint: SECOND_AS + "/token" } };
const hinted = (hint) => (code) => {
    const document = offerDocument(OID4VCI_ISSUER, "demo", code, TX_CODE);
    document.grants[GRANT].authorization_server = hint;
    return document;
};
await section("28a. authorization_server listed by the issuer", async () => {
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("hint", hinted(SECOND_AS)("code-hint"))], issuerMetadata: TWO_SERVERS, asMetadata: BOTH_AS,
    });
    await page.settle();
    page.el("subject").value = "hint-subject";
    page.el("txCode").value = "1234";
    await page.createOffer();
    await page.runWallet();
    equal("listed hint: its metadata is read", metadataRequest(page, "oauth-authorization-server") && metadataRequest(page, "oauth-authorization-server").url,
        wellKnown(SECOND_AS, "oauth-authorization-server"));
    equal("listed hint: the token request goes to its token endpoint, not the first server's",
        tokenRequest(page) && tokenRequest(page).url, SECOND_AS + "/token");
    check("listed hint: the credential is issued", page.el("walletStatus").textContent.includes("Credential issued"), page.el("walletStatus").textContent);
});
await section("28b. no authorization_server, two listed", async () => {
    const page = openPage({ subjects: [] }, {
        offers: [offerByValue("no-hint", offerDocument(OID4VCI_ISSUER, "demo", "code-no-hint"))], issuerMetadata: TWO_SERVERS, asMetadata: BOTH_AS,
    });
    await page.settle();
    page.el("subject").value = "hint-subject";
    await page.createOffer();
    await page.runWallet();
    equal("no hint: the first listed server is used", tokenRequest(page) && tokenRequest(page).url, TOKEN_ENDPOINT);
});
for (const [label, hint, issuerMetadata] of [
    ["authorization_server not listed by the issuer", "https://other.example", TWO_SERVERS],
    ["authorization_server and no authorization_servers", AS, { [OID4VCI_ISSUER]: (() => {
        const document = Object.assign({}, OID4VCI_DOCUMENT);
        delete document.authorization_servers;
        return document;
    })() }],
    ["authorization_server that is not a string", 42, TWO_SERVERS],
]) {
    await section(`28. ${label}`, async () => {
        const { sent } = await refusedRedemption(label, { reason: "does not list", document: hinted(hint),
            options: { issuerMetadata, asMetadata: BOTH_AS } });
        equal(`${label}: no authorization server metadata is requested`,
            sent.filter((request) => request.url.includes("oauth-authorization-server")).length, 0);
    });
}

// 29. F-18 round 3: a by-reference offer's credential_offer_uri is fetched only as a path on the page's own origin or
//     an absolute https URL (http when the deployment's own issuer identifier is http)
const linkTo = (value) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(value)}`;
for (const [label, value, fetchedAt, pageOptions] of [
    ["a path on the page's origin", "/v1/certify/credential-offer-data/by-path", DOMAIN + "/v1/certify/credential-offer-data/by-path", {}],
    ["an absolute https URL", OFFER_DOCUMENT + "absolute", OFFER_DOCUMENT + "absolute", {}],
    ["an http URL on an http deployment", "http://127.0.0.1:28191/v1/certify/credential-offer-data/dev",
        "http://127.0.0.1:28191/v1/certify/credential-offer-data/dev",
        { pageUrl: "http://127.0.0.1:28191/v1/certify/offer/", ownIssuer: "http://127.0.0.1:28191" }],
]) {
    await section(`29. by reference: ${label}`, async () => {
        const page = openPage({ subjects: [] }, Object.assign({
            offers: [{ credential_offer_uri: linkTo(value) }], offerFetches: [{ status: 200, body: REFERRED_OFFER }],
        }, pageOptions));
        await page.settle();
        page.el("subject").value = "reference-subject";
        await page.createOffer();
        equal(`${label}: the offer document is fetched there`, find(page, "GET", /credential-offer-data/) && find(page, "GET", /credential-offer-data/).url, fetchedAt);
        equal(`${label}: and published`, [page.el("offerUri").hidden, page.el("wallet").disabled], [false, false]);
    });
}
for (const [label, value] of [
    ["a protocol-relative URL", "//attacker.example/v1/certify/credential-offer-data/x"],
    ["a backslash path", "/\\attacker.example/v1/certify/credential-offer-data/x"],
    ["an http URL on an https deployment", "http://credentials.example/v1/certify/credential-offer-data/x"],
    ["another scheme", "ftp://credentials.example/v1/certify/credential-offer-data/x"],
    ["a javascript: URL", "javascript:alert(1)"],
    ["userinfo", "https://user@credentials.example/v1/certify/credential-offer-data/x"],
    ["a relative path without a leading slash", "v1/certify/credential-offer-data/x"],
]) {
    await section(`29. by reference refused: ${label}`, async () => {
        const page = openPage({ subjects: [] }, {
            offers: [{ credential_offer_uri: linkTo(value) }], offerFetches: [{ status: 200, body: REFERRED_OFFER }],
        });
        await page.settle();
        page.el("subject").value = "reference-subject";
        await page.createOffer();
        equal(`${label}: nothing but the offer POST is requested`, page.requests.filter((request) => request.method !== "GET"
            || !/^\/v1\/certify\/(\.well-known|offer\/)/.test(request.url)).map((request) => request.method + " " + request.url),
        ["POST /v1/certify/pre-authorized-data"]);
        check(`${label}: the refusal is reported`, page.el("offerStatus").className.includes("bad")
            && page.el("offerStatus").textContent.includes("not a URL this page fetches"), page.el("offerStatus").textContent);
        equal(`${label}: nothing is published`, [page.el("offerUri").hidden, page.el("wallet").disabled], [true, true]);
    });
}

// 30. RFC 8414 section 3.1: one terminating "/" of the identifier's path is removed before the well-known segment goes in
for (const [label, server, location] of [
    ["one trailing slash", "https://as.example/realm/", "https://as.example/.well-known/oauth-authorization-server/realm"],
    ["two trailing slashes", "https://as.example/realm//", "https://as.example/.well-known/oauth-authorization-server/realm/"],
]) {
    await section(`30. AS identifier with ${label}`, async () => {
        const page = openPage({ subjects: [] }, {
            offers: [offerByValue("slash", offerDocument(OID4VCI_ISSUER, "demo", "code-slash"))],
            issuerMetadata: { [OID4VCI_ISSUER]: Object.assign({}, OID4VCI_DOCUMENT, { authorization_servers: [server] }) },
            asMetadata: { [server]: { issuer: server, token_endpoint: "https://as.example/token" } },
        });
        await page.settle();
        page.el("subject").value = "slash-subject";
        await page.createOffer();
        await page.runWallet();
        equal(`${label}: the metadata URL`, metadataRequest(page, "oauth-authorization-server") && metadataRequest(page, "oauth-authorization-server").url, location);
        equal(`${label}: the token endpoint it names is used`, tokenRequest(page) && tokenRequest(page).url, "https://as.example/token");
    });
}

// 31. the parser's newline rules: CR LF normalised, and the newline right after <textarea>, <pre> and <listing> dropped
await section("31. parser newlines", async () => {
    const { ids } = parseMarkup('<textarea id="a">\nfirst</textarea><textarea id="b">\n\nsecond</textarea>'
        + '<textarea id="c">\r\nthird</textarea><pre id="p">\nx</pre><pre id="q"><b>y</b>\nz</pre><div id="d">\nkept</div>');
    equal("a textarea drops the newline right after its start tag", ids.get("a") && ids.get("a").value, "first");
    equal("only that one newline", ids.get("b") && ids.get("b").value, "\nsecond");
    equal("CR LF is a newline", ids.get("c") && ids.get("c").value, "third");
    equal("a pre drops the newline right after its start tag", ids.get("p") && ids.get("p").textContent, "x");
    equal("a newline later in a pre is kept", ids.get("q") && ids.get("q").textContent, "y\nz");
    equal("other elements keep a leading newline", ids.get("d") && ids.get("d").textContent, "\nkept");
});

} finally {
    console.log();
    if (!checks) check("the harness ran at least one check", false);
    if (failures) {
        console.log(`check-offer-page: ${failures} of ${checks} checks FAILED`);
    } else {
        console.log(`check-offer-page: all ${checks} checks passed`);
    }
    process.exitCode = failures ? 1 : 0;
}
