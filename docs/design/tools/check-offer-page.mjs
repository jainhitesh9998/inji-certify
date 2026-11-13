#!/usr/bin/env node
/*
 * Behaviour check of the credential offer page's demo-subject wiring (F-15), and of the page's own still-unmodified
 * behaviour around it: the REAL `certify-service/src/main/resources/static/offer/index.html` is loaded, its inline
 * script evaluated in a throwaway VM with a minimal fake DOM, a stub `fetch` and a stub `QRCode`, and the page is
 * driven the way a visitor drives it (choose a configuration, choose a subject, press "Create offer").
 *
 * Plain Node (18 or later), no npm dependencies, no browser, no server: `node docs/design/tools/check-offer-page.mjs`.
 * One line per check, then `check-offer-page: all N checks passed`; a non-zero exit when anything fails.
 *
 * Why it exists: round 1 of the F-15 review found that the JUnit page tests asserted source strings, which stayed green
 * while two real defects shipped (a `[hidden]` attribute that the page's own `label { display: block }` overrode, so a
 * stray subject label was always visible; and an "Other" sentinel value that a configured subject id could collide
 * with). Those two checks below are the regression tests for exactly those defects.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PAGE = resolve(REPO, "certify-service/src/main/resources/static/offer/index.html");
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

/* ---------------------------------------------------------------- fake DOM */

class Element {
    constructor(tag) {
        this.tagName = tag;
        this.children = [];
        this.listeners = new Map();
        this._value = undefined;
        this._text = "";
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

    // a browser's textContent is the element's text and nothing else: setting it drops the children (the page clears
    // the subject dropdown's options this way, so a fake that kept them would hide the re-filter it performs)
    get textContent() {
        return this._text;
    }

    set textContent(text) {
        this._text = String(text);
        this.children = [];
    }

    // a browser selects the first option of a select nobody chose for, which the page relies on for the configuration
    get value() {
        return this._value !== undefined ? this._value : (this.children.length ? this.children[0].value : "");
    }

    set value(value) {
        this._value = value;
    }

    appendChild(child) {
        this.children.push(child);
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
        this.children = [];
    }

    get innerHTML() {
        return "";
    }

    async fire(type) {
        const listeners = this.listeners.get(type) || [];
        for (const listener of listeners) await listener({ type, target: this });
    }
}

/** The elements the markup declares, with the state the markup gives them (hidden, value, the text between the tags). */
function markupElements(markup) {
    const elements = new Map();
    const tags = /<([a-zA-Z][\w-]*)([^<>]*)>([^<]*)/g;
    for (const match of markup.matchAll(tags)) {
        const [, tag, attributes, text = ""] = match;
        const id = /\bid="([^"]+)"/.exec(attributes);
        if (!id) continue;
        const element = new Element(tag.toLowerCase());
        element.hidden = /(^|\s)hidden(\s|=|$)/.test(attributes);
        const value = /\bvalue="([^"]*)"/.exec(attributes);
        if (value) element.value = value[1];
        element.textContent = text;
        elements.set(id[1], element);
    }
    return elements;
}

/* ---------------------------------------------------------------- a loaded page */

const METADATA = {
    credential_configurations_supported: {
        mdl: { format: "ldp_vc" },
        demo: { format: "ldp_vc" },
        farmer: { format: "ldp_vc" },
    },
};

const OFFER = {
    credential_offer_uri:
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fv1%2Fcertify%2Fcredential-offer-data%2Fabc",
    credential_offer: {
        grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "abc" } },
    },
};

/**
 * Opens the page: the markup's elements, the inline script evaluated against them, and the four requests it makes on
 * load (two metadata documents, the authorization server metadata, the demo-subject list).
 *
 * @param demo the answer to `GET /offer/demo-subjects`: a JSON value, a raw string, `false` for a 404, or `null` for a
 *             fetch that throws
 */
function openPage(demo) {
    const elements = markupElements(html);
    const created = [];
    const requests = [];

    const document = {
        getElementById(id) {
            let element = elements.get(id);
            if (!element) {
                element = new Element("div");
                elements.set(id, element);
            }
            return element;
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

    const fetch = async (url, options = {}) => {
        const target = String(url);
        const method = (options.method || "GET").toUpperCase();
        requests.push({ method, url: target, body: options.body });
        if (method === "GET" && target.endsWith("/.well-known/oauth-authorization-server")) {
            return answer(200, { token_endpoint: "https://issuer.example/token" });
        }
        if (method === "GET" && target.endsWith("/oid4vci/.well-known/openid-credential-issuer")) {
            return answer(200, { credential_issuer: "https://issuer.example/oid4vci", credential_configurations_supported: {} });
        }
        if (method === "GET" && target.endsWith("/.well-known/openid-credential-issuer")) return answer(200, METADATA);
        if (method === "GET" && target.endsWith("/offer/demo-subjects")) {
            if (demo === null) throw new TypeError("fetch failed");
            if (demo === false) return answer(404, "not found");
            return answer(200, demo);
        }
        if (method === "POST" && target.endsWith("/pre-authorized-data")) return answer(200, OFFER);
        return answer(404, "not found");
    };

    class QRCode {
        constructor() {}
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
    });
    const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]).find((source) => source.includes("(function () {"));
    if (!inline) throw new Error("the page's inline script is missing");
    vm.runInContext(inline, context, { filename: "static/offer/index.html" });

    const page = {
        el: (id) => document.getElementById(id),
        created,
        requests,
        /** Lets every pending promise of the page's load finish. */
        async settle() {
            for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done));
        },
        /** Presses "Create offer" and returns the parsed body of the POST it made (undefined when it made none). */
        async createOffer() {
            const before = requests.filter((request) => request.method === "POST").length;
            await page.el("create").fire("click");
            const posts = requests.filter((request) => request.method === "POST");
            if (posts.length <= before) return undefined;
            return JSON.parse(posts[posts.length - 1].body);
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

const SUBJECTS = [
    { id: "mdl-demo-1", label: "Asha Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-2", label: "Ravi Demo", credential_configuration_ids: ["mdl", "demo"] },
    { id: "mdl-demo-3", label: "Meera Test", credential_configuration_ids: ["mdl"] },
    { id: "farmer-1", label: "Farmer", credential_configuration_ids: ["farmer"] },
    { id: "__other__", label: "Sentinel", credential_configuration_ids: ["farmer"] },
];

const options = (page) => page.el("subjectChoice").children.map((option) => [option.value, option.textContent]);

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

// 6. the dropdown reappears on a reload with the same configuration, and only then
{
    const page = openPage({ subjects: [{ id: "only-1", label: "Only", credential_configuration_ids: ["farmer"] }] });
    await page.settle();
    equal("a configuration with no subject hides the dropdown again", page.el("subjectChoice").hidden, true);
    equal("and shows the typed field", page.el("subject").hidden, false);
    equal("and restores the claims label", page.el("claimsLabel").textContent, CLAIMS_LABEL);
}

console.log();
if (failures) {
    console.log(`check-offer-page: ${failures} of ${checks} checks FAILED`);
    process.exit(1);
}
console.log(`check-offer-page: all ${checks} checks passed`);
