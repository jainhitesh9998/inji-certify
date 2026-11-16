/*
 * OpenID4VP 1.0 request intake for the demo wallet (P5-03c, plan sections 4.4 and 4.5).
 *
 * Three jobs, all of them before anything is sent anywhere:
 *
 * 1. `parseLink` reads what a verifier handed the page: one of the wallet invocation schemes of VP section 9, or an
 *    https link that only carries parameters, or a request object by value, or - only with the `redirect_uri:` client
 *    identifier prefix, which cannot be signed (VP section 5.9.3) - plain parameters.
 * 2. `fetchRequestObject` reads the request object a `request_uri` names, once per page lifetime and never twice (EUDI's
 *    object is single use, plan 2.2), with `redirect: "error"` so a redirect is a refusal and not a fetch of somewhere
 *    else, and with the body read under a 64 KiB cap instead of whole.
 * 3. `checkRequest` checks the request and the verifier: R1-R11 of plan 4.5 (refusals), the four error cases a wallet
 *    answers with an error response (VP section 8.5), and the findings the page shows without blocking.
 *
 * A verifier that sends no CORS headers is P5-03f's: the page reads it by having its request object pasted, and the
 * relay that would read it instead arrives with the server half that gives its answers meaning.
 *
 * Nothing here sends anything. The only request this module makes is the fetch of the request object the protocol
 * names (I9): there is no response, no error post and no probe. `wallet.js` posts an error response only when the
 * visitor presses "Send error response".
 *
 * Depends on `X509` (the DER reader and WebCrypto) and on the browser's `fetch`, `crypto`, `TextEncoder/TextDecoder`,
 * `URL` and `atob`. The harness hands the same globals in from Node.
 */
var Oid4vp = (function () {
  "use strict";

  /* ---------------------------------------------------------------- limits (plan 4.4) */

  var LIMITS = {
    LINK_BYTES: 8 * 1024,
    REQUEST_BYTES: 64 * 1024,
    JSON_DEPTH: 16,
    CREDENTIAL_QUERIES: 20,
    CLAIMS_PER_QUERY: 100,
    CLAIM_SETS: 20,
    CREDENTIAL_SETS: 20,
    X5C_CERTIFICATES: 5,
    X5C_CERTIFICATE_BYTES: 8 * 1024,
  };

  /** The invocation schemes VP section 9 allows a wallet to receive; `https` only carries parameters here. */
  var SCHEMES = ["openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp", "https"];

  /**
   * Multipaz's scheme field produces `haip-vp://://?client_id=…`, with the separator doubled: what it hands the browser
   * is its scheme (`haip-vp://`) with the fragment it built (`://?…`) appended. That is not a URL (WHATWG URL parsing
   * refuses it), and it is what the hosted verifier's begin answer carries, so the extra separator is folded away before
   * the link is read. Only the wallet invocation schemes are folded: an `https` link gets no such generosity.
   */
  var DOUBLED_SEPARATOR = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/:\/\//;

  /** The client identifier prefixes of VP section 5.9.3, plus the none-prefix case. */
  var PREFIXES = ["x509_san_dns", "x509_hash", "redirect_uri", "origin", "decentralized_identifier",
    "verifier_attestation", "openid_federation"];

  /** The request parameters this page knows; anything else is a finding, never a refusal (plan 4.5). */
  var KNOWN_PARAMETERS = ["client_id", "client_metadata", "nonce", "response_mode", "response_type", "response_uri",
    "state", "dcql_query", "scope", "redirect_uri", "transaction_data", "aud", "exp", "iat", "nbf", "jti", "iss", "sub",
    "wallet_nonce", "verifier_info", "expected_origins"];

  var RESPONSE_MODES = ["direct_post", "direct_post.jwt"];
  var SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2";
  /** How far a verifier's clock may run ahead of this one before `iat` is refused (plan 4.5 R5). */
  var CLOCK_SKEW_MS = 5 * 60 * 1000;
  /** The doubling RFC 5280 section 6.1.3 (a)(2) checking allows for a certificate's validity. */
  var VALIDITY_SKEW_MS = 5 * 60 * 1000;
  var LOCAL_HOSTS = ["localhost", "127.0.0.1", "::1", "[::1]"];

  /* ---------------------------------------------------------------- helpers */

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  var BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  /**
   * base64url (RFC 4648 section 5) to bytes, strictly: no padding, only the two alphabet characters beyond the
   * standard one, and the encoding must be the one the bytes have (a trailing character whose spare bits are not zero
   * encodes the same bytes twice, and a signature is checked over these bytes). `atob` alone accepts that, so the
   * result is compared with the input.
   */
  function decodeBase64url(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
      throw new Error("not base64url");
    }
    if (text.length % 4 === 1) throw new Error("a base64url group of one character");
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var binary;
    try {
      binary = atob(padded);
    } catch (error) {
      throw new Error("not base64url");
    }
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    if (encodeBase64url(bytes) !== text) throw new Error("not the canonical base64url of its bytes");
    return bytes;
  }

  function encodeBase64url(bytes) {
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /**
   * Standard base64 (RFC 4648 section 4) to bytes, strictly: this is the encoding `x5c` uses, and it is not base64url
   * (RFC 7515 section 4.1.6). Padding is optional here because emitters differ, but the alphabet must be the standard
   * one and the encoding must be the one the bytes have.
   */
  function decodeBase64(text) {
    if (typeof text !== "string") throw new Error("not base64");
    var trimmed = text.replace(/={0,2}$/, "");
    if (!trimmed.length || !/^[A-Za-z0-9+/]+$/.test(trimmed)) throw new Error("not base64");
    if (trimmed.length % 4 === 1) throw new Error("a base64 group of one character");
    var padded = trimmed;
    while (padded.length % 4) padded += "=";
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    var again = btoa(binary).replace(/=+$/, "");
    if (again !== trimmed) throw new Error("not the canonical base64 of its bytes");
    return bytes;
  }

  function utf8Length(text) {
    return new TextEncoder().encode(text).length;
  }

  function decodeUtf8(bytes) {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function isLocalHost(hostname) {
    return LOCAL_HOSTS.indexOf(String(hostname).toLowerCase()) >= 0;
  }

  /** The deepest nesting of a JSON value, stopping as soon as it is over `limit` (a hostile document costs one walk). */
  function jsonDepth(value, limit) {
    var deepest = 0;
    var stack = [{ value: value, depth: 1 }];
    while (stack.length) {
      var item = stack.pop();
      if (item.depth > deepest) deepest = item.depth;
      if (deepest > limit) return deepest;
      if (Array.isArray(item.value)) {
        for (var i = 0; i < item.value.length; i++) stack.push({ value: item.value[i], depth: item.depth + 1 });
      } else if (isObject(item.value)) {
        var keys = Object.keys(item.value);
        for (var j = 0; j < keys.length; j++) stack.push({ value: item.value[keys[j]], depth: item.depth + 1 });
      }
    }
    return deepest;
  }

  /* ---------------------------------------------------------------- client identifiers (VP 5.9.3) */

  /** A client_id split into its prefix and value; `prefix` is null for a pre-registered (prefix-less) identifier. */
  function splitClientId(clientId) {
    if (typeof clientId !== "string" || !clientId.length) return { prefix: null, value: null };
    var colon = clientId.indexOf(":");
    if (colon < 0) return { prefix: null, value: clientId };
    var head = clientId.slice(0, colon);
    if (PREFIXES.indexOf(head) < 0) return { prefix: null, value: clientId };
    return { prefix: head, value: clientId.slice(colon + 1) };
  }

  /** A DNS name a dNSName SAN can hold: labels of letters, digits and hyphens, no wildcard (RFC 5280 4.2.1.6). */
  function isDnsName(value) {
    return typeof value === "string" && value.length > 0 && value.length <= 253
      && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/.test(value);
  }

  var PREFIX_EXPLANATIONS = {
    "x509_san_dns": "x509_san_dns: the verifier's leaf certificate carries this DNS name as a dNSName subject "
      + "alternative name, and the request is signed with that certificate's key (OpenID4VP 1.0 section 5.9.3).",
    "x509_hash": "x509_hash: this value is the base64url SHA-256 of the verifier's leaf certificate, and the request is "
      + "signed with that certificate's key (OpenID4VP 1.0 section 5.9.3; HAIP 1.0 requires this prefix).",
    "redirect_uri": "redirect_uri: the request is unsigned and this redirect URI is its client identifier "
      + "(OpenID4VP 1.0 section 5.9.3: requests with this prefix cannot be signed).",
  };

  /* ---------------------------------------------------------------- links (plan 4.4) */

  /** Whether a string is a compact JWS: three base64url parts (JWS, RFC 7515 section 7.1). */
  function isRequestObject(text) {
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(String(text));
  }

  function refused(rule, message, findings) {
    return { ok: false, rule: rule, message: message, findings: findings || [] };
  }

  function refusedLink(message, findings) {
    return { ok: false, rule: null, message: message, findings: findings || [] };
  }

  /**
   * Reads what the visitor pasted or what a verifier navigated the page to. Returns
   * `{ok, kind: "request_uri" | "by_value" | "plain", params, scheme, findings}` or `{ok: false, message}`.
   *
   * `params` always has `clientId` (undefined when the link names none, which Paradym's invitation link does) and
   * `requestUriMethod` (`get` unless the link says `post`); `request` holds a request object by value and `plain` the
   * parameters of an unsigned `redirect_uri:` request.
   */
  function parseLink(text) {
    var raw = String(text === undefined || text === null ? "" : text).trim();
    if (!raw) return refusedLink("the field is empty: paste the verifier's link, or its request object.");
    var findings = [];
    if (utf8Length(raw) > LIMITS.LINK_BYTES) {
      return refused("R1", "the link is " + utf8Length(raw) + " bytes, over the 8 KiB limit (plan 4.4).", findings);
    }
    if (isRequestObject(raw)) {
      // a request object pasted by itself: the checks are the same as for a fetched one (plan 4.4)
      return { ok: true, kind: "by_value", params: { clientId: undefined, request: raw }, scheme: null, findings: findings };
    }

    var doubled = DOUBLED_SEPARATOR.exec(raw);
    var target = raw;
    if (doubled !== null && SCHEMES.indexOf(doubled[1].toLowerCase()) >= 0 && doubled[1].toLowerCase() !== "https") {
      target = raw.replace(DOUBLED_SEPARATOR, doubled[1] + "://");
      findings.push("this link's separator is doubled (" + doubled[1] + "://://?…), which is the form the hosted Multipaz "
        + "verifier hands out; it is read as " + doubled[1] + "://?… .");
    }

    var url;
    try {
      url = new URL(target);
    } catch (error) {
      return refusedLink("this is neither a link nor a request object: a request object is three base64url parts "
        + "separated by dots.", findings);
    }
    var scheme = url.protocol.replace(/:$/, "").toLowerCase();
    if (SCHEMES.indexOf(scheme) < 0) {
      return refusedLink(scheme + ": is not a wallet invocation scheme this page accepts (" + SCHEMES.join(", ")
        + "; OpenID4VP 1.0 section 9).", findings);
    }

    var params = new URLSearchParams(url.search);
    var link = { clientId: undefined, requestUri: undefined, requestUriMethod: "get", request: undefined, plain: null };
    var seen = [];
    var duplicated = [];
    params.forEach(function (value, name) {
      if (seen.indexOf(name) >= 0) {
        if (duplicated.indexOf(name) < 0) duplicated.push(name);
        return;
      }
      seen.push(name);
      if (name === "client_id") link.clientId = value;
      if (name === "request_uri") link.requestUri = value;
      if (name === "request_uri_method") link.requestUriMethod = value;
      if (name === "request") link.request = value;
    });
    if (duplicated.length) {
      // RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more than once." Which of two
      // values a reader takes is a choice no specification makes, so the link is refused rather than guessed at.
      return refusedLink("the link carries " + duplicated.join(", ") + " more than once; a request parameter appears "
        + "once (RFC 6749 section 3.1).", findings);
    }
    // A link that carries a request object, or names one, is read for those four parameters only, so anything else on
    // it is a finding. A plain `redirect_uri:` link is the request itself: every parameter on it is read, and
    // `checkPlainRequest` reports the ones that are unknown to a request, so it is not reported here as well.
    var plainLink = link.request === undefined && link.requestUri === undefined
      && splitClientId(link.clientId).prefix === "redirect_uri";
    if (!plainLink) {
      seen.filter(function (name) {
        return ["client_id", "request_uri", "request_uri_method", "request"].indexOf(name) < 0;
      }).forEach(function (name) {
        findings.push("the link carries the parameter " + JSON.stringify(name) + ", which this page does not read.");
      });
    }

    var method = String(link.requestUriMethod).toLowerCase();
    if (method !== "get" && method !== "post") {
      return refusedLink("request_uri_method is " + JSON.stringify(link.requestUriMethod) + "; a wallet accepts get or "
        + "post (OpenID4VP 1.0 section 5.10.1).", findings);
    }
    link.requestUriMethod = method;

    if (link.request !== undefined && link.requestUri !== undefined) {
      return refusedLink("the link carries both request and request_uri; a request is one or the other "
        + "(OpenID4VP 1.0 section 5.1).", findings);
    }
    if (link.request !== undefined) {
      return { ok: true, kind: "by_value", params: link, scheme: scheme, findings: findings };
    }
    if (link.requestUri !== undefined) {
      return { ok: true, kind: "request_uri", params: link, scheme: scheme, findings: findings };
    }

    // no request object at all: only a redirect_uri: client identifier may carry plain parameters (VP 5.9.3)
    var split = splitClientId(link.clientId);
    if (split.prefix !== "redirect_uri") {
      return refusedLink("the link names neither request_uri nor request, so it must stand for an unsigned request with "
        + "the redirect_uri: client identifier prefix (OpenID4VP 1.0 section 5.9.3).", findings);
    }
    link.plain = {};
    params.forEach(function (value, name) { link.plain[name] = value; });
    return { ok: true, kind: "plain", params: link, scheme: scheme, findings: findings };
  }

  /* ---------------------------------------------------------------- fetching the request object (plan 4.4) */

  function contentTypeOf(answer) {
    if (answer === null || answer === undefined) return "";
    if (answer.headers && typeof answer.headers.get === "function") return String(answer.headers.get("content-type") || "");
    if (typeof answer.contentType === "string") return answer.contentType;
    return "";
  }

  /**
   * Reads at most `limit` bytes of a Response's body. The declared `Content-Length` is checked first, and the body is
   * then read chunk by chunk and abandoned the moment it goes over the limit, so a body that declares no length (a
   * chunked one, which is what a verifier streaming its request object sends) still costs at most one chunk past the
   * cap. A response is never read whole on the chance that it is small: a verifier does not get to choose how much
   * memory this page spends. Returns `{bytes}` or `{over}` with the byte count that broke the limit.
   */
  async function readCapped(answer, limit) {
    var declared = answer.headers && typeof answer.headers.get === "function"
      ? String(answer.headers.get("content-length") || "").trim() : "";
    if (/^\d+$/.test(declared) && Number(declared) > limit) return { over: Number(declared) };
    if (!answer.body || typeof answer.body.getReader !== "function") {
      // no body at all: a 204, or an answer a test handed in without one
      return { bytes: new Uint8Array(0) };
    }
    var reader = answer.body.getReader();
    var chunks = [];
    var total = 0;
    for (;;) {
      var step = await reader.read();
      if (step.done) break;
      var chunk = step.value instanceof Uint8Array ? step.value : new Uint8Array(step.value);
      total += chunk.length;
      if (total > limit) {
        try {
          await reader.cancel();
        } catch (error) {
          // the stream is abandoned either way; the refusal is the same
        }
        return { over: total };
      }
      chunks.push(chunk);
    }
    var bytes = new Uint8Array(total);
    var at = 0;
    chunks.forEach(function (chunk) {
      bytes.set(chunk, at);
      at += chunk.length;
    });
    return { bytes: bytes };
  }

  /** The key a request_uri's "already fetched" test uses: the URL itself, with its fragment taken off (RFC 3986 3.5). */
  function fetchedKeyOf(url) {
    var copy = new URL(url.href);
    copy.hash = "";
    return copy.href;
  }

  /**
   * Fetches the request object `requestUri` names. Returns `{ok, text, contentType, via}` or
   * `{ok: false, message, state}`; `state` is `"unreachable"` when the browser refused to let the page read the answer
   * (CORS, or a redirect seen through `redirect: "error"`), which is a state the page must report as such (plan 2.1:
   * Multipaz and Credo send no CORS headers).
   *
   * This is the page's only outgoing request (I9): nothing is sent to the verifier, and the response_uri is never
   * touched from here. Reading a verifier that sends no CORS headers through Certify's relay is P5-03f's, together
   * with the server half that would make the relay's answer mean anything.
   *
   * Options: `requestUri`, `method` (`get`/`post`), `walletNonce` (sent for a post, and only that), `pageUrl`, `fetched`
   * (a Set of request URIs already fetched), `fetchImpl`.
   */
  async function fetchRequestObject(options) {
    var requestUri = String(options.requestUri === undefined ? "" : options.requestUri);
    var fetchImpl = options.fetchImpl;
    var pageUrl = options.pageUrl;
    var url;
    try {
      url = new URL(requestUri);
    } catch (error) {
      return { ok: false, message: "the link's request_uri is not a URL." };
    }
    if (url.protocol !== "https:" && !(isLocalHost(pageUrl.hostname) && url.protocol === "http:")) {
      return { ok: false, message: "request_uri is " + url.protocol + "//" + url.host + "; https is required"
        + (isLocalHost(pageUrl.hostname) ? "." : ", and http is allowed only while this page is served from localhost.") };
    }
    var fetchedKey = fetchedKeyOf(url);
    if (options.fetched !== undefined && options.fetched.has(fetchedKey)) {
      return { ok: false, state: "alreadyFetched", message: "this request_uri was already fetched. A request object is "
        + "read once (plan 4.4: EUDI's is single use), so the page never fetches one twice." };
    }
    // recorded before the fetch: an attempt that failed may still have consumed the verifier's only copy
    if (options.fetched !== undefined) options.fetched.add(fetchedKey);

    var method = String(options.method || "get").toLowerCase() === "post" ? "POST" : "GET";

    /**
     * The answer's body, within the request object's limit, decoded as the UTF-8 text it has to be. `ignoreBOM` keeps a
     * leading byte order mark in the text instead of dropping it: a compact JWS is base64url and dots from its first
     * octet (RFC 7515 section 7.1), so a body that starts with U+FEFF is not one, and the checks refuse it as such
     * rather than reading the bytes after it as if the verifier had sent those.
     */
    async function finish(answer, via) {
      var read = await readCapped(answer, LIMITS.REQUEST_BYTES);
      if (read.over !== undefined) {
        return { ok: false, via: via, message: "the request object is " + read.over + " bytes, over the 64 KiB limit "
          + "(plan 4.4); it is not read any further." };
      }
      var text;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(read.bytes);
      } catch (error) {
        return { ok: false, via: via, message: "the request object is not UTF-8 (OpenID4VP 1.0 section 5.10)." };
      }
      return { ok: true, text: text, contentType: contentTypeOf(answer), via: via };
    }

    try {
      var init = {
        method: method,
        headers: { Accept: "application/oauth-authz-req+jwt" },
        cache: "no-store",
        credentials: "omit",
        // a 3xx is a refusal, never a fetch of wherever it points (plan 4.4)
        redirect: "error",
      };
      if (method === "POST") {
        // VP section 5.10.1: the form carries wallet_nonce and nothing else. wallet_metadata is not sent: EUDI refuses
        // a wallet_metadata without the fields it treats as required (plan 2.1), and VP makes both optional.
        init.headers["Content-Type"] = "application/x-www-form-urlencoded";
        init.body = new URLSearchParams({ wallet_nonce: String(options.walletNonce) });
      }
      var answer = await fetchImpl(requestUri, init);
      if (answer.status >= 200 && answer.status < 300 && answer.status !== 200) {
        // a success that is not 200 is not an error, so VP section 5.10.2 is not the reason; the reason is that the page
        // reads a request object only from the 200 answer that carries one, and nothing else is taken for it
        return { ok: false, via: "direct", message: "the request_uri answered " + answer.status + ", a success that is "
          + "not 200; this page reads a request object only from a 200 answer, so it stops here." };
      }
      if (answer.status !== 200) {
        return { ok: false, via: "direct", message: "the request_uri answered " + answer.status + "; any HTTP error ends "
          + "the process (OpenID4VP 1.0 section 5.10.2)." };
      }
      return await finish(answer, "direct");
    } catch (error) {
      return { ok: false, via: "direct", state: "unreachable",
        message: "the request object could not be read: the answer redirected (this page refuses redirects), or "
          + url.hostname + " does not let a page on this origin read it (no CORS headers). "
          + "Such a verifier's request object can also be pasted here." };
    }
  }

  /* ---------------------------------------------------------------- the checks (plan 4.5) */

  /** An audience claim that names the self-issued identifier (VP section 5.8), as a string or a one-entry array. */
  function audienceIsSelfIssued(aud) {
    if (typeof aud === "string") return aud === SELF_ISSUED_AUDIENCE;
    if (Array.isArray(aud)) return aud.length > 0 && aud.every(function (entry) { return entry === SELF_ISSUED_AUDIENCE; });
    return false;
  }

  function numericDate(value) {
    if (typeof value !== "number" || !isFinite(value)) return null;
    return value;
  }

  /** The DCQL limits of plan 4.4 (the query's semantics are P5-03d's). */
  function dcqlLimitBreach(dcql) {
    if (!isObject(dcql)) return null;
    if (Array.isArray(dcql.credentials) && dcql.credentials.length > LIMITS.CREDENTIAL_QUERIES) {
      return dcql.credentials.length + " credential queries, over the limit of " + LIMITS.CREDENTIAL_QUERIES;
    }
    if (Array.isArray(dcql.credential_sets) && dcql.credential_sets.length > LIMITS.CREDENTIAL_SETS) {
      return dcql.credential_sets.length + " credential sets, over the limit of " + LIMITS.CREDENTIAL_SETS;
    }
    if (Array.isArray(dcql.credentials)) {
      for (var i = 0; i < dcql.credentials.length; i++) {
        var query = dcql.credentials[i];
        if (!isObject(query)) continue;
        if (Array.isArray(query.claims) && query.claims.length > LIMITS.CLAIMS_PER_QUERY) {
          return "credential query " + i + " asks for " + query.claims.length + " claims, over the limit of "
            + LIMITS.CLAIMS_PER_QUERY;
        }
        if (Array.isArray(query.claim_sets) && query.claim_sets.length > LIMITS.CLAIM_SETS) {
          return "credential query " + i + " has " + query.claim_sets.length + " claim_sets, over the limit of "
            + LIMITS.CLAIM_SETS;
        }
      }
    }
    return null;
  }

  /** `client_metadata.client_name`, as the verifier names itself (never as a fact, so the card labels it). */
  function clientNameOf(payload) {
    var metadata = payload.client_metadata;
    if (!isObject(metadata)) return null;
    return typeof metadata.client_name === "string" ? metadata.client_name.slice(0, 200) : null;
  }

  /**
   * `verifier_info`'s entries with their JWS payload decoded as text, labelled unverified by the card (EUDI sends a
   * registration certificate this way, which is most of a 23 KB request object; plan 2.1).
   */
  function verifierInfoOf(payload) {
    if (!Array.isArray(payload.verifier_info)) return null;
    var entries = [];
    payload.verifier_info.slice(0, 4).forEach(function (entry) {
      if (!isObject(entry)) return;
      var text = "";
      if (typeof entry.data === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(entry.data)) {
        try {
          text = decodeUtf8(decodeBase64url(entry.data.split(".")[1]));
        } catch (error) {
          text = "";
        }
      }
      entries.push({
        format: entry.format === undefined ? "" : String(entry.format),
        type: entry.type === undefined ? "" : String(entry.type),
        text: text.slice(0, 4000),
      });
    });
    return entries.length ? entries : null;
  }

  /**
   * R8's half that holds whatever the client identifier prefix: the response_uri is there, is a URL, is `https` (`http`
   * only while the page is served from localhost), and carries no userinfo. Returns `{target}` (the parsed URL) or
   * `{rule, message}`. The prefix's own binding (the DNS name, or the redirect URI itself) is the caller's.
   */
  function responseUriFault(responseUri, localPage) {
    if (typeof responseUri !== "string" || !responseUri.length) {
      return { rule: "R8", message: "the request carries no response_uri, so there is nowhere to send a response "
        + "(OpenID4VP 1.0 section 5.1)." };
    }
    var target;
    try {
      target = new URL(responseUri);
    } catch (error) {
      return { rule: "R8", message: "response_uri is not a URL (OpenID4VP 1.0 section 5.1)." };
    }
    if (target.protocol !== "https:" && !(localPage && target.protocol === "http:")) {
      return { rule: "R8", message: "response_uri is " + target.protocol + "//" + target.host + "; https is required"
        + (localPage ? "." : ", and http is allowed only while this page is served from localhost.") };
    }
    if (target.username || target.password) {
      // a response_uri the client may use as its redirect_uri carries no userinfo (VP section 5.9.3 delegates to RFC
      // 6749 section 3.1.2, and a URL with credentials in it is not one this page will post a credential to)
      return { rule: "R8", message: "response_uri carries a user name or password; a response URI names a host and a "
        + "path, and nothing is posted to a URL with credentials in it (OpenID4VP 1.0 sections 5.9.3 and 8.2)." };
    }
    return { target: target };
  }

  /**
   * R11: the response type and mode this wallet implements (VP 5.6, 8.2). Both must be there: VP section 5.1 lists
   * response_type as required, and an absent response_mode defaults to `fragment` (VP section 8.2), which this page
   * cannot answer at all - so a request that omits either is refused rather than read as if it had said `vp_token` and
   * `direct_post`. Returns the refusal's message, or null.
   */
  function responseShapeFault(responseType, responseMode) {
    if (responseType !== "vp_token") {
      return "the request's response_type is " + (responseType === undefined
        ? "absent, and OpenID4VP 1.0 section 5.1 requires it" : JSON.stringify(responseType)
          + "; section 5.6 has vp_token") + ".";
    }
    if (RESPONSE_MODES.indexOf(responseMode) < 0) {
      return "the request's response_mode is " + (responseMode === undefined
        ? "absent, which OpenID4VP 1.0 section 8.2 defaults to fragment, and this wallet answers nothing that way"
        : JSON.stringify(responseMode) + "; this wallet implements " + RESPONSE_MODES.join(" and ")
          + " (OpenID4VP 1.0 section 8.2)") + ".";
    }
    return null;
  }

  /** The request parameters this page does not read, as the one finding that lists them (plan 4.5). */
  function unknownParametersFinding(members, findings) {
    var unknown = Object.keys(members).filter(function (name) { return KNOWN_PARAMETERS.indexOf(name) < 0; });
    if (unknown.length) findings.push("the request carries " + unknown.length + " parameter(s) this page does not read: "
      + unknown.join(", ") + ".");
  }

  function isoOf(date) {
    return date instanceof Date ? date.toISOString().replace(".000Z", "Z") : "";
  }

  /**
   * The verifier card the page shows before any consent (plan 4.5). Everything on it is text the page got from the
   * request; `textContent` puts it on the page, and no URL from it is ever loaded.
   */
  function cardOf(leaf, certificates, payload, prefix, target, signed) {
    return {
      clientId: payload === undefined ? "" : String(payload.client_id === undefined ? "" : payload.client_id),
      prefix: prefix,
      prefixExplanation: PREFIX_EXPLANATIONS[prefix] || "",
      signed: signed === true,
      subject: leaf === null ? [] : leaf.subject.attributes,
      issuer: leaf === null ? [] : leaf.issuer.attributes,
      sans: leaf === null ? [] : leaf.sans.dnsNames.map(function (name) { return "DNS:" + name; })
        .concat(leaf.sans.uris.map(function (uri) { return "URI:" + uri; })),
      validity: leaf === null ? null : { notBefore: isoOf(leaf.notBefore), notAfter: isoOf(leaf.notAfter) },
      key: leaf === null ? null : leaf.publicKey.kind === "ec" ? "EC " + leaf.publicKey.curve
        : "RSA " + leaf.publicKey.bits + " bits",
      chainLength: certificates.length,
      // filled by `checkSignedRequest` and `checkPlainRequest`, which are async and can digest
      fingerprints: { leaf: null, top: null },
      clientName: payload === undefined ? null : clientNameOf(payload),
      verifierInfo: payload === undefined ? null : verifierInfoOf(payload),
      responseUriHost: target === null ? "" : target.host,
      findingCount: 0,
    };
  }

  /** The SHA-256 fingerprints the card shows for the leaf and the topmost certificate (plan 4.5). */
  async function fingerprintsOf(certificates, card) {
    if (!certificates.length) return card;
    card.fingerprints.leaf = await X509.fingerprintSha256(certificates[0].der);
    card.fingerprints.top = await X509.fingerprintSha256(certificates[certificates.length - 1].der);
    return card;
  }

  /**
   * Checks a request that is a signed request object (fetched, pasted by value, or a link's `request=`).
   *
   * Options: `text`, `link` (`parseLink`'s params plus `scheme`/`kind` and its findings), `contentType`, `pageUrl`,
   * `now`, `keptIssuerAuthAlgs` (the COSE ids of the kept credentials' IssuerAuth algorithms).
   *
   * Returns `{ok: true, request, card, findings, error}` or `{ok: false, rule, message, findings}`. `error` is the
   * error response the wallet owes the verifier (VP section 8.5) once the checks above it pass; `null` otherwise.
   * Nothing is sent here.
   */
  async function checkSignedRequest(options) {
    var now = options.now instanceof Date ? options.now : new Date();
    var pageUrl = options.pageUrl instanceof URL ? options.pageUrl : new URL(String(options.pageUrl));
    var localPage = isLocalHost(pageUrl.hostname);
    var link = options.link || {};
    var findings = (link.findings || []).slice();
    var text = typeof options.text === "string" ? options.text : "";

    // R1: a compact JWS of three base64url parts, header and payload JSON objects, within the limits of plan 4.4
    if (utf8Length(text) > LIMITS.REQUEST_BYTES) {
      return refused("R1", "the request object is " + utf8Length(text) + " bytes, over the 64 KiB limit (plan 4.4).",
        findings);
    }
    var parts = text.split(".");
    if (parts.length !== 3) {
      return refused("R1", "the request object is not a compact JWS of three parts (JWS, RFC 7515 section 7.1; "
        + "OpenID4VP 1.0 section 5.10).", findings);
    }
    var header;
    var payload;
    var signature;
    try {
      header = JSON.parse(decodeUtf8(decodeBase64url(parts[0])));
      payload = JSON.parse(decodeUtf8(decodeBase64url(parts[1])));
      signature = decodeBase64url(parts[2]);
    } catch (error) {
      return refused("R1", "the request object's header or payload is not base64url JSON: " + error.message, findings);
    }
    if (!isObject(header) || !isObject(payload)) {
      return refused("R1", "the request object's header or payload is not a JSON object.", findings);
    }
    var depth = jsonDepth(payload, LIMITS.JSON_DEPTH);
    if (depth > LIMITS.JSON_DEPTH) {
      return refused("R1", "the request object nests " + depth + " levels, over the limit of " + LIMITS.JSON_DEPTH
        + " (plan 4.4).", findings);
    }

    // R2: the JWS type VP section 5 requires, and without which a wallet must not process the object. The comparison is
    // case-sensitive on purpose: VP pins the exact value "oauth-authz-req+jwt", and JWS `typ` is a media type whose
    // case a reader may not fold here without also accepting `JWT`-style spellings the text does not name.
    if (header.typ !== "oauth-authz-req+jwt") {
      return refused("R2", "the JWS typ is " + (header.typ === undefined ? "absent" : JSON.stringify(header.typ))
        + "; OpenID4VP 1.0 section 5 requires oauth-authz-req+jwt, and a wallet must not process a request object "
        + "without it.", findings);
    }

    // R1: the JWS `crit` header (RFC 7515 section 4.1.11). A `crit` entry names an extension the receiver must
    // understand before it may process the object, and this page understands none: refusing the object is the only
    // answer that cannot end in a signature or a claim being read under rules the page did not apply. A `crit` that is
    // not a non-empty array of strings is not a `crit` at all, and is refused for that reason.
    if (header.crit !== undefined) {
      if (!Array.isArray(header.crit) || !header.crit.length
          || !header.crit.every(function (name) { return typeof name === "string" && name.length > 0; })) {
        return refused("R1", "the JWS crit is not a non-empty array of header names (RFC 7515 section 4.1.11).",
          findings);
      }
      return refused("R1", "the JWS crit lists " + JSON.stringify(header.crit) + ", and this page understands no "
        + "JWS extension: RFC 7515 section 4.1.11 says a wallet must refuse such a request object rather than process "
        + "it with the extension ignored.", findings);
    }

    // R3: the link's client_id and the request object's must be identical, prefix included (VP section 5.10.1)
    if (typeof payload.client_id !== "string" || !payload.client_id.length) {
      return refused("R3", "the request object carries no client_id (OpenID4VP 1.0 section 5.1).", findings);
    }
    if (typeof link.clientId === "string" && link.clientId.length && link.clientId !== payload.client_id) {
      return refused("R3", "the link's client_id is " + JSON.stringify(link.clientId) + " and the request object's is "
        + JSON.stringify(payload.client_id) + "; they must be identical, including the prefix (OpenID4VP 1.0 section "
        + "5.10.1).", findings);
    }
    if (link.clientId === undefined) {
      // a pasted request object never had a link to name one, which is a different thing to say than a link that could
      // have named one and did not
      findings.push(link.kind === "by_value" && !link.scheme
        ? "this request object was pasted on its own, so nothing outside it named a client_id; this page took the one "
          + "the object carries, and the verifier's own signature is what stands behind it (OpenID4VP 1.0 section "
          + "5.9.3)."
        : "the link named no client_id, so this page took it from the request object (OpenID4VP 1.0 section "
          + "5.1 allows a request_uri link without one).");
    }

    // R4: a wallet_nonce the page sent must be the one the request object carries (VP section 5.10.1)
    if (typeof link.walletNonce === "string" && link.walletNonce.length
        && payload.wallet_nonce !== link.walletNonce) {
      return refused("R4", "this page sent wallet_nonce " + JSON.stringify(link.walletNonce) + " and the request object "
        + (payload.wallet_nonce === undefined ? "carries none" : "carries " + JSON.stringify(payload.wallet_nonce))
        + "; the verifier must use it, and the wallet must terminate request processing (OpenID4VP 1.0 section "
        + "5.10.1).", findings);
    }

    // R5: the audience, and the request object's own lifetime (VP section 5.8, RFC 9101 section 10.2)
    if (payload.aud !== undefined && !audienceIsSelfIssued(payload.aud)) {
      return refused("R5", "the request object's aud is " + JSON.stringify(payload.aud) + "; with no wallet metadata "
        + "sent, static discovery applies and aud must be " + SELF_ISSUED_AUDIENCE + " (OpenID4VP 1.0 section 5.8).",
        findings);
    }
    if (payload.exp !== undefined) {
      var exp = numericDate(payload.exp);
      if (exp === null) return refused("R5", "the request object's exp is not a NumericDate (RFC 9101 section 10.2).",
        findings);
      if (exp * 1000 <= now.getTime()) {
        return refused("R5", "the request object expired at " + new Date(exp * 1000).toISOString() + " (RFC 9101 section "
          + "10.2, exp).", findings);
      }
    }
    if (payload.iat !== undefined) {
      var iat = numericDate(payload.iat);
      if (iat === null) return refused("R5", "the request object's iat is not a NumericDate (RFC 9101 section 10.2).",
        findings);
      if (iat * 1000 > now.getTime() + CLOCK_SKEW_MS) {
        return refused("R5", "the request object's iat is " + new Date(iat * 1000).toISOString() + ", more than 5 "
          + "minutes ahead of this browser's clock (plan 4.5 R5).", findings);
      }
    }

    // the limits of plan 4.4: x5c and the DCQL counts. Everything over them is refused before anything is read.
    if (header.x5c !== undefined) {
      if (!Array.isArray(header.x5c)) return refused("R1", "the JWS x5c is not an array (RFC 7515 section 4.1.6).",
        findings);
      if (header.x5c.length === 0) return refused("R1", "the JWS x5c is empty (RFC 7515 section 4.1.6).", findings);
      if (header.x5c.length > LIMITS.X5C_CERTIFICATES) {
        return refused("R1", "the JWS x5c carries " + header.x5c.length + " certificates, over the limit of "
          + LIMITS.X5C_CERTIFICATES + " (plan 4.4).", findings);
      }
    }
    var breach = dcqlLimitBreach(payload.dcql_query);
    if (breach !== null) return refused("R1", "the DCQL query has " + breach + " (plan 4.4).", findings);

    // R9: which client identifier prefixes this wallet accepts at all (VP section 5.9.3, D-P5-03-9)
    var split = splitClientId(payload.client_id);
    var prefix = split.prefix;
    if (prefix === "origin") {
      return refused("R9", "the origin: client identifier prefix is refused: OpenID4VP 1.0 section 5.9.3 says a wallet "
        + "MUST NOT accept it.", findings);
    }
    if (prefix === "redirect_uri") {
      return refused("R9", "a redirect_uri: client identifier cannot be used with a signed request (OpenID4VP 1.0 "
        + "section 5.9.3), and this request object is signed.", findings);
    }
    if (prefix === "decentralized_identifier") {
      return refused("R9", "the decentralized_identifier: client identifier prefix is not supported by this demo wallet "
        + "(D-P5-03-9 (a)): run the verifier with its certificate signer, which gives x509_hash or x509_san_dns.",
        findings);
    }
    if (prefix === "verifier_attestation" || prefix === "openid_federation") {
      return refused("R9", "the " + prefix + ": client identifier prefix is not supported by this demo wallet "
        + "(plan 4.5 R9).", findings);
    }
    if (prefix === null) {
      return refused("R9", "the client_id has no recognised prefix, so it is a pre-registered identifier, which this "
        + "demo wallet does not have (plan 4.5 R9).", findings);
    }
    if (typeof split.value !== "string" || !split.value.length) {
      return refused("R9", "the client_id's " + prefix + ": prefix is followed by nothing.", findings);
    }

    // R10's algorithm half first: an alg this page does not verify is refused before any key is imported
    if (typeof header.alg !== "string" || X509.JWS_ALGORITHMS[header.alg] === undefined) {
      return refused("R10", "the JWS alg is " + (header.alg === undefined ? "absent" : JSON.stringify(header.alg))
        + "; this page verifies ES256, ES384, ES512, PS256 and RS256 (plan 4.5 R10). alg: none is not a signature.",
        findings);
    }
    if (!signature.length) {
      return refused("R1", "the request object's third part is empty: a signed request object carries its signature "
        + "(JWS, RFC 7515 section 7.1).", findings);
    }

    // R6 / R7: the verifier's certificate, bound to the client_id, and the JWS signed with its key
    if (header.x5c === undefined) {
      return refused(prefix === "x509_san_dns" ? "R6" : "R7", "the request object carries no x5c, so this page has no "
        + "certificate to check the signature with (" + prefix + " requires the verifier's leaf certificate: "
        + "OpenID4VP 1.0 section 5.9.3).", findings);
    }
    var certificates = [];
    for (var index = 0; index < header.x5c.length; index++) {
      var der;
      try {
        der = decodeBase64(header.x5c[index]);
      } catch (error) {
        return refused("R10", "x5c certificate " + index + " is not base64 (RFC 7515 section 4.1.6 requires base64, not "
          + "base64url).", findings);
      }
      if (der.length > LIMITS.X5C_CERTIFICATE_BYTES) {
        return refused("R1", "x5c certificate " + index + " is " + der.length + " bytes, over the limit of 8 KiB each "
          + "(plan 4.4).", findings);
      }
      try {
        certificates.push(X509.parse(der));
      } catch (error) {
        return refused("R10", "x5c certificate " + index + " does not parse as an X.509 certificate: " + error.message,
          findings);
      }
    }
    var leaf = certificates[0];
    if (prefix === "x509_san_dns") {
      if (!isDnsName(split.value)) {
        return refused("R6", "the client_id's value " + JSON.stringify(split.value) + " is not a DNS name (OpenID4VP "
          + "1.0 section 5.9.3).", findings);
      }
      var matches = leaf.sans.dnsNames.some(function (name) {
        return name.toLowerCase() === split.value.toLowerCase();
      });
      if (!matches) {
        return refused("R6", "the client_id says the verifier is " + split.value + ", and the leaf certificate's "
          + "dNSName subject alternative names are [" + leaf.sans.dnsNames.join(", ") + "] (OpenID4VP 1.0 section "
          + "5.9.3).", findings);
      }
    } else {
      if (!/^[A-Za-z0-9_-]{43}$/.test(split.value)) {
        return refused("R7", "the client_id's value is not the 43-character base64url SHA-256 hash of a certificate "
          + "(OpenID4VP 1.0 section 5.9.3).", findings);
      }
      var hash = encodeBase64url(new Uint8Array(await crypto.subtle.digest("SHA-256", leaf.der)));
      if (hash !== split.value) {
        return refused("R7", "the client_id's hash is " + split.value + " and the SHA-256 of the leaf certificate in "
          + "x5c is " + hash + " (OpenID4VP 1.0 section 5.9.3).", findings);
      }
    }
    var signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
    var verified = false;
    try {
      verified = await X509.verifyJws(signingInput, signature, leaf, header.alg);
    } catch (error) {
      // `verifyJws` answers false for a signature that does not verify, and throws only for a key the algorithm may not
      // use at all: an RSA key under 2048 bits (RFC 7518 section 3.3), which is R10's
      return refused("R10", error.message, findings);
    }
    if (!verified) {
      return refused(prefix === "x509_san_dns" ? "R6" : "R7", "the JWS does not verify with the leaf certificate's "
        + "public key (" + header.alg + "); OpenID4VP 1.0 section 5.9.3 requires the wallet to validate the signature.",
        findings);
    }

    // R10: what each certificate in the path must be (RFC 5280 sections 4.2, 6.1.4 and 6.1.5), then its validity, then
    // the link to the next one. The role a certificate's own extensions claim is read before any signature is tried: a
    // certificate that says it is not a CA, may not sign certificates, or permits fewer CAs below it than the chain has,
    // is wrong whatever its signature turns out to be.
    for (var position = 0; position < certificates.length; position++) {
      var fault = X509.certificateFault(certificates[position], position, certificates);
      if (fault !== null) return refused("R10", fault, findings);
    }
    for (var ensured = 0; ensured < certificates.length; ensured++) {
      var state = X509.validityOf(certificates[ensured], now, VALIDITY_SKEW_MS);
      if (state !== "valid") {
        return refused("R10", "x5c certificate " + ensured + " (" + certificates[ensured].subject.text + ") is "
          + (state === "expired" ? "expired: it ended " + isoOf(certificates[ensured].notAfter)
            : "not valid yet: it begins " + isoOf(certificates[ensured].notBefore))
          + " (RFC 5280 section 6.1.3 (a)(2), with a 5-minute skew).", findings);
      }
    }
    for (var link_index = 0; link_index + 1 < certificates.length; link_index++) {
      var child = certificates[link_index];
      var parent = certificates[link_index + 1];
      if (!X509.bytesEqual(child.issuer.der, parent.subject.der)) {
        return refused("R10", "x5c certificate " + link_index + "'s issuer (" + child.issuer.text + ") is not "
          + "certificate " + (link_index + 1) + "'s subject (" + parent.subject.text + "), so the chain does not "
          + "link (RFC 5280 section 6.1.3 (a)(4)).", findings);
      }
      var issued;
      try {
        issued = await X509.verifyIssuedBy(child, parent);
      } catch (error) {
        return refused("R10", "x5c certificate " + link_index + " cannot be verified with certificate "
          + (link_index + 1) + "'s key: " + error.message, findings);
      }
      if (!issued) {
        return refused("R10", "x5c certificate " + link_index + " is not signed by certificate " + (link_index + 1)
          + " (RFC 5280 section 6.1.3 (a)(1)).", findings);
      }
    }
    findSelfSigned(certificates, findings);

    // R8: the response_uri, and the host rules the client identifier prefix puts on it (VP 5.9.3, 8.2)
    var response = responseUriFault(payload.response_uri, localPage);
    if (response.target === undefined) return refused(response.rule, response.message, findings);
    var target = response.target;
    if (prefix === "x509_san_dns" && target.hostname.toLowerCase() !== split.value.toLowerCase()) {
      return refused("R8", "response_uri is on " + target.hostname + " and the client_id's DNS name is " + split.value
        + "; OpenID4VP 1.0 section 8.2 requires a response_uri the client may use as its redirect_uri, and section "
        + "5.9.3 ties that to the client identifier's name.", findings);
    }

    // R11: the response type and mode this wallet implements
    var shape = responseShapeFault(payload.response_type, payload.response_mode);
    if (shape !== null) return refused("R11", shape, findings);

    var responseMode = payload.response_mode;
    var request = {
      signed: true,
      clientId: payload.client_id,
      prefix: prefix,
      prefixValue: split.value,
      nonce: payload.nonce,
      state: payload.state,
      responseUri: payload.response_uri,
      responseMode: responseMode,
      responseType: payload.response_type,
      aud: payload.aud,
      iat: payload.iat,
      exp: payload.exp,
      walletNonce: payload.wallet_nonce,
      dcqlQuery: payload.dcql_query,
      scope: payload.scope,
      clientMetadata: payload.client_metadata,
      x5chain: certificates.map(function (certificate) { return certificate.der; }),
      leaf: leaf,
      top: certificates[certificates.length - 1],
      link: {
        scheme: link.scheme === undefined ? null : link.scheme,
        kind: link.kind === undefined ? "request_uri" : link.kind,
        requestUri: link.requestUri === undefined ? null : link.requestUri,
        requestUriMethod: link.requestUriMethod === undefined ? null : link.requestUriMethod,
      },
    };

    var error = errorCaseOf(payload, responseMode);
    addFindings(payload, request, leaf, certificates, options, findings);
    var card = await fingerprintsOf(certificates, cardOf(leaf, certificates, payload, prefix, target, true));
    card.findingCount = findings.length;
    return { ok: true, request: request, card: card, findings: findings, error: error };
  }

  /** HAIP 1.0 section 5: a verifier's signing certificate must not be self-signed, and its anchor must not be in x5c. */
  function findSelfSigned(certificates, findings) {
    certificates.forEach(function (certificate, index) {
      if (X509.bytesEqual(certificate.issuer.der, certificate.subject.der)) {
        findings.push("x5c certificate " + index + " (" + certificate.subject.text + ") is self-signed; HAIP 1.0 "
          + "section 5 says the verifier's signing certificate is not self-signed and its trust anchor is not in x5c.");
      }
    });
  }

  /**
   * The error response the wallet owes the verifier once the checks pass (plan 4.5's table; VP section 8.5). The page
   * shows it with a "Send error response" button and sends nothing until that is pressed.
   */
  function errorCaseOf(payload, responseMode) {
    if (typeof payload.nonce !== "string" || !payload.nonce.length) {
      return { error: "invalid_request", description: "the request object carries no nonce; the wallet needs it for the "
        + "session transcript (OpenID4VP 1.0 section 5.1 and B.2.6.1)." };
    }
    if (payload.redirect_uri !== undefined) {
      return { error: "invalid_request", description: "the request object carries redirect_uri together with "
        + responseMode + "; OpenID4VP 1.0 section 8.2 requires the wallet to answer invalid_request." };
    }
    if (payload.dcql_query === undefined) {
      return payload.scope !== undefined
        ? { error: "invalid_scope", description: "this wallet presents by DCQL query, and the request names only the "
          + "scope " + JSON.stringify(payload.scope) + " (OpenID4VP 1.0 section 6.1)." }
        : { error: "invalid_request", description: "the request object carries no dcql_query (OpenID4VP 1.0 section "
          + "6.1)." };
    }
    if (!isObject(payload.dcql_query)) {
      return { error: "invalid_request", description: "dcql_query is not a JSON object (OpenID4VP 1.0 section 6.1)." };
    }
    if (payload.transaction_data !== undefined) {
      return { error: "invalid_transaction_data", description: "this wallet does not process transaction_data "
        + "(OpenID4VP 1.0 section 8.5)." };
    }
    return null;
  }

  /** The findings: shown on the card, never blocking (plan 4.5). */
  function addFindings(payload, request, leaf, certificates, options, findings) {
    var link = options.link || {};
    if (payload.aud === undefined) {
      findings.push("no aud: OpenID4VP 1.0 section 5.8 requires https://self-issued.me/v2 when the verifier uses static "
        + "discovery. Multipaz's request objects carry none (plan 2.1).");
    }
    if (payload.state === undefined) {
      findings.push("no state: OpenID4VP 1.0 section 5.1 makes state optional, and without it a response cannot be "
        + "correlated with a session.");
    }
    if (link.scheme === "haip-vp" && (request.link.kind !== "request_uri" || request.responseMode !== "direct_post.jwt")) {
      findings.push("a haip-vp link whose request is not signed by request_uri or is not direct_post.jwt; HAIP 1.0 "
        + "section 5.1 wants both.");
    }
    if (request.prefix === "x509_san_dns" && typeof link.requestUri === "string") {
      var host = "";
      try {
        host = new URL(link.requestUri).hostname;
      } catch (error) {
        host = "";
      }
      if (host.toLowerCase() !== request.prefixValue.toLowerCase()) {
        findings.push("the request_uri is on " + (host || "an unreadable host") + ", not on the client_id's DNS name "
          + request.prefixValue + "; OpenID4VP 1.0 section 15.8.1 asks a wallet to be wary of an unrecognised request "
          + "URI endpoint.");
      }
    }
    var mediaType = String(options.contentType || "").split(";")[0].trim().toLowerCase();
    if (mediaType && mediaType !== "application/oauth-authz-req+jwt") {
      findings.push("the request object's media type is " + JSON.stringify(mediaType) + ", not "
        + "application/oauth-authz-req+jwt (OpenID4VP 1.0 section 5.10 names that media type, and the page asks for it "
        + "with its Accept header)." + (mediaType === "application/jwt"
          ? " application/jwt is the generic JOSE type a verifier falls back to; the request object is still checked, but "
            + "a verifier that names the specific type is the one VP 5.10 describes."
          : ""));
    }
    var algValues = payload.client_metadata && isObject(payload.client_metadata)
      && isObject(payload.client_metadata.vp_formats_supported)
      && isObject(payload.client_metadata.vp_formats_supported.mso_mdoc)
      ? payload.client_metadata.vp_formats_supported.mso_mdoc.issuerauth_alg_values : undefined;
    var kept = options.keptIssuerAuthAlgs;
    if (Array.isArray(algValues) && Array.isArray(kept) && kept.length) {
      var supported = kept.some(function (id) { return algValues.indexOf(id) >= 0; });
      if (!supported) {
        findings.push("the verifier's mso_mdoc issuerauth_alg_values " + JSON.stringify(algValues) + " does not list "
          + JSON.stringify(kept) + ", the algorithm of the credential this wallet holds (OpenID4VP 1.0 appendix B.2.2).");
      }
    }
    unknownParametersFinding(payload, findings);
  }

  /**
   * Checks a request that is not a request object at all: the plain parameters of a `redirect_uri:` client identifier,
   * which VP section 5.9.3 says cannot be signed. R1's JWS shape, R2, R3, R4 and R10 are about a JWS and do not apply;
   * R8 is the check that binds the response_uri to the client identifier, R11 is about the response itself, and the
   * limits of plan 4.4 still are: a query string is as good a place to hide a hostile DCQL document as a payload is,
   * so `jsonDepth` and `dcqlLimitBreach` run here too.
   */
  async function checkPlainRequest(options) {
    var pageUrl = options.pageUrl instanceof URL ? options.pageUrl : new URL(String(options.pageUrl));
    var localPage = isLocalHost(pageUrl.hostname);
    // the link's own findings travel with the request, as they do for a signed one: the intake panel shows them
    var findings = (options.findings || (options.link && options.link.findings) || []).slice();
    // a plain request's parameters arrive as the query string's text: the DCQL query is JSON inside one of them
    var params = Object.assign({}, options.plain);
    if (typeof params.dcql_query === "string") {
      try {
        params.dcql_query = JSON.parse(params.dcql_query);
      } catch (error) {
        // left as the string it is, which `errorCaseOf` then refuses as not an object
      }
    }
    var clientId = params.client_id;
    var split = splitClientId(clientId);
    if (split.prefix !== "redirect_uri") {
      return refused("R9", "plain parameters are accepted only with the redirect_uri: client identifier prefix "
        + "(OpenID4VP 1.0 section 5.9.3).", findings);
    }
    var response = responseUriFault(params.response_uri, localPage);
    if (response.target === undefined) return refused(response.rule, response.message, findings);
    var target = response.target;
    var depth = jsonDepth(params, LIMITS.JSON_DEPTH);
    if (depth > LIMITS.JSON_DEPTH) {
      return refused("R1", "the request nests " + depth + " levels, over the limit of " + LIMITS.JSON_DEPTH
        + " (plan 4.4).", findings);
    }
    var breach = dcqlLimitBreach(params.dcql_query);
    if (breach !== null) return refused("R1", "the DCQL query has " + breach + " (plan 4.4).", findings);
    // R11: both halves of the response have to be named, exactly as for a signed request
    var shape = responseShapeFault(params.response_type, params.response_mode);
    if (shape !== null) return refused("R11", shape, findings);
    // VP section 5.9.3: with this prefix the response_uri is the client identifier, so it is the same URI. Compared as
    // written, not by origin and path: the identifier is a URI, and two spellings of one endpoint are two identifiers.
    if (params.response_uri !== split.value) {
      return refused("R8", "response_uri is " + params.response_uri + " and the client_id is " + clientId + "; with the "
        + "redirect_uri: prefix they must be the same URI (OpenID4VP 1.0 sections 5.9.3 and 8.2).", findings);
    }
    findings.push("this request is unsigned: the redirect_uri: client identifier prefix cannot be signed (OpenID4VP "
      + "1.0 section 5.9.3), so there is no verifier certificate to show.");
    var responseMode = params.response_mode;
    var request = {
      signed: false,
      clientId: clientId,
      prefix: "redirect_uri",
      prefixValue: split.value,
      nonce: params.nonce,
      state: params.state,
      responseUri: params.response_uri,
      responseMode: responseMode,
      responseType: params.response_type,
      aud: params.aud,
      walletNonce: undefined,
      dcqlQuery: params.dcql_query,
      scope: params.scope,
      clientMetadata: undefined,
      x5chain: [],
      leaf: null,
      top: null,
      link: {
        scheme: options.scheme === undefined ? null : options.scheme,
        kind: "plain",
        requestUri: null,
        requestUriMethod: null,
      },
    };
    var error = errorCaseOf(params, responseMode);
    unknownParametersFinding(params, findings);
    var card = await fingerprintsOf([], cardOf(null, [], params, "redirect_uri", target, false));
    card.findingCount = findings.length;
    return { ok: true, request: request, card: card, findings: findings, error: error };
  }

  /**
   * Checks one request, whatever form it arrived in. `options` is
   * `{text, plain, link, scheme, contentType, pageUrl, now, keptIssuerAuthAlgs}`; see `checkSignedRequest` and
   * `checkPlainRequest`. A verifier must not be able to make this throw, so an unexpected failure is a refusal.
   */
  async function checkRequest(options) {
    try {
      if (isObject(options.plain)) return await checkPlainRequest(options);
      return await checkSignedRequest(options);
    } catch (error) {
      return refused("R1", "the request could not be read: " + (error && error.message ? error.message : String(error)),
        (options.link && options.link.findings) || []);
    }
  }

  return {
    LIMITS: LIMITS,
    SCHEMES: SCHEMES,
    PREFIXES: PREFIXES,
    SELF_ISSUED_AUDIENCE: SELF_ISSUED_AUDIENCE,
    CLOCK_SKEW_MS: CLOCK_SKEW_MS,
    VALIDITY_SKEW_MS: VALIDITY_SKEW_MS,
    isRequestObject: isRequestObject,
    parseLink: parseLink,
    fetchRequestObject: fetchRequestObject,
    checkRequest: checkRequest,
    splitClientId: splitClientId,
    decodeBase64url: decodeBase64url,
    decodeBase64: decodeBase64,
    encodeBase64url: encodeBase64url,
    jsonDepth: jsonDepth,
  };
})();
