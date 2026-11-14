/*
 * ISO/IEC 18013-5 IssuerSigned reading and the checks a credential must pass before this browser keeps it (P5-03a,
 * plan section 4.2). Nothing here re-encodes an issued item: an IssuerSignedItemBytes is returned as the exact byte
 * range it arrived in, because the digest the issuer signed is computed over those bytes (ISO/IEC 18013-5 9.1.2.5), and
 * a DeviceResponse later carries the same slice.
 *
 * Depends on cbor.js (the global `Cbor`): `Cbor.spans` supplies the byte ranges, `Cbor.decode` the values.
 */
var Mdoc = (function () {
  "use strict";

  /** The largest IssuerSigned the page keeps, and how many credentials it keeps (plan 4.2, check 5). */
  var MAX_ISSUER_SIGNED_BYTES = 256 * 1024;
  var MAX_CREDENTIALS = 50;
  /** The digest algorithms an MSO may name (ISO/IEC 18013-5 9.1.2.4). */
  var DIGEST_ALGORITHMS = ["SHA-256", "SHA-384", "SHA-512"];

  /** The key of a spans entry: its path, in one string. */
  function pathKey(path) {
    return JSON.stringify(path);
  }

  function bytesOf(input) {
    return input instanceof Uint8Array ? input : new Uint8Array(input);
  }

  function base64url(bytes) {
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /** The first byte pair of a range: whether those bytes are a tag-24 (encoded CBOR data item) head. */
  function isTag24(bytes, range) {
    return range !== undefined && range.end - range.start >= 2
      && bytes[range.start] === 0xd8 && bytes[range.start + 1] === 0x18;
  }

  /** A COSE header label's value from the protected header, else from the unprotected one. */
  function headerValue(protectedBytes, unprotected, label) {
    if (protectedBytes && protectedBytes.length) {
      var header = Cbor.decode(protectedBytes);
      if (header && typeof header === "object" && header[label] !== undefined) return header[label];
    }
    if (unprotected && typeof unprotected === "object" && unprotected[label] !== undefined) return unprotected[label];
    return undefined;
  }

  /**
   * Reads one IssuerSigned (ISO/IEC 18013-5 8.3.2.1.2) without changing a byte:
   * `{nameSpaces: {ns: [{elementIdentifier, digestID, elementValue, raw}]}, issuerAuth: {raw, alg, x5chain, mso}}`.
   * `raw` is the exact `[start, end)` slice of `input`, so the tag-24 IssuerSignedItemBytes and the IssuerAuth can be
   * carried into a DeviceResponse exactly as issued. Throws a message naming what is wrong.
   */
  function readIssuerSigned(input) {
    var bytes = bytesOf(input);
    var walked = Cbor.spans(bytes, 3);
    var value = walked.value;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("the credential is not an IssuerSigned map");
    }
    var ranges = new Map();
    walked.ranges.forEach(function (range) { ranges.set(pathKey(range.path), range); });

    var issuerAuthRange = ranges.get(pathKey(["issuerAuth"]));
    if (issuerAuthRange === undefined) throw new Error("the credential has no issuerAuth");
    var issuerAuth = value.issuerAuth;
    if (!Array.isArray(issuerAuth) || issuerAuth.length !== 4) {
      throw new Error("issuerAuth is not a COSE_Sign1 array of four elements");
    }
    // ISO/IEC 18013-5 9.1.2.4: the MSO inside issuerAuth's payload is tag 24, and its bytes say so
    var payloadRange = ranges.get(pathKey(["issuerAuth", 2]));
    if (!isTag24(bytes, payloadRange)) {
      throw new Error("the issuerAuth payload is not a tag-24 MSO (ISO/IEC 18013-5 9.1.2.4)");
    }
    var mso = issuerAuth[2];
    if (!mso || typeof mso !== "object" || Array.isArray(mso)) {
      throw new Error("the issuerAuth payload is not an MSO map");
    }

    var x5chain = [];
    var chain = headerValue(issuerAuth[0], issuerAuth[1], "33");
    if (chain !== undefined) {
      if (!Array.isArray(chain) || !chain.every(function (der) { return der instanceof Uint8Array; })) {
        throw new Error("the issuerAuth x5chain is not an array of certificates");
      }
      x5chain = chain;
    }

    var nameSpaces = {};
    var decoded = value.nameSpaces === undefined ? {} : value.nameSpaces;
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("IssuerSigned nameSpaces is not a map");
    }
    Object.keys(decoded).forEach(function (namespace) {
      var items = decoded[namespace];
      if (!Array.isArray(items)) throw new Error("the namespace " + namespace + " is not an array of IssuerSignedItems");
      nameSpaces[namespace] = items.map(function (item, index) {
        if (!item || typeof item !== "object" || Array.isArray(item)
            || typeof item.elementIdentifier !== "string" || typeof item.digestID !== "number") {
          throw new Error("an IssuerSignedItem in " + namespace + " is not an element map");
        }
        var itemRange = ranges.get(pathKey(["nameSpaces", namespace, index]));
        if (itemRange === undefined || !isTag24(bytes, itemRange)) {
          throw new Error("the IssuerSignedItem " + namespace + "/" + item.elementIdentifier
            + " is not a tag-24 IssuerSignedItemBytes");
        }
        return {
          elementIdentifier: item.elementIdentifier,
          digestID: item.digestID,
          elementValue: item.elementValue,
          raw: bytes.subarray(itemRange.start, itemRange.end),
        };
      });
    });

    var issuerAuthStart = issuerAuthRange.start, issuerAuthEnd = issuerAuthRange.end;
    return {
      nameSpaces: nameSpaces,
      issuerAuth: {
        raw: bytes.subarray(issuerAuthStart, issuerAuthEnd),
        alg: headerValue(issuerAuth[0], issuerAuth[1], "1"),
        x5chain: x5chain,
        mso: mso,
      },
    };
  }

  function refuse(code, message) {
    return { ok: false, code: code, message: message };
  }

  async function digestOf(algorithm, bytes) {
    return new Uint8Array(await crypto.subtle.digest(algorithm, bytes));
  }

  /**
   * The checks of plan 4.2 that decide whether a just-issued credential may be kept, in order, each with its own
   * message. Returns `{ok: true, ...}` with what the record stores, or `{ok: false, code, message}`; a refusal keeps
   * nothing.
   *
   * `options` is `{issuerSigned, doctype, publicJwk, stored}`: the bytes as received, the configuration's `doctype` from
   * the issuer metadata the run fetched, this browser's holder public JWK (`{kty, crv, x, y}` base64url) and how many
   * credentials are already kept.
   */
  async function checkKeepable(options) {
    var bytes = bytesOf(options.issuerSigned);
    var stored = typeof options.stored === "number" ? options.stored : 0;
    // check 5: the limits, cheapest first
    if (stored >= MAX_CREDENTIALS) {
      return refuse("limit", "This browser already keeps " + stored + " credentials; delete one first (at most "
        + MAX_CREDENTIALS + ").");
    }
    if (bytes.length > MAX_ISSUER_SIGNED_BYTES) {
      return refuse("size", "The credential is " + bytes.length + " bytes; at most " + MAX_ISSUER_SIGNED_BYTES
        + " (256 KiB) is kept.");
    }
    // check 1: an IssuerSigned whose issuerAuth payload is a tag-24 MSO
    var read;
    try {
      read = readIssuerSigned(bytes);
    } catch (error) {
      return refuse("issuer-signed", "The credential is not an IssuerSigned with a tag-24 MSO in issuerAuth: "
        + error.message);
    }
    var mso = read.issuerAuth.mso;
    if (typeof mso.docType !== "string" || !mso.docType) {
      return refuse("issuer-signed", "The credential's MSO names no docType.");
    }
    // check 2: the docType the configuration issues
    if (typeof options.doctype !== "string" || !options.doctype) {
      return refuse("doctype", "The issuer metadata names no doctype for this configuration, so the credential"
        + " cannot be checked against it.");
    }
    if (mso.docType !== options.doctype) {
      return refuse("doctype", "The credential's docType is " + JSON.stringify(mso.docType)
        + ", not this configuration's " + JSON.stringify(options.doctype) + ".");
    }
    // check 3: the MSO's deviceKey is this browser's P-256 key (ISO/IEC 18013-5 9.1.2.4)
    var deviceKey = mso.deviceKeyInfo && mso.deviceKeyInfo.deviceKey;
    if (!deviceKey || typeof deviceKey !== "object") {
      return refuse("device-key", "The credential's MSO carries no deviceKey.");
    }
    if (deviceKey["1"] !== 2) {
      return refuse("device-key", "The credential's deviceKey is not an EC2 COSE key (label 1 must be 2).");
    }
    if (deviceKey["-1"] !== 1) {
      return refuse("device-key", "The credential's deviceKey is not a P-256 key (label -1 must be 1); this page holds"
        + " P-256 keys only.");
    }
    if (!(deviceKey["-2"] instanceof Uint8Array) || !(deviceKey["-3"] instanceof Uint8Array)) {
      return refuse("device-key", "The credential's deviceKey carries no P-256 coordinates (labels -2 and -3).");
    }
    var publicJwk = options.publicJwk || {};
    if (base64url(deviceKey["-2"]) !== publicJwk.x || base64url(deviceKey["-3"]) !== publicJwk.y) {
      return refuse("device-key", "The credential's deviceKey is not this browser's key: it was issued to another"
        + " holder.");
    }
    // check 4: every IssuerSignedItemBytes hashes to its valueDigests entry, over the bytes as received
    var algorithm = mso.digestAlgorithm;
    if (DIGEST_ALGORITHMS.indexOf(algorithm) < 0) {
      return refuse("digest", "The credential's MSO names the digest algorithm " + JSON.stringify(algorithm)
        + "; SHA-256, SHA-384 and SHA-512 are supported.");
    }
    var valueDigests = mso.valueDigests;
    for (var namespace of Object.keys(read.nameSpaces)) {
      var byDigestId = valueDigests && valueDigests[namespace];
      if (!byDigestId || typeof byDigestId !== "object") {
        return refuse("digest", "The credential's MSO has no valueDigests for the namespace " + namespace + ".");
      }
      var items = read.nameSpaces[namespace];
      for (var item of items) {
        var expected = byDigestId[String(item.digestID)];
        var actual = await digestOf(algorithm, item.raw);
        if (!(expected instanceof Uint8Array) || base64url(expected) !== base64url(actual)) {
          return refuse("digest", "The IssuerSignedItem " + namespace + "/" + item.elementIdentifier
            + " does not hash to the MSO's valueDigest " + item.digestID + ".");
        }
      }
    }
    var validity = mso.validityInfo || {};
    return {
      ok: true,
      docType: mso.docType,
      validFrom: typeof validity.validFrom === "string" ? validity.validFrom : null,
      validUntil: typeof validity.validUntil === "string" ? validity.validUntil : null,
    };
  }

  return {
    readIssuerSigned: readIssuerSigned,
    checkKeepable: checkKeepable,
    MAX_ISSUER_SIGNED_BYTES: MAX_ISSUER_SIGNED_BYTES,
    MAX_CREDENTIALS: MAX_CREDENTIALS,
  };
})();
