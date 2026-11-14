/*
 * ISO/IEC 18013-5 IssuerSigned reading and the checks a credential must pass before this browser keeps it (P5-03a,
 * plan section 4.2). Nothing here re-encodes an issued item: an IssuerSignedItemBytes is returned as the exact byte
 * range it arrived in, because the digest the issuer signed is computed over those bytes (ISO/IEC 18013-5 9.1.2.5), and
 * a DeviceResponse later carries the same slice.
 *
 * Depends on cbor.js (the global `Cbor`): `Cbor.spans` supplies the byte ranges, `Cbor.tagged` the tag of a data item,
 * `Cbor.decode` the values.
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

  /**
   * Whether a byte range is a tag-24 data item. The tag is read by its numeric value, so the non-preferred head
   * (`d9 00 18`) is the same tag 24 as `d8 18` (RFC 8949 3.1); the bytes are not inspected any further than that.
   */
  function isTag24(bytes, range) {
    if (range === undefined) return false;
    var tagged = Cbor.tagged(bytes.subarray(range.start, range.end));
    return tagged !== null && tagged.tag === 24;
  }

  /**
   * The Mobile Security Object of an issuerAuth payload. ISO/IEC 18013-5 9.1.2.4 makes the COSE_Sign1 payload a byte
   * string, and RFC 8949 3.4.5.1 makes its content `#6.24(bstr .cbor MobileSecurityObject)`: the tag is required here,
   * never inferred from the payload's shape, and the MSO is decoded from the bstr the tag wraps. This is the layout
   * Certify's own MdocFormatter writes (`CoseEnvelope` signs the tag-24 bytes, and the envelope carries them as a
   * bstr), so a real Certify mDL reads exactly like a hand-built one.
   */
  function msoOf(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new Error("the issuerAuth payload is not a byte string (ISO/IEC 18013-5 9.1.2.4)");
    }
    var tagged = Cbor.tagged(payload);
    if (tagged === null || tagged.tag !== 24) {
      throw new Error("the issuerAuth payload is not a tag-24 MSO (ISO/IEC 18013-5 9.1.2.4)");
    }
    if (tagged.end !== payload.length) {
      throw new Error("the issuerAuth payload is not exactly one tag-24 MSO item");
    }
    var wrapped = Cbor.decode(tagged.content);
    if (!(wrapped instanceof Uint8Array)) {
      throw new Error("the tag-24 MSO content is not a byte string (ISO/IEC 18013-5 9.1.2.4)");
    }
    var mso = Cbor.decode(wrapped);
    if (!mso || typeof mso !== "object" || Array.isArray(mso)) throw new Error("the issuerAuth payload is not an MSO map");
    return mso;
  }

  /** The major type of the data item a range starts with (RFC 8949 3.1); a tag is 6, whatever it carries. */
  function majorAt(bytes, range) {
    return bytes[range.start] >> 5;
  }

  var MAJOR_NAMES = ["an unsigned integer", "a negative integer", "a byte string", "a text string", "an array", "a map",
    "a tag", "a simple value"];

  /**
   * Requires the data item at a range to be of one major type, so a tag around it is refused: the decoder resolves most
   * tags to the value they carry (`#6.24(bstr)` decodes as the embedded item, any unknown tag as its content), so the
   * decoded value alone cannot say whether the bytes were tagged.
   */
  function requireMajor(bytes, range, major, what) {
    if (range === undefined) throw new Error(what + " is missing");
    var found = majorAt(bytes, range);
    if (found !== major) throw new Error(what + " is " + MAJOR_NAMES[found] + ", not " + MAJOR_NAMES[major]);
  }

  /**
   * The ranges of a `Cbor.spans` walk by path. Two items at one path would leave a reader holding one range while the
   * checks ran on the other, so a second one is refused rather than kept.
   */
  function rangesByPath(walked) {
    var ranges = new Map();
    walked.ranges.forEach(function (range) {
      var key = pathKey(range.path);
      if (ranges.has(key)) throw new Error("two data items sit at " + key + "; the reader cannot tell which one was checked");
      ranges.set(key, range);
    });
    return ranges;
  }

  /** The keys `Cbor.spans` recorded for the map at {@code path}. */
  function keysAt(walked, path) {
    var at = pathKey(path);
    return walked.keys.filter(function (entry) { return pathKey(entry.path) === at; });
  }

  /**
   * One COSE header map, walked so its labels keep their types (RFC 9052 section 3: `label = int / tstr`; the decoder
   * renders the integer 33 and the text "33" alike, and only the key's major type tells them apart).
   */
  function headerOf(bytes, what) {
    var walked = Cbor.spans(bytes, 2);
    if (bytes[0] >> 5 !== 5) throw new Error("the issuerAuth " + what + " is not a map (RFC 9052 section 3)");
    return { bytes: bytes, walked: walked, ranges: rangesByPath(walked) };
  }

  /** The value of an integer label in one header, with its range there; `undefined` when the label is absent. */
  function intLabel(header, label) {
    if (header === null) return undefined;
    var entry = keysAt(header.walked, []).filter(function (key) { return key.key === String(label); })[0];
    // a text label that happens to read "33" is another label (RFC 9052 section 3), not x5chain
    if (entry === undefined || entry.major !== (label < 0 ? 1 : 0)) return undefined;
    return { header: header, value: header.walked.value[String(label)], range: header.ranges.get(pathKey([String(label)])) };
  }

  /** A header label from the protected header, else from the unprotected one (RFC 9052 section 3). */
  function headerValue(protectedHeader, unprotectedHeader, label) {
    var found = intLabel(protectedHeader, label);
    return found !== undefined ? found : intLabel(unprotectedHeader, label);
  }

  /**
   * The certificates of an {@code x5chain} header (RFC 9360 section 2: `COSE_X509 = bstr / [2*certs: bstr]`), always as
   * a list of DER byte strings. The bstr form is one certificate, which is what Certify emits for a DSC-only chain. The
   * array form carries two or more: a one-element array is not a COSE_X509, so it is refused rather than read. Each
   * certificate's major type is read from its bytes, so a tag around one is refused too.
   */
  function x5chainOf(found) {
    if (found === undefined) return [];
    var bytes = found.header.bytes;
    var major = majorAt(bytes, found.range);
    if (major === 2) return [found.value];
    if (major === 4 && Array.isArray(found.value) && found.value.length >= 2) {
      found.value.forEach(function (der, index) {
        requireMajor(bytes, found.header.ranges.get(pathKey(["33", index])), 2,
          "x5chain certificate " + index + " (RFC 9360 section 2)");
      });
      return found.value;
    }
    throw new Error("the issuerAuth x5chain is not a certificate (a bstr) or an array of two or more certificates"
      + " (RFC 9360 section 2: COSE_X509 = bstr / [2*certs: bstr])");
  }

  /**
   * Reads one IssuerSigned (ISO/IEC 18013-5 8.3.2.1.2) without changing a byte:
   * `{nameSpaces: {ns: [{elementIdentifier, digestID, elementValue, raw}]}, issuerAuth: {raw, alg, x5chain, mso}}`.
   * `raw` is the exact `[start, end)` slice of `input`, so the tag-24 IssuerSignedItemBytes and the IssuerAuth can be
   * carried into a DeviceResponse exactly as issued. Throws a message naming what is wrong.
   *
   * Every structural check reads the bytes a `raw` slice is cut from, not only the decoded value: the decoder resolves
   * tags to what they carry and renders keys of different types alike, so a value can look right while its bytes are a
   * tagged item, a map key's contents or a second item at the same path. Each of those is refused:
   * - the IssuerSigned and `nameSpaces` keys are text strings (`IssuerSigned = {? "nameSpaces": IssuerNameSpaces,
   *   "issuerAuth": IssuerAuth}`, `NameSpace = tstr`), and IssuerSigned has no other key;
   * - no path carries two data items;
   * - `issuerAuth` is a COSE_Sign1 array, untagged or tag 18 (RFC 9052 section 4.2), whose four elements are a bstr, a
   *   map, a bstr and a bstr, each untagged; the protected header's content is empty or a map (RFC 9052 section 3);
   * - each IssuerSignedItemBytes is tag 24 (ISO/IEC 18013-5 8.3.2.1.2).
   */
  function readIssuerSigned(input) {
    var bytes = bytesOf(input);
    var walked = Cbor.spans(bytes, 3);
    var value = walked.value;
    if (!bytes.length || majorAt(bytes, { start: 0 }) !== 5 || !value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("the credential is not an IssuerSigned map");
    }
    keysAt(walked, []).forEach(function (key) {
      if (key.major !== 3) {
        throw new Error("an IssuerSigned key is " + MAJOR_NAMES[key.major] + ", not a text string (ISO/IEC 18013-5 8.3.2.1.2)");
      }
      if (key.key !== "nameSpaces" && key.key !== "issuerAuth") {
        throw new Error("IssuerSigned carries the key " + JSON.stringify(key.key) + ", which ISO/IEC 18013-5 8.3.2.1.2"
          + " does not define");
      }
    });
    keysAt(walked, ["nameSpaces"]).forEach(function (key) {
      if (key.major !== 3) {
        throw new Error("a nameSpaces key is " + MAJOR_NAMES[key.major] + ", not a text string (NameSpace = tstr,"
          + " ISO/IEC 18013-5 8.3.2.1.2)");
      }
    });
    var ranges = rangesByPath(walked);

    // RFC 9052 4.2: COSE_Sign1 = [protected, unprotected, payload, signature], untagged or #6.18 (COSE_Sign1_Tagged).
    // `raw` keeps whichever of the two arrived.
    var issuerAuthRange = ranges.get(pathKey(["issuerAuth"]));
    if (issuerAuthRange === undefined) throw new Error("the credential has no issuerAuth");
    var outer = Cbor.tagged(bytes.subarray(issuerAuthRange.start, issuerAuthRange.end));
    if (outer !== null && outer.tag !== 18) {
      throw new Error("issuerAuth is wrapped in tag " + String(outer.tag) + "; a COSE_Sign1 is untagged or tag 18"
        + " (RFC 9052 section 4.2)");
    }
    var arrayMajor = outer === null ? majorAt(bytes, issuerAuthRange) : outer.content[0] >> 5;
    var issuerAuth = value.issuerAuth;
    if (arrayMajor !== 4 || !Array.isArray(issuerAuth) || issuerAuth.length !== 4) {
      throw new Error("issuerAuth is not a COSE_Sign1 array of four elements");
    }
    [[2, "the protected header"], [5, "the unprotected header"], [2, "the payload"], [2, "the signature"]]
      .forEach(function (expected, index) {
        requireMajor(bytes, ranges.get(pathKey(["issuerAuth", index])), expected[0],
          "issuerAuth element " + index + " (" + expected[1] + ", RFC 9052 section 4.2)");
      });
    // ISO/IEC 18013-5 9.1.2.4: element 2 is the payload, a bstr holding #6.24(bstr .cbor MSO)
    var mso = msoOf(issuerAuth[2]);
    // RFC 9052 3: protected = bstr .cbor header_map / bstr .size 0
    var protectedHeader = issuerAuth[0].length ? headerOf(issuerAuth[0], "protected header") : null;
    var unprotectedRange = ranges.get(pathKey(["issuerAuth", 1]));
    var unprotectedHeader = headerOf(bytes.subarray(unprotectedRange.start, unprotectedRange.end), "unprotected header");
    var x5chain = x5chainOf(headerValue(protectedHeader, unprotectedHeader, 33));
    var alg = headerValue(protectedHeader, unprotectedHeader, 1);

    var nameSpaces = {};
    var decoded = value.nameSpaces === undefined ? {} : value.nameSpaces;
    if (value.nameSpaces !== undefined) requireMajor(bytes, ranges.get(pathKey(["nameSpaces"])), 5, "IssuerSigned nameSpaces");
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("IssuerSigned nameSpaces is not a map");
    }
    Object.keys(decoded).forEach(function (namespace) {
      var items = decoded[namespace];
      if (!Array.isArray(items)) throw new Error("the namespace " + namespace + " is not an array of IssuerSignedItems");
      requireMajor(bytes, ranges.get(pathKey(["nameSpaces", namespace])), 4, "the namespace " + namespace);
      nameSpaces[namespace] = items.map(function (item, index) {
        if (!item || typeof item !== "object" || Array.isArray(item)
            || typeof item.elementIdentifier !== "string" || typeof item.digestID !== "number") {
          throw new Error("an IssuerSignedItem in " + namespace + " is not an element map");
        }
        var itemRange = ranges.get(pathKey(["nameSpaces", namespace, index]));
        if (!isTag24(bytes, itemRange)) {
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

    return {
      nameSpaces: nameSpaces,
      issuerAuth: {
        raw: bytes.subarray(issuerAuthRange.start, issuerAuthRange.end),
        alg: alg === undefined ? undefined : alg.value,
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
