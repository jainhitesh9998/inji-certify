/*
 * ISO/IEC 18013-5 IssuerSigned reading and the checks a credential must pass before this browser keeps it (P5-03a,
 * plan section 4.2). Nothing here re-encodes an issued item: an IssuerSignedItemBytes is returned as the exact byte
 * range it arrived in, because the digest the issuer signed is computed over those bytes (ISO/IEC 18013-5 9.1.2.5), and
 * a DeviceResponse later carries the same slice.
 *
 * Depends on cbor.js (the global `Cbor`): `Cbor.spans` supplies the byte ranges, `Cbor.tagged` the tag of a data item,
 * `Cbor.decodeTyped` the values. Every map is read typed (a `Map` whose integer keys are numbers and whose text keys are
 * strings), so a lookup names the key's type: `deviceKey.get(1)` is the COSE label 1, never a text label "1" (RFC 9052
 * 1.5), and `valueDigests.get(ns).get(digestID)` is the uint DigestID, never a text key that prints alike.
 */
var Mdoc = (function () {
  "use strict";

  /** The largest IssuerSigned the page keeps, and how many credentials it keeps (plan 4.2, check 5). */
  var MAX_ISSUER_SIGNED_BYTES = 256 * 1024;
  var MAX_CREDENTIALS = 50;
  /** The digest algorithms an MSO may name (ISO/IEC 18013-5 9.1.2.4). */
  var DIGEST_ALGORITHMS = ["SHA-256", "SHA-384", "SHA-512"];

  /** The key of a spans entry: its path, in one string. Typed segments print apart: `[33]` and `["33"]` differ. */
  function pathKey(path) {
    return JSON.stringify(path);
  }

  /** The value at a text or integer key of a typed map; `undefined` when the value is not a map or has no such key. */
  function field(map, key) {
    return map instanceof Map ? map.get(key) : undefined;
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
   * bstr), so a real Certify mDL reads exactly like a hand-built one. The tag's content and the MSO are read from their
   * bytes too: a tag around the bstr or around the MSO map is refused, and so is a value `requireMsoShapes` refuses.
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
    var wrapped = Cbor.decodeTyped(tagged.content);
    if (!(wrapped instanceof Uint8Array) || tagged.content[0] >> 5 !== 2) {
      throw new Error("the tag-24 MSO content is not a byte string (ISO/IEC 18013-5 9.1.2.4)");
    }
    if (!wrapped.length || wrapped[0] >> 5 !== 5) throw new Error("the issuerAuth payload is not an MSO map");
    var walked = Cbor.spans(wrapped, 3);
    requireMsoShapes(wrapped, rangesByPath(walked));
    return walked.value;
  }

  /**
   * The MSO values a decision reads, each of the major type ISO/IEC 18013-5 9.1.2.4 and COSE_Key give it, read from the
   * bytes: the decoder resolves tags and reads a float 2.0 as 2, so `#6.99(2)` or `2.0` would otherwise pass for the
   * EC2 kty, and a tagged digest for a Digest. `docType` and `digestAlgorithm` are a tstr; `valueDigests`, each
   * namespace's DigestIDs, `deviceKeyInfo` and `deviceKey` a map; each Digest a bstr; the deviceKey's kty (1) and crv
   * (-1) an int or a tstr (RFC 9052 section 7, RFC 9053 section 7.1.1), x (-2) a bstr and y (-3) a bstr or a bool. A
   * field that is absent is left to `checkKeepable`, which names it.
   */
  function requireMsoShapes(bytes, ranges) {
    var expect = function (path, majors, what) {
      var range = ranges.get(pathKey(path));
      if (range === undefined) return;
      var found = majorAt(bytes, range);
      var bool = found === 7 && (bytes[range.start] === 0xf4 || bytes[range.start] === 0xf5);
      if (majors.indexOf(found) < 0 && !(bool && majors.indexOf("bool") >= 0)) {
        throw new Error("the MSO's " + what + " is " + MAJOR_NAMES[found] + " (ISO/IEC 18013-5 9.1.2.4)");
      }
    };
    expect(["docType"], [3], "docType, a tstr,");
    expect(["digestAlgorithm"], [3], "digestAlgorithm, a tstr,");
    expect(["valueDigests"], [5], "valueDigests, a map,");
    ranges.forEach(function (range) {
      if (range.path[0] !== "valueDigests") return;
      if (range.path.length === 2) expect(range.path, [5], "DigestIDs of " + String(range.path[1]) + ", a map,");
      if (range.path.length === 3) {
        expect(range.path, [2], "Digest " + JSON.stringify(range.path[2]) + " of " + String(range.path[1]) + ", a bstr,");
      }
    });
    expect(["deviceKeyInfo"], [5], "deviceKeyInfo, a map,");
    expect(["deviceKeyInfo", "deviceKey"], [5], "deviceKey, a COSE_Key map,");
    expect(["deviceKeyInfo", "deviceKey", 1], [0, 1, 3], "deviceKey kty (label 1, an int or a tstr: RFC 9052 section 7)");
    expect(["deviceKeyInfo", "deviceKey", -1], [0, 1, 3], "deviceKey crv (label -1, an int or a tstr: RFC 9053 section 7.1.1)");
    expect(["deviceKeyInfo", "deviceKey", -2], [2], "deviceKey x (label -2, a bstr: RFC 9053 section 7.1.1)");
    expect(["deviceKeyInfo", "deviceKey", -3], [2, "bool"], "deviceKey y (label -3, a bstr or a bool: RFC 9053 section 7.1.1)");
  }

  /**
   * The IssuerSignedItem an IssuerSignedItemBytes (already known to be tag 24) carries, read from its bytes:
   * `#6.24(bstr .cbor IssuerSignedItem)` holds an untagged map whose `digestID` is a uint (DigestID = uint) and whose
   * `elementIdentifier` is a tstr (ISO/IEC 18013-5 8.3.2.1.2). The decoder reads `1.0` and `#6.99(1)` as 1, so a value
   * alone would let either pass for DigestID 1.
   */
  function requireItemShapes(raw, what) {
    var embedded = Cbor.decodeTyped(Cbor.tagged(raw).content);
    if (!embedded.length || embedded[0] >> 5 !== 5) {
      throw new Error(what + " does not embed an IssuerSignedItem map (ISO/IEC 18013-5 8.3.2.1.2)");
    }
    var itemRanges = rangesByPath(Cbor.spans(embedded, 1));
    requireMajor(embedded, itemRanges.get(pathKey(["digestID"])), 0, what + " digestID (DigestID = uint, ISO/IEC 18013-5 8.3.2.1.2)");
    requireMajor(embedded, itemRanges.get(pathKey(["elementIdentifier"])), 3,
      what + " elementIdentifier (DataElementIdentifier = tstr, ISO/IEC 18013-5 8.3.2.1.2)");
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
   * One COSE header map, walked so its labels keep their types. RFC 9052 1.5 and 3: `label = int / tstr`, and the
   * integer 33 and the text "33" are two labels; the typed walk keeps them apart (`[33]` and `["33"]` are two paths), so
   * a header carrying both is read, not refused. A label of any other type - a byte string, a float, a tag around an
   * integer, a map - is not a COSE label and is refused (`labels` lists the header's labels as path segments).
   */
  function headerOf(bytes, what) {
    if (!bytes.length || bytes[0] >> 5 !== 5) throw new Error("the issuerAuth " + what + " is not a map (RFC 9052 section 3)");
    var walked = Cbor.spans(bytes, 2);
    var labels = keysAt(walked, []).map(function (key) {
      if (key.major !== 0 && key.major !== 1 && key.major !== 3) {
        throw new Error("the issuerAuth " + what + " has a label that is " + MAJOR_NAMES[key.major]
          + "; a COSE label is an int or a tstr (RFC 9052 sections 1.5 and 3)");
      }
      return key.key;
    });
    return { bytes: bytes, walked: walked, ranges: rangesByPath(walked), labels: labels, what: what };
  }

  /**
   * RFC 9052 section 3: "the same label MUST NOT occur in both the protected and unprotected headers". Labels compare by
   * type and value, so the integer 1 in one bucket and the text "1" in the other are two labels and both are kept.
   * Without this, a reader that looks in one bucket first would read whichever copy that bucket holds (a stand-in
   * x5chain in the protected bucket next to the real one in the unprotected bucket, ISO/IEC 18013-5 9.1.2.4).
   */
  function requireDisjointBuckets(protectedHeader, unprotectedHeader) {
    if (protectedHeader === null) return;
    var unprotectedLabels = new Set(unprotectedHeader.labels.map(function (label) { return pathKey([label]); }));
    protectedHeader.labels.forEach(function (label) {
      if (unprotectedLabels.has(pathKey([label]))) {
        throw new Error("the issuerAuth header label " + JSON.stringify(label) + " is in both the protected and the"
          + " unprotected header (RFC 9052 section 3: a label MUST NOT occur in both)");
      }
    });
  }

  /** The value of an integer label in one header, with its range there; `undefined` when the label is absent. */
  function intLabel(header, label) {
    // a typed lookup: the text label "33" is another label (RFC 9052 1.5), not x5chain
    if (header === null || !header.walked.value.has(label)) return undefined;
    return { header: header, value: header.walked.value.get(label), range: header.ranges.get(pathKey([label])) };
  }

  /** A header label from whichever bucket holds it; `requireDisjointBuckets` has made sure only one does. */
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
        requireMajor(bytes, found.header.ranges.get(pathKey([33, index])), 2,
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
   * - every header label is an int or a tstr, compared by type (RFC 9052 sections 1.5 and 3), and no label is in both
   *   the protected and the unprotected header (RFC 9052 section 3);
   * - each IssuerSignedItemBytes is tag 24 around a bstr holding an untagged map, whose `digestID` is a uint and whose
   *   `elementIdentifier` is a tstr (ISO/IEC 18013-5 8.3.2.1.2);
   * - the MSO is a bstr inside the tag 24, holding an untagged map, and the values it decides by are of their CDDL
   *   types (`requireMsoShapes`: docType, digestAlgorithm, valueDigests and its Digests, the deviceKey's labels).
   * Plan 4.2 (check 1) and the decision log's P5-03a review round 3 and 4 rows record these refusals and the clauses
   * behind them: each is a shape the CDDL or RFC 9052 / RFC 9053 / RFC 9360 does not allow, read from the bytes the
   * page would carry.
   *
   * Maps are read typed (`Map`), so `mso` and each `elementValue` that is a map are `Map`s; `nameSpaces` is an object
   * with no prototype, so a namespace named "__proto__" is a namespace like any other.
   */
  function readIssuerSigned(input) {
    var bytes = bytesOf(input);
    var walked = Cbor.spans(bytes, 3);
    var value = walked.value;
    if (!bytes.length || majorAt(bytes, { start: 0 }) !== 5 || !(value instanceof Map)) {
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
    var issuerAuth = value.get("issuerAuth");
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
    requireDisjointBuckets(protectedHeader, unprotectedHeader);
    var x5chain = x5chainOf(headerValue(protectedHeader, unprotectedHeader, 33));
    var alg = headerValue(protectedHeader, unprotectedHeader, 1);

    // no prototype: a namespace named "__proto__" is stored as one, not as this object's prototype (which would hide its
    // items from every check that lists the namespaces)
    var nameSpaces = Object.create(null);
    var decoded = value.has("nameSpaces") ? value.get("nameSpaces") : new Map();
    if (value.has("nameSpaces")) requireMajor(bytes, ranges.get(pathKey(["nameSpaces"])), 5, "IssuerSigned nameSpaces");
    if (!(decoded instanceof Map)) throw new Error("IssuerSigned nameSpaces is not a map");
    decoded.forEach(function (items, namespace) {
      if (!Array.isArray(items)) throw new Error("the namespace " + namespace + " is not an array of IssuerSignedItems");
      requireMajor(bytes, ranges.get(pathKey(["nameSpaces", namespace])), 4, "the namespace " + namespace);
      nameSpaces[namespace] = items.map(function (item, index) {
        var elementIdentifier = field(item, "elementIdentifier");
        var digestID = field(item, "digestID");
        if (typeof elementIdentifier !== "string" || typeof digestID !== "number") {
          throw new Error("an IssuerSignedItem in " + namespace + " is not an element map");
        }
        var itemRange = ranges.get(pathKey(["nameSpaces", namespace, index]));
        if (!isTag24(bytes, itemRange)) {
          throw new Error("the IssuerSignedItem " + namespace + "/" + elementIdentifier
            + " is not a tag-24 IssuerSignedItemBytes");
        }
        requireItemShapes(bytes.subarray(itemRange.start, itemRange.end), "the IssuerSignedItem " + namespace + "/"
          + elementIdentifier);
        return {
          elementIdentifier: elementIdentifier,
          digestID: digestID,
          elementValue: item.get("elementValue"),
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
  /**
   * The sign bit of a base64url P-256 y coordinate (its last byte's lowest bit), as a compressed COSE_Key carries it
   * in label -3 (RFC 9053 section 7.1.1: true for an odd y); null when `y` is not base64url.
   */
  function ySign(y) {
    if (typeof y !== "string" || !/^[A-Za-z0-9_-]+$/.test(y)) {
      return null;
    }
    var binary = atob(y.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((y.length + 3) % 4));
    return binary.length > 0 ? (binary.charCodeAt(binary.length - 1) & 1) === 1 : null;
  }

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
    var docType = field(mso, "docType");
    if (typeof docType !== "string" || !docType) {
      return refuse("issuer-signed", "The credential's MSO names no docType.");
    }
    // check 2: the docType the configuration issues
    if (typeof options.doctype !== "string" || !options.doctype) {
      return refuse("doctype", "The issuer metadata names no doctype for this configuration, so the credential"
        + " cannot be checked against it.");
    }
    if (docType !== options.doctype) {
      return refuse("doctype", "The credential's docType is " + JSON.stringify(docType)
        + ", not this configuration's " + JSON.stringify(options.doctype) + ".");
    }
    // check 3: the MSO's deviceKey is this browser's P-256 key (ISO/IEC 18013-5 9.1.2.4)
    // COSE_Key labels are int / tstr (RFC 9052 7): the lookups are by the integer labels, never a text key alike
    var deviceKey = field(field(mso, "deviceKeyInfo"), "deviceKey");
    if (!(deviceKey instanceof Map)) {
      return refuse("device-key", "The credential's MSO carries no deviceKey.");
    }
    if (deviceKey.get(1) !== 2) {
      return refuse("device-key", "The credential's deviceKey is not an EC2 COSE key (label 1 must be 2).");
    }
    if (deviceKey.get(-1) !== 1) {
      return refuse("device-key", "The credential's deviceKey is not a P-256 key (label -1 must be 1); this page holds"
        + " P-256 keys only.");
    }
    // -3 (y) is a bstr, or a bool for a compressed point whose y is the root of that sign (RFC 9053 section 7.1.1)
    var keyY = deviceKey.get(-3);
    if (!(deviceKey.get(-2) instanceof Uint8Array) || !(keyY instanceof Uint8Array || typeof keyY === "boolean")) {
      return refuse("device-key", "The credential's deviceKey carries no P-256 coordinates (labels -2 and -3).");
    }
    var publicJwk = options.publicJwk || {};
    var sameY = keyY instanceof Uint8Array ? base64url(keyY) === publicJwk.y : ySign(publicJwk.y) === keyY;
    if (base64url(deviceKey.get(-2)) !== publicJwk.x || !sameY) {
      return refuse("device-key", "The credential's deviceKey is not this browser's key: it was issued to another"
        + " holder.");
    }
    // check 4: every IssuerSignedItemBytes hashes to its valueDigests entry, over the bytes as received
    var algorithm = field(mso, "digestAlgorithm");
    if (DIGEST_ALGORITHMS.indexOf(algorithm) < 0) {
      return refuse("digest", "The credential's MSO names the digest algorithm " + JSON.stringify(algorithm)
        + "; SHA-256, SHA-384 and SHA-512 are supported.");
    }
    var valueDigests = field(mso, "valueDigests");
    for (var namespace of Object.keys(read.nameSpaces)) {
      var byDigestId = field(valueDigests, namespace);
      if (!(byDigestId instanceof Map)) {
        return refuse("digest", "The credential's MSO has no valueDigests for the namespace " + namespace + ".");
      }
      var items = read.nameSpaces[namespace];
      for (var item of items) {
        // DigestID = uint (ISO/IEC 18013-5 9.1.2.4): the integer key, never a text key that prints alike
        var expected = byDigestId.get(item.digestID);
        var actual = await digestOf(algorithm, item.raw);
        if (!(expected instanceof Uint8Array) || base64url(expected) !== base64url(actual)) {
          return refuse("digest", "The IssuerSignedItem " + namespace + "/" + item.elementIdentifier
            + " does not hash to the MSO's valueDigest " + item.digestID + ".");
        }
      }
    }
    var validity = field(mso, "validityInfo");
    var validFrom = field(validity, "validFrom");
    var validUntil = field(validity, "validUntil");
    return {
      ok: true,
      docType: docType,
      validFrom: typeof validFrom === "string" ? validFrom : null,
      validUntil: typeof validUntil === "string" ? validUntil : null,
    };
  }

  return {
    readIssuerSigned: readIssuerSigned,
    checkKeepable: checkKeepable,
    MAX_ISSUER_SIGNED_BYTES: MAX_ISSUER_SIGNED_BYTES,
    MAX_CREDENTIALS: MAX_CREDENTIALS,
  };
})();
