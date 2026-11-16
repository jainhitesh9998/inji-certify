/*
 * X.509 reading and signature checking for the demo wallet (P5-03c, plan sections 4.1 and 4.5).
 *
 * A verifier's authorization request carries its certificates in the JWS `x5c` header (OpenID4VP 1.0 section 5.9.3,
 * RFC 7515 section 4.1.6), and the page has to do three things with them without a library:
 *
 * - read them (RFC 5280 section 4.1): the subject and issuer names, the validity, the subject alternative names, the
 *   AKI and SKI, the basic constraints and the SubjectPublicKeyInfo;
 * - import the leaf's public key (the DER SubjectPublicKeyInfo itself, which WebCrypto imports, section 13.1.1.2 of the
 *   WebCrypto Level 2 draft) and verify the JWS with it;
 * - check each certificate's signature with the next one's key, up to the topmost one (RFC 5280 section 6.1.3 (a)(1)),
 *   which is as far as this page goes: there is no trust anchor list (plan section 6, deviation 1).
 *
 * Everything is read from DER: a certificate is one SEQUENCE of three elements, and every field the page decides by is
 * taken from where the structure puts it, never by searching for a shape. A tag's class matters here: the version is
 * context [0], and the extensions context [3], and neither is a universal tag 0 or 3 (X.690 section 8.6).
 *
 * Depends on nothing: `crypto.subtle` is the browser's, and the harness hands in Node's `webcrypto` for the same calls.
 */
var X509 = (function () {
  "use strict";

  /* ---------------------------------------------------------------- DER */

  /** The classes of a tag's first byte (X.690 section 8.6.2). */
  var UNIVERSAL = 0;
  var CONTEXT = 2;

  /**
   * One DER element at `offset`: its class, tag number, constructed bit and the boundaries of its header and content.
   * The high-tag-number form (tag number 31) is refused: no field of a certificate uses it, and refusing it keeps a
   * tag's identity one byte. An indefinite length is refused too: that is BER, and DER requires the length to be
   * definite (X.690 sections 10.1 and 9.1). The long form must be the *shortest* encoding of its length (section 10.1:
   * "the minimum number of octets shall be used"), so a long-form length below 128, or one padded with a leading 0x00
   * octet, is refused as well: the same value has two spellings, and a signature is checked over these bytes.
   */
  function element(bytes, offset) {
    var first = bytes[offset];
    if (first === undefined) throw new Error("the certificate ends in the middle of a header");
    var cls = first >> 6;
    var tag = first & 0x1f;
    if (tag === 0x1f) throw new Error("the high-tag-number form is not part of a certificate");
    var pos = offset + 1;
    var octet = bytes[pos];
    if (octet === undefined) throw new Error("a DER length is missing");
    pos++;
    var length;
    if (octet < 0x80) {
      length = octet;
    } else if (octet === 0x80) {
      throw new Error("an indefinite length is BER, not DER (X.690 section 10.1)");
    } else {
      var count = octet & 0x7f;
      if (count > 3) throw new Error("a DER length longer than three octets");
      if (bytes[pos] === 0x00) throw new Error("a DER length carries a leading 0x00 octet (X.690 section 10.1)");
      length = 0;
      for (var i = 0; i < count; i++) {
        var byte = bytes[pos++];
        if (byte === undefined) throw new Error("a DER length is truncated");
        length = length * 256 + byte;
      }
      if (count === 1 && length < 0x80) {
        throw new Error("a DER length below 128 uses the long form (X.690 section 10.1)");
      }
    }
    var end = pos + length;
    if (end > bytes.length) throw new Error("a DER value runs past the end of the certificate");
    return { cls: cls, tag: tag, constructed: (first & 0x20) !== 0, start: offset, contentStart: pos, end: end };
  }

  /** The child elements of a constructed element, in order, each starting where the previous one ended. */
  function children(bytes, parent) {
    if (!parent.constructed) throw new Error("a primitive DER value has no children");
    var list = [];
    var at = parent.contentStart;
    while (at < parent.end) {
      var child = element(bytes, at);
      list.push(child);
      at = child.end;
    }
    if (at !== parent.end) throw new Error("a DER value's children do not fill it");
    return list;
  }

  /** The content octets of an element, as a view (never a copy: a signature is checked over these exact bytes). */
  function content(bytes, el) {
    return bytes.subarray(el.contentStart, el.end);
  }

  function requireTag(el, cls, tag, what) {
    if (el.cls !== cls || el.tag !== tag) throw new Error(what + " has the wrong DER tag");
    return el;
  }

  /** A DER OBJECT IDENTIFIER as its dotted form (X.690 section 8.19). */
  function oid(bytes, el) {
    requireTag(el, UNIVERSAL, 6, "an OBJECT IDENTIFIER");
    var value = content(bytes, el);
    if (!value.length) throw new Error("an OBJECT IDENTIFIER is empty");
    var arcs = [];
    var current = 0;
    var started = false;
    for (var i = 0; i < value.length; i++) {
      current = current * 128 + (value[i] & 0x7f);
      started = true;
      if (!(value[i] & 0x80)) {
        arcs.push(current);
        current = 0;
        started = false;
      }
    }
    if (started) throw new Error("an OBJECT IDENTIFIER ends in the middle of an arc");
    // the first subidentifier carries the first two arcs: 40 * X + Y with X in 0..2 (X.690 section 8.19.4)
    var first = arcs.shift();
    var x = first < 40 ? 0 : first < 80 ? 1 : 2;
    return [x, first - 40 * x].concat(arcs).join(".");
  }

  /**
   * An INTEGER's content octets, held to the minimal encoding DER requires (X.690 section 8.3.2): the first nine bits
   * are never all zeros or all ones, so a value has one spelling. Every INTEGER the page reads goes through here.
   */
  function minimalOctets(bytes, el) {
    requireTag(el, UNIVERSAL, 2, "an INTEGER");
    var value = content(bytes, el);
    if (!value.length) throw new Error("an INTEGER is empty");
    if (value.length > 1 && ((value[0] === 0x00 && !(value[1] & 0x80)) || (value[0] === 0xff && (value[1] & 0x80)))) {
      throw new Error("an INTEGER is not minimally encoded (X.690 section 8.3.2)");
    }
    return value;
  }

  /**
   * A serialNumber's octets (RFC 5280 section 4.1.2.2), kept as octets because a serial may be 20 of them and no
   * JavaScript number holds that. A positive serial loses the 0x00 pad DER puts in front of a top bit. A negative one
   * is a CA's mistake that section 4.1.2.2 asks a reader to handle gracefully ("Certificate users SHOULD be prepared
   * to gracefully handle such certificates"), so its octets are kept as written, for display, and `negative` says so:
   * the serial decides nothing on this page, and refusing the whole chain over it would be the opposite of graceful.
   */
  function serialOctets(bytes, el) {
    var value = minimalOctets(bytes, el);
    var negative = (value[0] & 0x80) !== 0;
    return { octets: !negative && value.length > 1 && value[0] === 0x00 ? value.subarray(1) : value, negative: negative };
  }

  /** Those octets as uppercase hex, two characters per octet (how every other tool prints a serial). */
  function hexOctets(value) {
    var text = "";
    for (var i = 0; i < value.length; i++) text += (value[i] < 16 ? "0" : "") + value[i].toString(16).toUpperCase();
    return text;
  }

  /** A non-negative INTEGER as a number, refusing what does not fit one (no field the page reads is that large). */
  function integer(bytes, el) {
    var value = minimalOctets(bytes, el);
    if (value[0] & 0x80) throw new Error("a negative INTEGER where none is allowed");
    var result = 0;
    for (var i = 0; i < value.length; i++) result = result * 256 + value[i];
    if (!Number.isSafeInteger(result)) throw new Error("an INTEGER is too large");
    return result;
  }

  /** The bit length of a positive INTEGER (an RSA modulus is far larger than a JavaScript number holds). */
  function integerBits(bytes, el) {
    requireTag(el, UNIVERSAL, 2, "an INTEGER");
    var value = content(bytes, el);
    var first = 0;
    while (first < value.length && value[first] === 0) first++;
    if (first === value.length) return 0;
    var top = value[first];
    var bits = 0;
    while (top) {
      bits++;
      top >>= 1;
    }
    return (value.length - first - 1) * 8 + bits;
  }

  /* ---------------------------------------------------------------- names */

  /** The attributes the page shows, by OID (RFC 4519 and RFC 5280 section 4.1.2.4). */
  var ATTRIBUTES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
  };

  /**
   * A DirectoryString/IA5String's text, by the string type's own tag (X.680 section 30, X.690 section 8.20).
   * `DirectoryString` is `teletexString / printableString / universalString / utf8String / bmpString`; a certificate
   * also writes numericString and IA5String where a name attribute is free-form, so both are read here.
   */
  function directoryString(bytes, el) {
    var value = content(bytes, el);
    var text;
    switch (el.cls === UNIVERSAL ? el.tag : -1) {
      case 12: // UTF8String
        text = new TextDecoder("utf-8", { fatal: true }).decode(value);
        break;
      case 18: // NumericString: the digits and the space, one per octet (X.680 section 41)
      case 19: // PrintableString
      case 20: // TeletexString: read as latin1, which is what every certificate that uses it means
      case 22: // IA5String
      case 26: // VisibleString
        text = "";
        for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
        break;
      case 28: // UniversalString: UCS-4, four octets per code point, big endian (X.690 section 8.23.8)
        text = "";
        if (value.length % 4) throw new Error("a UniversalString is not a whole number of code points");
        for (var k = 0; k < value.length; k += 4) {
          var point = ((value[k] << 24) | (value[k + 1] << 16) | (value[k + 2] << 8) | value[k + 3]) >>> 0;
          if (point > 0x10ffff) throw new Error("a UniversalString carries a code point beyond Unicode");
          text += String.fromCodePoint(point);
        }
        break;
      case 30: // BMPString: UTF-16BE
        text = "";
        if (value.length % 2) throw new Error("a BMPString has an odd number of octets");
        for (var j = 0; j < value.length; j += 2) text += String.fromCharCode((value[j] << 8) | value[j + 1]);
        break;
      default:
        throw new Error("a name attribute is not a string type this page reads");
    }
    return text;
  }

  /**
   * An X.501 Name (RFC 5280 section 4.1.2.4): `SEQUENCE OF SET OF SEQUENCE { type, value }`, in DER order, which is the
   * order openssl prints. `attributes` keeps the OID so a caller can compare two names, and `text` is what the card
   * shows.
   */
  function name(bytes, el) {
    requireTag(el, UNIVERSAL, 16, "a Name");
    var rdns = children(bytes, el);
    var attributes = [];
    rdns.forEach(function (rdn) {
      requireTag(rdn, UNIVERSAL, 17, "a RelativeDistinguishedName");
      children(bytes, rdn).forEach(function (atv) {
        requireTag(atv, UNIVERSAL, 16, "an AttributeTypeAndValue");
        var pair = children(bytes, atv);
        if (pair.length !== 2) throw new Error("an AttributeTypeAndValue is not a pair");
        var type = oid(bytes, pair[0]);
        attributes.push({ oid: type, short: ATTRIBUTES[type] || type, value: directoryString(bytes, pair[1]) });
      });
    });
    var text = attributes.map(function (attribute) {
      return attribute.short + "=" + attribute.value;
    }).join(", ");
    // the DER of the Name itself, so two names compare as the certificate wrote them (RFC 5280 6.1.3 (a)(4))
    return { attributes: attributes, text: text, der: bytes.subarray(el.start, el.end) };
  }

  /* ---------------------------------------------------------------- time */

  /**
   * A UTCTime or GeneralizedTime, as an instant (RFC 5280 section 4.1.2.5, X.690 section 11.8). Each field is held
   * to its range before any Date is made: `Date.UTC` would turn month 13 into January of the next year and hour 40 into
   * the next afternoon, so a certificate that names no instant would be read as naming another one. The year is set
   * with `setUTCFullYear` for the same reason (`Date.UTC` reads a year below 100 as 1900 + year).
   */
  function time(bytes, el) {
    requireTag(el, UNIVERSAL, el.tag === 24 ? 24 : 23, "a Time");
    var text = "";
    var value = content(bytes, el);
    for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
    var match;
    var year;
    var what;
    if (el.tag === 23) {
      // UTCTime "YYMMDDHHMMSSZ": YY 50..99 is 1950..1999 and 00..49 is 2000..2049 (RFC 5280 section 4.1.2.5.1)
      what = "UTCTime";
      match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
      if (!match) throw new Error("a UTCTime is not YYMMDDHHMMSSZ");
      var yy = Number(match[1]);
      year = yy >= 50 ? 1900 + yy : 2000 + yy;
    } else {
      what = "GeneralizedTime";
      match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
      if (!match) throw new Error("a GeneralizedTime is not YYYYMMDDHHMMSSZ");
      year = Number(match[1]);
    }
    var month = Number(match[2]);
    var day = Number(match[3]);
    var hour = Number(match[4]);
    var minute = Number(match[5]);
    var second = Number(match[6]);
    var leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    var days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) {
      throw new Error("a " + what + " names no instant (" + text + "): month 01-12, a day the month has, hour 00-23, "
        + "minute and second 00-59 (RFC 5280 section 4.1.2.5)");
    }
    var date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, 0);
    return date;
  }

  /* ---------------------------------------------------------------- extensions */

  var EXTENSION = {
    subjectAltName: "2.5.29.17", subjectKeyIdentifier: "2.5.29.14", authorityKeyIdentifier: "2.5.29.35",
    basicConstraints: "2.5.29.19", keyUsage: "2.5.29.15",
  };

  /**
   * The extension types this page may meet marked critical. RFC 5280 section 4.2: "A certificate-using system MUST
   * reject the certificate if it encounters a critical extension it does not recognize or a critical extension that
   * contains information that it cannot process" (and sections 6.1.4 (o) and 6.1.5 (f) for a path). So this list is
   * not the extensions RFC 5280 defines; it is the ones whose criticality the page honours:
   *
   * - the five it reads and decides by: subjectKeyIdentifier, authorityKeyIdentifier, subjectAltName (R6),
   *   basicConstraints and keyUsage (`certificateFault`). EUDI's leaf marks the last two critical;
   * - extendedKeyUsage, which Multipaz's leaf marks critical (ISO/IEC 18013-5 mdoc reader authentication). A critical
   *   one limits the purposes the key may serve (RFC 5280 section 4.2.1.12), and authenticating a verifier's request
   *   is the purpose that leaf is issued for; no extended key usage is defined for signing a request object;
   * - the four that only say where to look for revocation or for more certificates: cRLDistributionPoints,
   *   freshestCRL, authorityInfoAccess, subjectInfoAccess. They constrain nothing the page decides, and the page
   *   checks no revocation at all (plan section 6, deviation 1).
   *
   * The path-constraining extensions are deliberately absent: nameConstraints (2.5.29.30), certificatePolicies
   * (.32), policyMappings (.33), policyConstraints (.36) and inhibitAnyPolicy (.54). The page runs none of the
   * name-constraint or policy steps of sections 6.1.3 and 6.1.4, so a critical one ends the path rather than being
   * read as if it were satisfied: an intermediate permitted only `DNS:allowed.example` must not be able to vouch for
   * `DNS:verifier.example` here when `openssl verify` refuses the same chain. Neither hosted capture carries one
   * (EUDI's leaf has a non-critical certificatePolicies, which a reader may ignore).
   */
  var KNOWN_EXTENSIONS = [
    "2.5.29.14", // subjectKeyIdentifier
    "2.5.29.15", // keyUsage
    "2.5.29.17", // subjectAltName
    "2.5.29.19", // basicConstraints
    "2.5.29.31", // cRLDistributionPoints
    "2.5.29.35", // authorityKeyIdentifier
    "2.5.29.37", // extKeyUsage
    "2.5.29.46", // freshestCRL
    "1.3.6.1.5.5.7.1.1", // authorityInfoAccess
    "1.3.6.1.5.5.7.1.11", // subjectInfoAccess
  ];

  /** Names for the extensions a refusal is likeliest to name, so a message says more than an OID. */
  var EXTENSION_NAMES = {
    "2.5.29.30": "nameConstraints", "2.5.29.32": "certificatePolicies", "2.5.29.33": "policyMappings",
    "2.5.29.36": "policyConstraints", "2.5.29.54": "inhibitAnyPolicy",
  };

  /**
   * The one DER element an extension's OCTET STRING holds, which must fill it: an extnValue is its own DER document
   * (RFC 5280 section 4.1), and octets after its value would be a second reading of the same extension.
   */
  function single(extnValue, what) {
    var el = element(extnValue, 0);
    if (el.end !== extnValue.length) throw new Error(what + " carries octets after its value");
    return el;
  }

  /**
   * The GeneralNames the page reads: dNSName [2] and URI [6], both IA5String (RFC 5280 section 4.2.1.6). `extnValue`
   * is the extension's OCTET STRING content, and every offset below is relative to it: a certificate's extension is
   * its own small DER document, so it is read as one.
   */
  function generalNames(extnValue) {
    var sans = { dnsNames: [], uris: [] };
    children(extnValue, single(extnValue, "subjectAltName")).forEach(function (generalName) {
      if (generalName.cls !== CONTEXT) return;
      if (generalName.tag !== 2 && generalName.tag !== 6) return;
      var text = "";
      var value = content(extnValue, generalName);
      for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
      (generalName.tag === 2 ? sans.dnsNames : sans.uris).push(text);
    });
    return sans;
  }

  /**
   * A DER BOOLEAN that is there only because it is TRUE: a field `BOOLEAN DEFAULT FALSE` is left out when FALSE (X.690
   * section 11.5, "the encoding of a set value or sequence value shall not include an encoding for any component value
   * which is equal to its default value"), and TRUE is the single octet 0xFF (section 11.1). Anything else is a second
   * spelling of the same certificate.
   */
  function defaultFalseBoolean(bytes, el, what) {
    requireTag(el, UNIVERSAL, 1, what);
    var flag = content(bytes, el);
    if (flag.length === 1 && flag[0] === 0x00) {
      throw new Error(what + " is written as FALSE, its DEFAULT, which DER leaves out (X.690 section 11.5)");
    }
    if (flag.length !== 1 || flag[0] !== 0xff) {
      throw new Error(what + " is not the DER BOOLEAN TRUE, the single octet 0xFF (X.690 section 11.1)");
    }
    return true;
  }

  /**
   * The extensions of a certificate, by OID, each with the DER of its own extnValue octets and its criticality flag
   * (RFC 5280 section 4.2: `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`,
   * so the BOOLEAN is there only when it is TRUE). Section 4.2: "A certificate MUST NOT include more than one instance
   * of a particular extension", and a reader that kept either one would decide by a value the other contradicts.
   */
  function extensions(bytes, list) {
    var found = new Map();
    list.forEach(function (extension) {
      requireTag(extension, UNIVERSAL, 16, "an Extension");
      var parts = children(bytes, extension);
      if (parts.length !== 2 && parts.length !== 3) throw new Error("an Extension is not two or three elements");
      var id = oid(bytes, parts[0]);
      var critical = parts.length === 3 && defaultFalseBoolean(bytes, parts[1], "an Extension's critical flag");
      var value = parts[parts.length - 1];
      requireTag(value, UNIVERSAL, 4, "an extnValue");
      if (found.has(id)) {
        throw new Error("the extension " + id + " appears more than once (RFC 5280 section 4.2)");
      }
      found.set(id, { value: content(bytes, value), critical: critical });
    });
    return found;
  }

  /* ---------------------------------------------------------------- the certificate */

  /**
   * The signature algorithms a certificate may name here, and the WebCrypto parameters each one needs. RSA-PSS
   * (`rsassaPss`) carries its hash, mask generation function and salt length in the algorithm's own parameters, so
   * those are read from the certificate (RFC 4055 section 3.1) rather than fixed here.
   */
  var SIGNATURE_ALGORITHMS = {
    "1.2.840.10045.4.3.2": { kind: "ec", hash: "SHA-256" },      // ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": { kind: "ec", hash: "SHA-384" },      // ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": { kind: "ec", hash: "SHA-512" },      // ecdsa-with-SHA512
    "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },   // sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },   // sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },   // sha512WithRSAEncryption
    "1.2.840.113549.1.1.10": { kind: "pss" },                     // rsassaPss (RFC 4055 section 3.1)
  };

  /**
   * The digests an RSASSA-PSS-params may name here, by OID, and their WebCrypto names (RFC 4055 section 2.1). The
   * same three as the PKCS#1 v1.5 algorithms above: SHA-1 and SHA-224 are left out, so a certificate cannot get past
   * the refusal of `sha1WithRSAEncryption` by naming RSA-PSS with SHA-1 instead (RFC 4055's own default).
   */
  var DIGESTS = {
    "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
  };
  var OID_MGF1 = "1.2.840.113549.1.1.8";

  var CURVE_OIDS = {
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
  };

  var OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
  var OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

  /**
   * One certificate, read from its DER (RFC 5280 section 4.1):
   * `{der, subject, issuer, notBefore, notAfter, serialNumber, serialBytes, serialNegative, version, sans, ca,
   * pathLength, keyUsage, keyUsagePresent, keyUsageText, unknownCritical, ski, aki, spki, publicKey, signatureAlgorithm,
   * signatureAlgorithmDer, tbs, tbsSignatureAlgorithm, tbsSignatureAlgorithmDer, signatureValue, selfIssued}`.
   *
   * `serialNumber` is the upper-case hex of the serial's octets, never a number: RFC 5280 section 4.1.2.2 allows up to
   * 20 octets, and both of the hosted captures' certificates carry serials no JavaScript number holds (EUDI's is 20
   * octets, Multipaz's 13). `serialBytes` is the same value unpadded, which is what the card can show; a negative
   * serial keeps its two's-complement octets as written, and `serialNegative` says so (`serialOctets`).
   *
   * The DER is held to the rules a second spelling of the same certificate would break (X.690 sections 10 and 11): no
   * field equal to its DEFAULT is written (a `version` of v1, an Extension's `critical` FALSE, basicConstraints' `cA`
   * FALSE), a BOOLEAN TRUE is 0xFF, every INTEGER is minimal, the TBSCertificate's optional fields come in their
   * order and at most once, and no extension appears twice.
   *
   * `selfIssued` is the Name comparison only (RFC 5280 section 4.1.2.4); whether the certificate really signed itself
   * is `verifyIssuedBy(certificate, certificate)`, which is what the trust-path check asks.
   */
  function parse(input) {
    var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    var outer = element(bytes, 0);
    requireTag(outer, UNIVERSAL, 16, "a Certificate");
    if (outer.end !== bytes.length) throw new Error("a Certificate is not exactly one SEQUENCE");
    var parts = children(bytes, outer);
    if (parts.length !== 3) throw new Error("a Certificate is a SEQUENCE of three elements (RFC 5280 4.1)");
    var tbsElement = requireTag(parts[0], UNIVERSAL, 16, "a TBSCertificate");
    var signatureAlgorithmElement = requireTag(parts[1], UNIVERSAL, 16, "a signatureAlgorithm");
    var signatureValueElement = requireTag(parts[2], UNIVERSAL, 3, "a signatureValue");

    var fields = children(bytes, tbsElement);
    if (fields.length < 6) throw new Error("a TBSCertificate has fewer than six fields (RFC 5280 section 4.1.2)");
    var index = 0;
    var version = 1;
    if (fields[0].cls === CONTEXT && fields[0].tag === 0) {
      // version [0] EXPLICIT Version DEFAULT v1: the INTEGER inside is 0, 1 or 2 (RFC 5280 section 4.1.2.1), and DER
      // leaves v1 out because it is the DEFAULT (X.690 section 11.5)
      var versionNumber = integer(bytes, childOf(bytes, fields[0], "the version"));
      if (versionNumber === 0) {
        throw new Error("the version is written as v1, its DEFAULT, which DER leaves out (X.690 section 11.5)");
      }
      if (versionNumber !== 1 && versionNumber !== 2) {
        throw new Error("the version INTEGER is " + versionNumber + "; RFC 5280 section 4.1.2.1 defines 0, 1 and 2 "
          + "(v1, v2, v3)");
      }
      version = versionNumber + 1;
      index = 1;
    }
    var serial = serialOctets(bytes, fields[index++]);
    var serialBytes = serial.octets;
    var serialNumber = hexOctets(serialBytes);
    // the TBS's own AlgorithmIdentifier, kept whole so that two spellings of the same OID - RSA-PSS's parameters
    // differ per hash and salt length - compare as the certificate wrote them (RFC 5280 section 4.1.1.2)
    var tbsSignatureElement = requireTag(fields[index++], UNIVERSAL, 16, "a signature");
    var tbsSignature = oid(bytes, children(bytes, tbsSignatureElement)[0]);
    var issuerName = name(bytes, requireTag(fields[index++], UNIVERSAL, 16, "an issuer"));
    var validity = children(bytes, requireTag(fields[index++], UNIVERSAL, 16, "a Validity"));
    if (validity.length !== 2) throw new Error("a Validity is not a pair of times");
    var notBefore = time(bytes, validity[0]);
    var notAfter = time(bytes, validity[1]);
    var subjectName = name(bytes, requireTag(fields[index++], UNIVERSAL, 16, "a subject"));
    var spkiElement = requireTag(fields[index++], UNIVERSAL, 16, "a SubjectPublicKeyInfo");

    var found = new Map();
    var previousTag = 0;
    for (; index < fields.length; index++) {
      var field = fields[index];
      // issuerUniqueID [1], subjectUniqueID [2] and extensions [3], each at most once and in that order
      if (field.cls !== CONTEXT || field.tag < 1 || field.tag > 3 || field.tag <= previousTag) {
        throw new Error("a TBSCertificate field the certificate does not define, or one out of its order");
      }
      previousTag = field.tag;
      if (field.tag === 3) {
        // extensions [3] EXPLICIT Extensions, which only a v3 certificate carries (RFC 5280 section 4.1.2.9)
        if (version !== 3) throw new Error("a version " + version + " certificate carries extensions, which need v3 "
          + "(RFC 5280 section 4.1.2.9)");
        var sequence = children(bytes, field);
        if (sequence.length !== 1) throw new Error("the extensions are not one SEQUENCE");
        found = extensions(bytes, children(bytes, requireTag(sequence[0], UNIVERSAL, 16, "Extensions")));
      } else if (version < 2) {
        // the unique identifiers carry nothing this page decides by, and only v2 or v3 has them (RFC 5280 4.1.2.8)
        throw new Error("a version 1 certificate carries a unique identifier, which needs v2 or v3 (RFC 5280 section "
          + "4.1.2.8)");
      }
    }

    var sans = { dnsNames: [], uris: [] };
    if (found.has(EXTENSION.subjectAltName)) {
      sans = generalNames(found.get(EXTENSION.subjectAltName).value);
    }
    var ca = false;
    var pathLength = null;
    if (found.has(EXTENSION.basicConstraints)) {
      // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }, in
      // that order and nothing else (RFC 5280 section 4.2.1.9)
      var constraintsValue = found.get(EXTENSION.basicConstraints).value;
      var members = children(constraintsValue, requireTag(single(constraintsValue, "basicConstraints"), UNIVERSAL, 16,
        "basicConstraints"));
      var at = 0;
      if (at < members.length && members[at].cls === UNIVERSAL && members[at].tag === 1) {
        ca = defaultFalseBoolean(constraintsValue, members[at++], "basicConstraints' cA");
      }
      if (at < members.length && members[at].cls === UNIVERSAL && members[at].tag === 2) {
        pathLength = integer(constraintsValue, members[at++]);
      }
      if (at !== members.length) throw new Error("basicConstraints carries a member RFC 5280 section 4.2.1.9 does not "
        + "define");
    }
    var ski = null;
    if (found.has(EXTENSION.subjectKeyIdentifier)) {
      var skiValue = found.get(EXTENSION.subjectKeyIdentifier).value;
      ski = content(skiValue, requireTag(single(skiValue, "subjectKeyIdentifier"), UNIVERSAL, 4,
        "subjectKeyIdentifier"));
    }
    var aki = null;
    if (found.has(EXTENSION.authorityKeyIdentifier)) {
      // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
      var akiValue = found.get(EXTENSION.authorityKeyIdentifier).value;
      children(akiValue, single(akiValue, "authorityKeyIdentifier")).forEach(function (member) {
        if (member.cls === CONTEXT && member.tag === 0 && aki === null) aki = content(akiValue, member);
      });
    }
    var keyUsagePresent = found.has(EXTENSION.keyUsage);
    var keyUsage = [];
    if (keyUsagePresent) {
      // KeyUsage ::= BIT STRING, named by bit position (RFC 5280 section 4.2.1.3)
      var usageValue = found.get(EXTENSION.keyUsage).value;
      var bits = content(usageValue, requireTag(single(usageValue, "keyUsage"), UNIVERSAL, 3, "keyUsage"));
      var names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
        "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
      for (var bit = 0; bit < names.length; bit++) {
        if (bits.length > 1 + (bit >> 3) && (bits[1 + (bit >> 3)] & (0x80 >> (bit & 7)))) keyUsage.push(names[bit]);
      }
    }
    var unknownCritical = [];
    found.forEach(function (extension, id) {
      if (extension.critical && KNOWN_EXTENSIONS.indexOf(id) < 0) unknownCritical.push(id);
    });

    var signatureAlgorithm = oid(bytes, children(bytes, signatureAlgorithmElement)[0]);
    var publicKey = publicKeyInfo(bytes, spkiElement);
    var signatureValue = content(bytes, signatureValueElement);
    if (!signatureValue.length) throw new Error("a signatureValue is empty");
    if (signatureValue[0] !== 0) throw new Error("a signatureValue BIT STRING names unused bits");

    var sameName = issuerName.text === subjectName.text && bytesEqual(issuerName.der, subjectName.der);
    return {
      der: bytes,
      version: version,
      serialNumber: serialNumber,
      serialBytes: serialBytes,
      serialNegative: serial.negative,
      subject: subjectName,
      issuer: issuerName,
      notBefore: notBefore,
      notAfter: notAfter,
      sans: sans,
      ca: ca,
      pathLength: pathLength,
      keyUsage: keyUsage,
      keyUsagePresent: keyUsagePresent,
      keyUsageText: keyUsage.join(", "),
      unknownCritical: unknownCritical,
      ski: ski,
      aki: aki,
      spki: bytes.subarray(spkiElement.start, spkiElement.end),
      publicKey: publicKey,
      signatureAlgorithm: signatureAlgorithm,
      signatureAlgorithmDer: bytes.subarray(signatureAlgorithmElement.start, signatureAlgorithmElement.end),
      tbsSignatureAlgorithm: tbsSignature,
      tbsSignatureAlgorithmDer: bytes.subarray(tbsSignatureElement.start, tbsSignatureElement.end),
      tbs: bytes.subarray(tbsElement.start, tbsElement.end),
      signatureValue: signatureValue.subarray(1),
      selfIssued: sameName,
    };
  }

  /** What the SubjectPublicKeyInfo holds, as far as the page names it on the card (RFC 3279, RFC 5480). */
  function publicKeyInfo(bytes, spki) {
    var parts = children(bytes, spki);
    if (parts.length !== 2) throw new Error("a SubjectPublicKeyInfo is not a pair");
    var algorithm = children(bytes, requireTag(parts[0], UNIVERSAL, 16, "an AlgorithmIdentifier"));
    var type = oid(bytes, algorithm[0]);
    if (type === OID_EC_PUBLIC_KEY) {
      if (algorithm.length < 2) throw new Error("an EC public key names no curve");
      var curveOid = oid(bytes, algorithm[1]);
      if (!CURVE_OIDS[curveOid]) throw new Error("an EC public key is on no curve this page reads (" + curveOid + ")");
      return { kind: "ec", curve: CURVE_OIDS[curveOid] };
    }
    if (type === OID_RSA_ENCRYPTION) {
      // subjectPublicKey is a BIT STRING holding the DER RSAPublicKey (RFC 3279 section 2.3.1), read in its own view
      var bitString = content(bytes, requireTag(parts[1], UNIVERSAL, 3, "a subjectPublicKey"));
      var rsaKey = element(bitString, 1);
      var rsa = children(bitString, rsaKey);
      return { kind: "rsa", bits: integerBits(bitString, rsa[0]) };
    }
    throw new Error("a public key is neither EC nor RSA (" + type + ")");
  }

  function bytesEqual(left, right) {
    if (left.length !== right.length) return false;
    for (var i = 0; i < left.length; i++) if (left[i] !== right[i]) return false;
    return true;
  }

  /* ---------------------------------------------------------------- WebCrypto */

  /** The JWS algorithms this page verifies (plan 4.5 R10). An `alg` outside these is refused, `none` included. */
  var JWS_ALGORITHMS = {
    ES256: { kind: "ec", curve: "P-256", hash: "SHA-256" },
    ES384: { kind: "ec", curve: "P-384", hash: "SHA-384" },
    ES512: { kind: "ec", curve: "P-521", hash: "SHA-512" },
    RS256: { kind: "rsa", name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    PS256: { kind: "rsa", name: "RSA-PSS", hash: "SHA-256", saltLength: 32 },
  };

  /**
   * A certificate's SubjectPublicKeyInfo imported for one JWS algorithm, which fixes both the key type and the hash
   * (RFC 7518 sections 3.3 and 3.4). The key is the whole SPKI DER, which WebCrypto imports for EC and RSA alike, so
   * there is no point or modulus to reassemble by hand.
   */
  async function importPublicKey(spkiDer, alg) {
    var spec = JWS_ALGORITHMS[alg];
    if (spec === undefined) throw new Error("the JWS algorithm " + JSON.stringify(alg) + " is not one this page verifies");
    var key = spec.kind === "ec"
      ? await crypto.subtle.importKey("spki", spkiDer, { name: "ECDSA", namedCurve: spec.curve }, false, ["verify"])
      : await crypto.subtle.importKey("spki", spkiDer, { name: spec.name, hash: spec.hash }, false, ["verify"]);
    return { key: key, spec: spec };
  }

  /** The smallest RSA modulus the page verifies a signature with, the request's or a certificate's. */
  var RSA_MINIMUM_BITS = 2048;

  /**
   * Whether `signature` is `certificate`'s signature over `signingInput` under `alg`. An ECDSA JWS signature is `r || s`
   * raw (RFC 7518 section 3.4), which is what WebCrypto returns and expects; a certificate's own ECDSA signature is the
   * DER SEQUENCE (RFC 3279 section 2.2.3), which `derEcdsaToRaw` converts.
   *
   * An RSA key below 2048 bits is refused, by a throw and not a `false`, before the signature is tried: RFC 7518
   * section 3.3 requires 2048 or more for RS256 and PS256, and WebCrypto would happily verify a 1024-bit signature
   * that the specification does not allow. This is the one place that rule lives; `checkRequest` reports the throw as
   * R10. Everything else that keeps a signature from verifying (a key of the wrong type or curve, bad bytes) is `false`.
   */
  async function verifyJws(signingInput, signature, certificate, alg) {
    var spec = JWS_ALGORITHMS[alg];
    if (spec !== undefined && spec.kind === "rsa" && certificate.publicKey.kind === "rsa"
        && certificate.publicKey.bits < RSA_MINIMUM_BITS) {
      throw new Error("the leaf certificate's RSA key is " + certificate.publicKey.bits + " bits; " + alg
        + " requires " + RSA_MINIMUM_BITS + " or more (RFC 7518 section 3.3).");
    }
    var imported;
    try {
      imported = await importPublicKey(certificate.spki, alg);
    } catch (error) {
      return false;
    }
    var parameters = imported.spec.kind === "ec"
      ? { name: "ECDSA", hash: imported.spec.hash }
      : imported.spec.name === "RSA-PSS"
        ? { name: "RSA-PSS", saltLength: imported.spec.saltLength }
        : { name: "RSASSA-PKCS1-v1_5" };
    try {
      return await crypto.subtle.verify(parameters, imported.key, signature, signingInput);
    } catch (error) {
      return false;
    }
  }

  /**
   * An ECDSA signature in DER (`SEQUENCE { INTEGER r, INTEGER s }`) as the fixed-width `r || s` WebCrypto expects
   * (RFC 3279 section 2.2.3, RFC 7518 section 3.4). The DER is held to its own rules: the SEQUENCE is the whole input,
   * both integers are non-empty and positive (X.690 sections 8.3.1 and 8.3.2), each carries at most the one 0x00 pad a
   * top bit needs, and each is at most as wide as the curve it belongs to. A signature that is two unequal spellings
   * of the same value would otherwise verify twice, and a certificate would have two DERs and two `x509_hash` values.
   */
  function derEcdsaToRaw(der, width) {
    var outer = element(der, 0);
    requireTag(outer, UNIVERSAL, 16, "an ECDSA signature");
    if (outer.end !== der.length) throw new Error("an ECDSA signature is not exactly one SEQUENCE");
    var pair = children(der, outer);
    if (pair.length !== 2) throw new Error("an ECDSA signature is not a pair of integers");
    var raw = new Uint8Array(width * 2);
    [pair[0], pair[1]].forEach(function (part, index) {
      var value = content(der, requireTag(part, UNIVERSAL, 2, "an ECDSA signature integer"));
      if (!value.length) throw new Error("an ECDSA signature integer is empty");
      if (value[0] & 0x80) throw new Error("an ECDSA signature integer is negative");
      // X.690 section 8.3.2: a leading 0x00 is allowed only in front of an octet whose top bit is set, so `00 00 80`
      // (a second pad) and `00 01` (a pad nothing needs) are both refused. The test is on the second octet itself, not
      // on the first non-zero one, which is what let `00 00 80` through: skipping every leading zero finds 0x80 there.
      if (value.length > 1 && value[0] === 0x00 && !(value[1] & 0x80)) {
        throw new Error("an ECDSA signature integer is not minimal (X.690 section 8.3.2)");
      }
      if (value.length === 1 && value[0] === 0) throw new Error("an ECDSA signature integer is zero");
      var significant = value[0] === 0x00 ? value.subarray(1) : value;
      if (significant.length > width) throw new Error("an ECDSA signature integer is wider than its curve");
      raw.set(significant, index * width + (width - significant.length));
    });
    return raw;
  }

  var CURVE_WIDTH = { "P-256": 32, "P-384": 48, "P-521": 66 };

  /**
   * An RSASSA-PSS AlgorithmIdentifier's parameters (RFC 4055 section 3.1):
   * `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] HashAlgorithm DEFAULT sha1, maskGenAlgorithm [1] MaskGenAlgorithm
   * DEFAULT mgf1SHA1, saltLength [2] INTEGER DEFAULT 20, trailerField [3] TrailerField DEFAULT trailerFieldBC }`.
   *
   * Section 3.1 says the parameters "MUST be present when used in the algorithm identifier associated with a signature
   * value", which is the only place this reads them, so their absence is refused. Every default is SHA-1 or follows
   * from it, and SHA-1 is not a digest this page verifies (`DIGESTS`), so a hashAlgorithm and a maskGenAlgorithm must
   * be written; a saltLength of 20 and a trailerField of 1 are their DEFAULTs, which DER leaves out (X.690 section
   * 11.5), and trailerField has no other value it may take. The fields come in their order, each at most once.
   */
  function pssParameters(bytes, algorithm) {
    var spec = { hash: null, mgfHash: null, saltLength: 20 };
    if (algorithm.length !== 2) {
      throw new Error("an RSASSA-PSS signature algorithm carries no parameters; RFC 4055 section 3.1 requires them "
        + "with a signature value");
    }
    var parameters = requireTag(algorithm[1], UNIVERSAL, 16, "RSASSA-PSS-params");
    var previousTag = -1;
    children(bytes, parameters).forEach(function (member) {
      if (member.cls !== CONTEXT) throw new Error("an RSASSA-PSS-params field has the wrong DER class");
      if (member.tag <= previousTag) throw new Error("the RSASSA-PSS-params fields are out of their order, or repeated");
      previousTag = member.tag;
      var inner = childOf(bytes, member, "an RSASSA-PSS-params field");
      if (member.tag === 0) {
        spec.hash = digestOf(bytes, inner);
      } else if (member.tag === 1) {
        // MGF1's parameters are the digest's AlgorithmIdentifier itself (RFC 4055 section 2.1: MGF1Parameters ::=
        // HashAlgorithm), not a SEQUENCE around it
        var mgf = children(bytes, requireTag(inner, UNIVERSAL, 16, "a maskGenAlgorithm"));
        if (oid(bytes, mgf[0]) !== OID_MGF1) throw new Error("the RSASSA-PSS mask generation function is not MGF1");
        if (mgf.length < 2) throw new Error("MGF1 names no digest");
        spec.mgfHash = digestOf(bytes, mgf[1]);
      } else if (member.tag === 2) {
        spec.saltLength = integer(bytes, inner);
        if (spec.saltLength === 20) {
          throw new Error("the RSASSA-PSS saltLength is written as 20, its DEFAULT, which DER leaves out (X.690 "
            + "section 11.5)");
        }
      } else if (member.tag === 3) {
        throw new Error(integer(bytes, inner) === 1
          ? "the RSASSA-PSS trailerField is written as 1, its DEFAULT, which DER leaves out (X.690 section 11.5)"
          : "the RSASSA-PSS trailerField is not 1 (RFC 4055 section 3.1)");
      } else {
        throw new Error("an RSASSA-PSS-params field the structure does not define");
      }
    });
    if (spec.hash === null) {
      throw new Error("RSASSA-PSS names no hashAlgorithm, so it is SHA-1 (RFC 4055 section 3.1's DEFAULT), which "
        + "this page does not verify");
    }
    if (spec.mgfHash === null) {
      throw new Error("RSASSA-PSS names no maskGenAlgorithm, so it is MGF1 with SHA-1 (RFC 4055 section 3.1's "
        + "DEFAULT), which this page does not verify");
    }
    if (spec.mgfHash !== spec.hash) {
      throw new Error("RSASSA-PSS uses MGF1 with " + spec.mgfHash + " over a " + spec.hash + " digest, which this page "
        + "does not verify");
    }
    if (spec.saltLength < 0) throw new Error("the RSASSA-PSS salt length is negative");
    return spec;
  }

  /** The one element a context-specific EXPLICIT field wraps. */
  function childOf(bytes, el, what) {
    var wrapped = children(bytes, el);
    if (wrapped.length !== 1) throw new Error(what + " is not one EXPLICIT value");
    return wrapped[0];
  }

  /** The digest an AlgorithmIdentifier names, as the hash's WebCrypto name (RFC 4055 section 2.1). */
  function digestOf(bytes, el) {
    var parts = children(bytes, requireTag(el, UNIVERSAL, 16, "a digest AlgorithmIdentifier"));
    var id = oid(bytes, parts[0]);
    if (DIGESTS[id] === undefined) throw new Error("the digest " + id + " is not one this page reads");
    return DIGESTS[id];
  }

  /**
   * Whether `issuer` issued `certificate`: the algorithm, then the signature over the TBSCertificate with the issuer's
   * key (RFC 5280 section 6.1.3 (a)(1)). The outer `signatureAlgorithm` must be the AlgorithmIdentifier the TBS names,
   * parameters included, or the certificate says two different things about how it was signed (RFC 5280 section
   * 4.1.1.2) and is refused: with RSA-PSS those parameters are the hash and the salt length.
   *
   * An issuer's RSA key below 2048 bits is refused here as it is for the request's own signature (`verifyJws`): no
   * RFC sets a floor for a certificate signature, but a chain is as strong as its weakest key, and a 1024-bit CA would
   * otherwise vouch for a 2048-bit leaf the page then accepts.
   */
  async function verifyIssuedBy(certificate, issuer) {
    var spec = SIGNATURE_ALGORITHMS[certificate.signatureAlgorithm];
    if (spec === undefined) {
      throw new Error("the certificate is signed with " + certificate.signatureAlgorithm
        + ", which this page does not verify");
    }
    if (certificate.tbsSignatureAlgorithm !== certificate.signatureAlgorithm
        || !bytesEqual(certificate.tbsSignatureAlgorithmDer, certificate.signatureAlgorithmDer)) {
      throw new Error("the certificate's outer and inner signature algorithms differ (RFC 5280 section 4.1.1.2)");
    }
    var key;
    var parameters;
    var signature;
    if (spec.kind === "ec") {
      if (issuer.publicKey.kind !== "ec") {
        throw new Error("an ECDSA certificate is signed by a non-EC key");
      }
      key = await crypto.subtle.importKey("spki", issuer.spki,
        { name: "ECDSA", namedCurve: issuer.publicKey.curve }, false, ["verify"]);
      parameters = { name: "ECDSA", hash: spec.hash };
      signature = derEcdsaToRaw(certificate.signatureValue, CURVE_WIDTH[issuer.publicKey.curve]);
    } else {
      if (issuer.publicKey.kind !== "rsa") throw new Error("an RSA certificate is signed by a non-RSA key");
      if (issuer.publicKey.bits < RSA_MINIMUM_BITS) {
        throw new Error("the issuing certificate's RSA key is " + issuer.publicKey.bits + " bits, and this page "
          + "verifies no signature with an RSA key under " + RSA_MINIMUM_BITS + " bits (plan 4.5 R10)");
      }
      signature = certificate.signatureValue;
      if (spec.kind === "pss") {
        var pss = pssParameters(certificate.signatureAlgorithmDer, children(certificate.signatureAlgorithmDer,
          element(certificate.signatureAlgorithmDer, 0)));
        key = await crypto.subtle.importKey("spki", issuer.spki, { name: "RSA-PSS", hash: pss.hash }, false,
          ["verify"]);
        parameters = { name: "RSA-PSS", saltLength: pss.saltLength };
      } else {
        key = await crypto.subtle.importKey("spki", issuer.spki, { name: "RSASSA-PKCS1-v1_5", hash: spec.hash },
          false, ["verify"]);
        parameters = { name: "RSASSA-PKCS1-v1_5" };
      }
    }
    return await crypto.subtle.verify(parameters, key, signature, certificate.tbs);
  }

  /* ---------------------------------------------------------------- what a path member must be */

  /**
   * RFC 5280 sections 6.1.4 and 6.1.5, on one certificate of a path: what its own extensions have to say about the
   * role the chain gives it. `position` is its index in `x5c`, the leaf being 0, and `chain` is the whole `x5c` as
   * parsed (optional: without it every certificate between the leaf and this one counts as an intermediate CA).
   *
   * - a critical extension the page does not process ends the path (sections 4.2, 6.1.4 (o) and 6.1.5 (f));
   * - the leaf, when it carries a keyUsage, must assert digitalSignature, because its key signs the request object
   *   (section 4.2.1.3: digitalSignature is the bit for "verifying digital signatures, other than signatures on
   *   certificates (bit 5) and CRLs (bit 6)");
   * - every certificate that issues another must be a CA (basicConstraints cA=TRUE, section 6.1.4 (k)) and, when it
   *   carries a keyUsage at all, must assert keyCertSign (sections 4.2.1.3 and 6.1.4 (n));
   * - a pathLenConstraint bounds how many non-self-issued intermediate certificates may follow it (sections 4.2.1.9 and
   *   6.1.4 (l)-(m)): a self-issued one (a CA's key rollover, issuer and subject the same name) does not count, and the
   *   leaf is not an intermediate.
   *
   * Returns the sentence that says what is wrong, or null.
   */
  function certificateFault(certificate, position, chain) {
    var subject = certificate.subject.text;
    if (certificate.unknownCritical.length) {
      return "x5c certificate " + position + " (" + subject + ") marks " + certificate.unknownCritical.map(function (id) {
        return EXTENSION_NAMES[id] === undefined ? id : id + " (" + EXTENSION_NAMES[id] + ")";
      }).join(", ") + " critical, and this page does not process " + (certificate.unknownCritical.length > 1
        ? "them" : "it") + " (RFC 5280 sections 4.2, 6.1.4 (o) and 6.1.5 (f)).";
    }
    if (position === 0) {
      if (certificate.keyUsagePresent && certificate.keyUsage.indexOf("digitalSignature") < 0) {
        return "x5c certificate 0 (" + subject + ") has a keyUsage of [" + certificate.keyUsage.join(", ")
          + "] without digitalSignature, so its key may not sign the request object (RFC 5280 section 4.2.1.3).";
      }
      return null;
    }
    if (!certificate.ca) {
      return "x5c certificate " + position + " (" + subject + ") is not a CA: basicConstraints cA=TRUE is required of "
        + "a certificate that issues another (RFC 5280 sections 4.2.1.9 and 6.1.4 (k)).";
    }
    if (certificate.keyUsagePresent && certificate.keyUsage.indexOf("keyCertSign") < 0) {
      return "x5c certificate " + position + " (" + subject + ") has a keyUsage without keyCertSign, so it may not "
        + "sign certificates (RFC 5280 sections 4.2.1.3 and 6.1.4 (n)).";
    }
    var intermediates = position - 1;
    if (Array.isArray(chain)) {
      intermediates = 0;
      for (var below = 1; below < position; below++) if (!chain[below].selfIssued) intermediates++;
    }
    if (certificate.pathLength !== null && intermediates > certificate.pathLength) {
      return "x5c certificate " + position + " (" + subject + ") permits " + certificate.pathLength
        + " intermediate CA certificate(s) below it and the chain has " + intermediates + " that are not self-issued "
        + "(RFC 5280 sections 4.2.1.9 and 6.1.4 (l), pathLenConstraint).";
    }
    return null;
  }

  /* ---------------------------------------------------------------- display */

  /** The SHA-256 of a certificate, as openssl prints it: uppercase hex pairs separated by colons. */
  async function fingerprintSha256(der) {
    var digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
    var text = [];
    for (var i = 0; i < digest.length; i++) text.push((digest[i] < 16 ? "0" : "") + digest[i].toString(16).toUpperCase());
    return text.join(":");
  }

  /** Whether a derived "now" is inside a certificate's validity, with the skew RFC 5280 checking allows for. */
  function validityOf(certificate, now, skewMs) {
    var skew = typeof skewMs === "number" ? skewMs : 0;
    if (now.getTime() + skew < certificate.notBefore.getTime()) return "notYetValid";
    if (now.getTime() - skew >= certificate.notAfter.getTime()) return "expired";
    return "valid";
  }

  return {
    parse: parse,
    importPublicKey: importPublicKey,
    verifyJws: verifyJws,
    verifyIssuedBy: verifyIssuedBy,
    certificateFault: certificateFault,
    fingerprintSha256: fingerprintSha256,
    validityOf: validityOf,
    derEcdsaToRaw: derEcdsaToRaw,
    JWS_ALGORITHMS: JWS_ALGORITHMS,
    SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
    KNOWN_EXTENSIONS: KNOWN_EXTENSIONS,
    element: element,
    children: children,
    bytesEqual: bytesEqual,
  };
})();
