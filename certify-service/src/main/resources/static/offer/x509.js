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
   * definite (X.690 sections 10.1 and 9.1).
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
      length = 0;
      for (var i = 0; i < count; i++) {
        var byte = bytes[pos++];
        if (byte === undefined) throw new Error("a DER length is truncated");
        length = length * 256 + byte;
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

  /** A non-negative INTEGER as a number, refusing what does not fit one (no field the page reads is that large). */
  function integer(bytes, el) {
    requireTag(el, UNIVERSAL, 2, "an INTEGER");
    var value = content(bytes, el);
    if (!value.length) throw new Error("an INTEGER is empty");
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

  /** A DirectoryString/IA5String's text, by the string type's own tag (X.680 section 30, X.690 section 8.20). */
  function directoryString(bytes, el) {
    var value = content(bytes, el);
    var text;
    switch (el.cls === UNIVERSAL ? el.tag : -1) {
      case 12: // UTF8String
        text = new TextDecoder("utf-8", { fatal: true }).decode(value);
        break;
      case 19: // PrintableString
      case 20: // TeletexString: read as latin1, which is what every certificate that uses it means
      case 22: // IA5String
      case 26: // VisibleString
        text = "";
        for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
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

  /** A UTCTime or GeneralizedTime, as an instant (RFC 5280 section 4.1.2.5, X.690 section 11.8). */
  function time(bytes, el) {
    requireTag(el, UNIVERSAL, el.tag === 24 ? 24 : 23, "a Time");
    var text = "";
    var value = content(bytes, el);
    for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
    var match;
    if (el.tag === 23) {
      // UTCTime "YYMMDDHHMMSSZ": YY 50..99 is 1950..1999 and 00..49 is 2000..2049 (RFC 5280 section 4.1.2.5.1)
      match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
      if (!match) throw new Error("a UTCTime is not YYMMDDHHMMSSZ");
      var yy = Number(match[1]);
      return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, Number(match[2]) - 1, Number(match[3]),
        Number(match[4]), Number(match[5]), Number(match[6])));
    }
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new Error("a GeneralizedTime is not YYYYMMDDHHMMSSZ");
    return new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]),
      Number(match[5]), Number(match[6])));
  }

  /* ---------------------------------------------------------------- extensions */

  var EXTENSION = {
    subjectAltName: "2.5.29.17", subjectKeyIdentifier: "2.5.29.14", authorityKeyIdentifier: "2.5.29.35",
    basicConstraints: "2.5.29.19", keyUsage: "2.5.29.15",
  };

  /**
   * The GeneralNames the page reads: dNSName [2] and URI [6], both IA5String (RFC 5280 section 4.2.1.6). `extnValue`
   * is the extension's OCTET STRING content, and every offset below is relative to it: a certificate's extension is
   * its own small DER document, so it is read as one.
   */
  function generalNames(extnValue) {
    var sans = { dnsNames: [], uris: [] };
    children(extnValue, element(extnValue, 0)).forEach(function (generalName) {
      if (generalName.cls !== CONTEXT) return;
      if (generalName.tag !== 2 && generalName.tag !== 6) return;
      var text = "";
      var value = content(extnValue, generalName);
      for (var i = 0; i < value.length; i++) text += String.fromCharCode(value[i]);
      (generalName.tag === 2 ? sans.dnsNames : sans.uris).push(text);
    });
    return sans;
  }

  /** The extensions of a certificate, by OID, each with the DER of its own extnValue octets. */
  function extensions(bytes, list) {
    var found = new Map();
    list.forEach(function (extension) {
      requireTag(extension, UNIVERSAL, 16, "an Extension");
      var parts = children(bytes, extension);
      if (parts.length < 2) throw new Error("an Extension has fewer than two elements");
      var id = oid(bytes, parts[0]);
      var value = parts[parts.length - 1];
      requireTag(value, UNIVERSAL, 4, "an extnValue");
      found.set(id, content(bytes, value));
    });
    return found;
  }

  /* ---------------------------------------------------------------- the certificate */

  /** The signature algorithms a certificate may name here, and the WebCrypto parameters each one needs. */
  var SIGNATURE_ALGORITHMS = {
    "1.2.840.10045.4.3.2": { kind: "ec", hash: "SHA-256" },      // ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": { kind: "ec", hash: "SHA-384" },      // ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": { kind: "ec", hash: "SHA-512" },      // ecdsa-with-SHA512
    "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },   // sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },   // sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },   // sha512WithRSAEncryption
  };

  var CURVE_OIDS = {
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
  };

  var OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
  var OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

  /**
   * One certificate, read from its DER (RFC 5280 section 4.1):
   * `{der, subject, issuer, notBefore, notAfter, serialNumber, version, sans, ca, pathLength, keyUsageText, ski, aki,
   * spki, publicKey, signatureAlgorithm, tbs, signatureValue, selfIssued}`.
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
      // version [0] EXPLICIT Version DEFAULT v1: the INTEGER inside says 0, 1 or 2
      version = integer(bytes, children(bytes, fields[0])[0]) + 1;
      index = 1;
    }
    var serialNumber = integer(bytes, fields[index++]);
    var tbsSignature = oid(bytes, children(bytes, requireTag(fields[index++], UNIVERSAL, 16, "a signature"))[0]);
    var issuerName = name(bytes, requireTag(fields[index++], UNIVERSAL, 16, "an issuer"));
    var validity = children(bytes, requireTag(fields[index++], UNIVERSAL, 16, "a Validity"));
    if (validity.length !== 2) throw new Error("a Validity is not a pair of times");
    var notBefore = time(bytes, validity[0]);
    var notAfter = time(bytes, validity[1]);
    var subjectName = name(bytes, requireTag(fields[index++], UNIVERSAL, 16, "a subject"));
    var spkiElement = requireTag(fields[index++], UNIVERSAL, 16, "a SubjectPublicKeyInfo");

    var found = new Map();
    for (; index < fields.length; index++) {
      var field = fields[index];
      if (field.cls !== CONTEXT) throw new Error("a TBSCertificate field the certificate does not define");
      if (field.tag === 3) {
        // extensions [3] EXPLICIT Extensions
        var sequence = children(bytes, field);
        if (sequence.length !== 1) throw new Error("the extensions are not one SEQUENCE");
        found = extensions(bytes, children(bytes, requireTag(sequence[0], UNIVERSAL, 16, "Extensions")));
      }
      // issuerUniqueID [1] and subjectUniqueID [2] carry nothing this page decides by (RFC 5280 4.1.2.8)
    }

    var sans = { dnsNames: [], uris: [] };
    if (found.has(EXTENSION.subjectAltName)) {
      sans = generalNames(found.get(EXTENSION.subjectAltName));
    }
    var ca = false;
    var pathLength = null;
    if (found.has(EXTENSION.basicConstraints)) {
      var constraintsValue = found.get(EXTENSION.basicConstraints);
      children(constraintsValue, element(constraintsValue, 0)).forEach(function (member) {
        if (member.cls === UNIVERSAL && member.tag === 1) ca = content(constraintsValue, member)[0] !== 0;
        if (member.cls === UNIVERSAL && member.tag === 2) pathLength = integer(constraintsValue, member);
      });
    }
    var ski = null;
    if (found.has(EXTENSION.subjectKeyIdentifier)) {
      var skiValue = found.get(EXTENSION.subjectKeyIdentifier);
      ski = content(skiValue, element(skiValue, 0));
    }
    var aki = null;
    if (found.has(EXTENSION.authorityKeyIdentifier)) {
      // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
      var akiValue = found.get(EXTENSION.authorityKeyIdentifier);
      children(akiValue, element(akiValue, 0)).forEach(function (member) {
        if (member.cls === CONTEXT && member.tag === 0 && aki === null) aki = content(akiValue, member);
      });
    }
    var keyUsageText = "";
    if (found.has(EXTENSION.keyUsage)) {
      var usageValue = found.get(EXTENSION.keyUsage);
      var bits = content(usageValue, element(usageValue, 0));
      var names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
        "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
      var text = [];
      for (var bit = 0; bit < names.length; bit++) {
        if (bits.length > 1 + (bit >> 3) && (bits[1 + (bit >> 3)] & (0x80 >> (bit & 7)))) text.push(names[bit]);
      }
      keyUsageText = text.join(", ");
    }

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
      subject: subjectName,
      issuer: issuerName,
      notBefore: notBefore,
      notAfter: notAfter,
      sans: sans,
      ca: ca,
      pathLength: pathLength,
      keyUsageText: keyUsageText,
      ski: ski,
      aki: aki,
      spki: bytes.subarray(spkiElement.start, spkiElement.end),
      publicKey: publicKey,
      signatureAlgorithm: signatureAlgorithm,
      tbsSignatureAlgorithm: tbsSignature,
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

  /**
   * Whether `signature` is `certificate`'s signature over `signingInput` under `alg`. An ECDSA JWS signature is `r || s`
   * raw (RFC 7518 section 3.4), which is what WebCrypto returns and expects; a certificate's own ECDSA signature is the
   * DER SEQUENCE (RFC 3279 section 2.2.3), which `derEcdsaToRaw` converts.
   */
  async function verifyJws(signingInput, signature, certificate, alg) {
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

  /** An ECDSA signature in DER (`SEQUENCE { INTEGER r, INTEGER s }`) as the fixed-width `r || s` WebCrypto expects. */
  function derEcdsaToRaw(der, width) {
    var outer = element(der, 0);
    requireTag(outer, UNIVERSAL, 16, "an ECDSA signature");
    var pair = children(der, outer);
    if (pair.length !== 2) throw new Error("an ECDSA signature is not a pair of integers");
    var raw = new Uint8Array(width * 2);
    [pair[0], pair[1]].forEach(function (part, index) {
      var value = content(der, requireTag(part, UNIVERSAL, 2, "an ECDSA signature integer"));
      var first = 0;
      while (first < value.length - 1 && value[first] === 0) first++;
      var significant = value.subarray(first);
      if (significant.length > width) throw new Error("an ECDSA signature integer is wider than its curve");
      raw.set(significant, index * width + (width - significant.length));
    });
    return raw;
  }

  var CURVE_WIDTH = { "P-256": 32, "P-384": 48, "P-521": 66 };

  /**
   * Whether `issuer` issued `certificate`: the algorithm, then the signature over the TBSCertificate with the issuer's
   * key (RFC 5280 section 6.1.3 (a)(1)). The outer `signatureAlgorithm` must be the one the TBS names, or the
   * certificate says two different things about how it was signed (RFC 5280 section 4.1.1.2) and is refused.
   */
  async function verifyIssuedBy(certificate, issuer) {
    var spec = SIGNATURE_ALGORITHMS[certificate.signatureAlgorithm];
    if (spec === undefined) {
      throw new Error("the certificate is signed with " + certificate.signatureAlgorithm
        + ", which this page does not verify");
    }
    if (certificate.tbsSignatureAlgorithm !== certificate.signatureAlgorithm) {
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
      key = await crypto.subtle.importKey("spki", issuer.spki, { name: "RSASSA-PKCS1-v1_5", hash: spec.hash }, false,
        ["verify"]);
      parameters = { name: "RSASSA-PKCS1-v1_5" };
      signature = certificate.signatureValue;
    }
    return await crypto.subtle.verify(parameters, key, signature, certificate.tbs);
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
    fingerprintSha256: fingerprintSha256,
    validityOf: validityOf,
    derEcdsaToRaw: derEcdsaToRaw,
    JWS_ALGORITHMS: JWS_ALGORITHMS,
    SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
    element: element,
    children: children,
    bytesEqual: bytesEqual,
  };
})();
