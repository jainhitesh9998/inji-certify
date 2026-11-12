#!/usr/bin/env python3
"""Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor, a library Certify does not maintain.

The second non-Java opinion on every mDoc the tests write to target/mdoc-samples/ (M-01 in
docs/design/20-mdl-issuer.md, decision D9). The Java harness uses Multipaz and Authlete; this uses pymdoccbor
(pycose + cryptography) for the COSE signature and a second digest opinion, cbor2 for the CBOR, and a small framing
walker of its own for the bytes as received, so one credential has to satisfy two independent stacks.

Input is the credential as issued: a bare IssuerSigned, or the draft-13 Document {docType, issuerSigned} the
0.14.0-compatible surface returns; raw CBOR, or the same bytes base64url-encoded.

Checks, named like the Java harness's where the rule is the same:

  issuerSigned.parse          the file is an IssuerSigned (or a Document around one).
  mso.docType                 the MSO docType equals --doctype (and a Document's docType equals it too).
  x5chain.iaca                with --iaca: each certificate signs the next and the last reaches the IACA, all valid now.
  issuerAuth.signature        the COSE_Sign1 verifies with the x5chain leaf (pymdoccbor).
  mso.payloadTag24            the COSE payload is #6.24(bstr .cbor MobileSecurityObject).
  mso.nameSpaces              nameSpaces is a non-empty map, no namespace is empty, every namespace has valueDigests,
                              no elementIdentifier and no digestID repeats within a namespace.
  mso.valueDigests            every IssuerSignedItem hashes, over the bytes as received, to its valueDigests entry under
                              the declared algorithm (SHA-256/384/512); every #6.24 head is the preferred encoding,
                              because a verifier that re-encodes (pymdoccbor among them) would otherwise hash other
                              bytes than the issuer did; the verified count equals the item count.
  mso.valueDigests.pymdoccbor pymdoccbor's own element-hash check agrees (it re-encodes and computes SHA-256 only: any
                              other digestAlgorithm fails unless --allow-partial accepts the partial run).
  mso.deviceKey               with --holder: the MSO deviceKey is that JWK (EC2: kty 2, crv, x, y; OKP Ed25519: kty 1,
                              crv 6, x, no y), and it carries no private key (label -4).
  mso.validityInfo            signed <= validFrom < validUntil, validFrom <= expectedUpdate < validUntil, now inside
                              validFrom..validUntil, read from the dates as sent whether tagged or not.
  mso.validityInfo.tdateTags  every validityInfo date is #6.0(tstr) RFC 3339 with whole seconds and Z.

With --gaps <sample>.gaps (the sidecar the producing test writes), a failing check the sidecar lists is reported as an
accepted gap instead of a failure. Whether a listed gap is still present is decided by certify-conformance-mdoc; here a
listed check that passes is only a note.

Exit status: 0 every check passed or is an accepted gap, 1 a check failed, 2 the file is not an IssuerSigned.

Usage:
    verify_mdoc.py <sample.mdoc> [--doctype org.iso.18013.5.1.mDL] [--iaca iaca.pem] [--holder holder.jwk]
                   [--gaps sample.gaps] [--allow-partial]
"""
import argparse
import base64
import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pymdoccbor.mdoc.issuersigned import IssuerSigned

X5CHAIN_LABEL = 33
DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
WHOLE_SECOND_TDATE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
EC2_CURVES = {"P-256": 1, "P-384": 2, "P-521": 3}

# pymdoccbor logs every skipped chain validation at WARNING; a --iaca-less run is normal, an error is not
logging.getLogger("pymdoccbor").setLevel(logging.ERROR)


class Check(Exception):
    """A failed check: the message names the rule it broke."""


# ---- the bytes as received ----------------------------------------------------------------------------------------

def head(data, pos):
    """(major, additional, argument, next) of the CBOR head at pos; argument is None for indefinite length."""
    if pos >= len(data):
        raise Check(f"CBOR item at offset {pos} runs past the end ({len(data)} bytes)")
    initial = data[pos]
    major, additional = initial >> 5, initial & 0x1F
    if additional < 24:
        return major, additional, additional, pos + 1
    if additional in (24, 25, 26, 27):
        size = 1 << (additional - 24)
        if len(data) - pos - 1 < size:
            raise Check(f"truncated CBOR head at offset {pos}")
        return major, additional, int.from_bytes(data[pos + 1:pos + 1 + size], "big"), pos + 1 + size
    if additional == 31:
        return major, additional, None, pos + 1
    raise Check(f"reserved CBOR additional information {additional} at offset {pos}")


def skip(data, pos, depth=0):
    """The end offset of the CBOR item at pos, without interpreting it."""
    if depth > 256:
        raise Check(f"CBOR nested deeper than 256 levels at offset {pos}")
    major, _, argument, nxt = head(data, pos)
    if major in (0, 1, 7):
        return nxt
    if major in (2, 3):
        if argument is not None:
            if argument > len(data) - nxt:
                raise Check(f"CBOR string at offset {pos} declares {argument} bytes, {len(data) - nxt} remain")
            return nxt + argument
        while data[nxt:nxt + 1] != b"\xff":
            nxt = skip(data, nxt, depth + 1)
        return nxt + 1
    if major == 6:
        return skip(data, nxt, depth + 1)
    per_entry = 1 if major == 4 else 2
    if argument is None:
        while True:
            if nxt >= len(data):
                raise Check("indefinite-length item not terminated")
            if data[nxt] == 0xFF:
                return nxt + 1
            for _ in range(per_entry):
                nxt = skip(data, nxt, depth + 1)
    for _ in range(argument * per_entry):
        nxt = skip(data, nxt, depth + 1)
    return nxt


def map_entries(data, pos):
    """[(key_start, value_start, value_end)] of the CBOR map at pos, and the map's end."""
    major, _, argument, nxt = head(data, pos)
    if major != 5:
        raise Check(f"CBOR item at offset {pos} is not a map")
    entries = []
    count = 0
    while argument is None or count < argument:
        if argument is None and data[nxt:nxt + 1] == b"\xff":
            return entries, nxt + 1
        value = skip(data, nxt)
        end = skip(data, value)
        entries.append((nxt, value, end))
        nxt, count = end, count + 1
    return entries, nxt


def array_items(data, pos):
    """[(start, end)] of the items of the CBOR array at pos."""
    major, _, argument, nxt = head(data, pos)
    if major != 4:
        raise Check(f"CBOR item at offset {pos} is not an array")
    items = []
    while argument is None or len(items) < argument:
        if argument is None and data[nxt:nxt + 1] == b"\xff":
            break
        end = skip(data, nxt)
        items.append((nxt, end))
        nxt = end
    return items


def value_of(data, key):
    """The raw bytes of the value under the text key `key` of the top-level map, or None."""
    entries, end = map_entries(data, 0)
    if end != len(data):
        raise Check(f"{len(data) - end} trailing byte(s) after the top-level map")
    found = [data[v:e] for k, v, e in entries if cbor2.loads(data[k:v]) == key]
    if len(found) > 1:
        raise Check(f"the top-level map carries {key} twice")
    return found[0] if found else None


def wire_items(issuer_signed):
    """{namespace: [raw IssuerSignedItemBytes]} exactly as received."""
    namespaces = value_of(issuer_signed, "nameSpaces")
    if namespaces is None:
        return {}
    items = {}
    entries, _ = map_entries(namespaces, 0)
    for k, v, e in entries:
        block = namespaces[v:e]
        items[cbor2.loads(namespaces[k:v])] = [block[start:end] for start, end in array_items(block, 0)]
    return items


def preferred_tag24_head(raw):
    """True when raw starts with the shortest encodings of tag 24 and of its bstr length."""
    if raw[:2] != b"\xd8\x18":
        return False
    _, additional, length, _ = head(raw, 2)
    if length is None:
        return False
    shortest = 0 if length < 24 else 24 if length < 0x100 else 25 if length < 0x10000 else 26 if length < 2 ** 32 else 27
    return additional == shortest if length >= 24 else additional == length


# ---- the credential -------------------------------------------------------------------------------------------------

def load(path):
    """(received bytes, IssuerSigned bytes, Document docType or None, encoding)."""
    with open(path, "rb") as f:
        data = f.read()
    candidates = [("cbor", data)]
    text = b"".join(data.split())
    try:
        candidates.append(("base64url", base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))))
    except Exception:  # not base64url, the raw CBOR attempt already covered the file
        pass
    for encoding, raw in candidates:
        try:
            document = cbor2.loads(raw)
        except Exception:
            continue
        if isinstance(document, dict) and "issuerSigned" in document:
            return raw, value_of(raw, "issuerSigned"), document.get("docType"), encoding
        if isinstance(document, dict) and "issuerAuth" in document and "nameSpaces" in document:
            return raw, raw, None, encoding
    raise SystemExit(f"FAIL {path}: not an IssuerSigned document (raw CBOR or base64url expected)")


def cose_sign1(issuer_auth):
    """The COSE_Sign1 array, untagged when it arrived as #6.18 (the draft-13 Document)."""
    if isinstance(issuer_auth, cbor2.CBORTag):
        if issuer_auth.tag != 18:
            raise Check(f"issuerAuth carries tag {issuer_auth.tag}, not COSE_Sign1 (18)")
        issuer_auth = issuer_auth.value
    if not isinstance(issuer_auth, (list, tuple)) or len(issuer_auth) != 4:
        raise Check("issuerAuth is not a COSE_Sign1 [protected, unprotected, payload, signature]")
    return issuer_auth


def x5chain(sign1):
    """The x5chain certificates, leaf first: COSE label 33 in the unprotected header, else the protected one."""
    chain = sign1[1].get(X5CHAIN_LABEL) if isinstance(sign1[1], dict) else None
    if chain is None and isinstance(sign1[0], bytes) and sign1[0]:
        header = cbor2.loads(sign1[0])
        chain = header.get(X5CHAIN_LABEL) if isinstance(header, dict) else None
    if chain is None:
        raise Check("no x5chain (COSE label 33) in IssuerAuth")
    entries = chain if isinstance(chain, (list, tuple)) else [chain]
    if not entries:
        raise Check("x5chain is empty")
    return [x509.load_der_x509_certificate(der) for der in entries]


def mso_of(sign1):
    """(MSO dict with tags preserved, payload tagged 24?)."""
    payload = cbor2.loads(sign1[2])
    if isinstance(payload, cbor2.CBORTag) and payload.tag == 24 and isinstance(payload.value, bytes):
        return cbor2.loads(payload.value), True
    return payload, False


# ---- the checks -----------------------------------------------------------------------------------------------------

def check_chain(certificates, iaca):
    now = datetime.now(timezone.utc)
    problems = []
    for index in range(len(certificates) - 1):
        try:
            certificates[index].verify_directly_issued_by(certificates[index + 1])
        except Exception as e:
            problems.append(f"certificate {index} is not issued by certificate {index + 1}: {e}")
    last = certificates[-1]
    if last.fingerprint(hashes.SHA256()) != iaca.fingerprint(hashes.SHA256()):
        try:
            last.verify_directly_issued_by(iaca)
        except Exception as e:
            problems.append(f"{last.subject.rfc4514_string()} does not reach the IACA {iaca.subject.rfc4514_string()}: {e}")
    for certificate in certificates + [iaca]:
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            problems.append(f"{certificate.subject.rfc4514_string()} is not valid at {now.isoformat()}")
    if problems:
        raise Check("; ".join(problems))
    return f"x5chain reaches {iaca.subject.rfc4514_string()}"


def check_namespaces(namespaces, items, value_digests):
    if not isinstance(namespaces, dict) or not namespaces:
        raise Check("nameSpaces is empty: nothing to verify")
    problems = []
    for namespace, wire in items.items():
        if not wire:
            problems.append(f"namespace {namespace} carries no IssuerSignedItem")
        if namespace not in value_digests:
            problems.append(f"namespace {namespace} is in nameSpaces but has no valueDigests entry in the MSO")
        identifiers, digest_ids = set(), set()
        for raw in wire:
            item = cbor2.loads(cbor2.loads(raw).value)
            identifier, digest_id = item.get("elementIdentifier"), item.get("digestID")
            if identifier in identifiers:
                problems.append(f"elementIdentifier {identifier} repeats in {namespace}")
            if digest_id in digest_ids:
                problems.append(f"digestID {digest_id} repeats in {namespace} ({identifier})")
            identifiers.add(identifier)
            digest_ids.add(digest_id)
    if problems:
        raise Check("; ".join(problems))
    return f"{sum(len(w) for w in items.values())} items in {len(items)} namespace(s), identifiers and digestIDs unique"


def check_value_digests(items, value_digests, algorithm):
    if algorithm not in DIGESTS:
        raise Check(f"digestAlgorithm {algorithm} is not SHA-256, SHA-384 or SHA-512 (ISO/IEC 18013-5 9.1.2.5)")
    problems, verified, total = [], 0, 0
    for namespace, wire in items.items():
        for raw in wire:
            total += 1
            tagged = cbor2.loads(raw)
            if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != 24:
                problems.append(f"an item in {namespace} is not #6.24(bstr)")
                continue
            item = cbor2.loads(tagged.value)
            name = f"{namespace}/{item.get('elementIdentifier')} digestID {item.get('digestID')}"
            if not preferred_tag24_head(raw):
                problems.append(f"{name} has a non-preferred #6.24 head {raw[:6].hex()}: a verifier that re-encodes "
                                "hashes other bytes than the issuer did")
            expected = value_digests.get(namespace, {}).get(item.get("digestID"))
            if expected is None:
                problems.append(f"{name} has no valueDigests entry")
            elif DIGESTS[algorithm](raw).digest() != expected:
                problems.append(f"{name}: the received bytes do not hash to the declared digest")
            else:
                verified += 1
    if problems:
        raise Check("; ".join(problems))
    if verified != total or total == 0:
        raise Check(f"verified {verified} of {total} items")
    return f"{verified}/{total} items hash to valueDigests under {algorithm}, over the received bytes"


def check_pymdoccbor_digests(verifier, namespaces, algorithm, total, allow_partial, notes):
    if algorithm != "SHA-256":
        message = f"pymdoccbor computes SHA-256 only and the MSO declares {algorithm}"
        if allow_partial:
            notes.append(f"partial run, {message}")
            return "not run (--allow-partial)"
        raise Check(f"{message} (pass --allow-partial to accept a partial verification)")
    results = verifier.verify_element_hashes(namespaces)
    if not results["valid"]:
        raise Check(f"IssuerSignedItem digests: {results['failed']}")
    if results["total"] != total or results["verified"] != total:
        raise Check(f"pymdoccbor verified {results['verified']} of {results['total']}, the wire carries {total}")
    return f"pymdoccbor verifies {results['verified']}/{total}"


def b64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def check_device_key(mso, holder):
    key = ((mso.get("deviceKeyInfo") or {}).get("deviceKey")) or {}
    if not isinstance(key, dict) or not key:
        raise Check("MSO deviceKeyInfo.deviceKey is missing")
    if -4 in key:
        raise Check("the MSO deviceKey carries a private key (COSE_Key label -4, d)")
    if holder.get("kty") == "EC":
        expected = {1: 2, -1: EC2_CURVES.get(holder.get("crv")), -2: b64url(holder["x"]), -3: b64url(holder["y"])}
    elif holder.get("kty") == "OKP" and holder.get("crv") == "Ed25519":
        expected = {1: 1, -1: 6, -2: b64url(holder["x"])}
        if -3 in key:
            raise Check("OKP deviceKey carries a y coordinate (label -3)")
    else:
        raise Check(f"unsupported holder key {holder.get('kty')} {holder.get('crv')}")
    wrong = [label for label, value in expected.items() if key.get(label) != value]
    if wrong:
        raise Check(f"deviceKey labels {wrong} do not match the holder {holder.get('kty')} {holder.get('crv')} key")
    return f"deviceKey is the {holder.get('crv')} holder key"


def instant(field, value):
    """The instant a validityInfo date names, tagged or not and at any precision: the order must not depend on it."""
    text = value.value if isinstance(value, cbor2.CBORTag) else value
    if not isinstance(text, str):
        raise Check(f"validityInfo.{field} is not a date string: {value!r}")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise Check(f"validityInfo.{field} is not an RFC 3339 date-time: {text}")
    if parsed.tzinfo is None:
        raise Check(f"validityInfo.{field} has no time offset: {text}")
    return parsed


def check_validity(validity):
    for field in ("signed", "validFrom", "validUntil"):
        if field not in validity:
            raise Check(f"validityInfo.{field} is missing")
    signed, valid_from, valid_until = (instant(f, validity[f]) for f in ("signed", "validFrom", "validUntil"))
    expected_update = instant("expectedUpdate", validity["expectedUpdate"]) if "expectedUpdate" in validity else None
    now = datetime.now(timezone.utc)
    if signed > valid_from:
        raise Check(f"signed {signed.isoformat()} is after validFrom {valid_from.isoformat()} (ISO/IEC 18013-5 9.1.2.4)")
    if not valid_from < valid_until:
        raise Check(f"validFrom {valid_from.isoformat()} is not before validUntil {valid_until.isoformat()}")
    if expected_update is not None and not valid_from <= expected_update < valid_until:
        raise Check(f"expectedUpdate {expected_update.isoformat()} is outside validFrom..validUntil")
    if not valid_from <= now <= valid_until:
        raise Check(f"{now.isoformat()} is outside validFrom..validUntil")
    return f"signed {signed.isoformat()} within {valid_from.isoformat()}..{valid_until.isoformat()}"


def check_tdate_tags(validity):
    problems = []
    for field in ("signed", "validFrom", "validUntil", "expectedUpdate"):
        if field not in validity:
            continue
        value = validity[field]
        if not (isinstance(value, cbor2.CBORTag) and value.tag == 0 and isinstance(value.value, str)):
            problems.append(f"{field} is not #6.0(tstr): {value!r}")
        elif not WHOLE_SECOND_TDATE.fullmatch(value.value):
            problems.append(f"{field} is not RFC 3339 with whole seconds and Z: {value.value}")
    if problems:
        raise Check("; ".join(problems) + " (ISO/IEC 18013-5 9.1.2.4)")
    return "validityInfo dates are #6.0 whole-second tdate"


def read_gaps(path):
    gaps = {}
    if not path:
        return gaps
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.]+)(\?)?\s+#\s*(\S.*)", line)
            if not match:
                raise SystemExit(f"FAIL {path} line {number} is not '<check>[?] # <reason>': {line}")
            gaps[match.group(1)] = match.group(3)
    return gaps


def main():
    parser = argparse.ArgumentParser(description="Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor")
    parser.add_argument("issuer_signed", help="raw CBOR or base64url IssuerSigned or draft-13 Document")
    parser.add_argument("--doctype", help="docType the MSO must declare, e.g. org.iso.18013.5.1.mDL")
    parser.add_argument("--iaca", help="PEM IACA the x5chain must reach")
    parser.add_argument("--holder", help="holder public JWK the MSO deviceKey must equal (the .holder.jwk sidecar)")
    parser.add_argument("--gaps", help="the sample's .gaps sidecar: listed checks may fail as accepted gaps")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept a run where pymdoccbor cannot verify the element digests (non-SHA-256 algorithm)")
    args = parser.parse_args()
    gaps = read_gaps(args.gaps)

    _, issuer_signed_bytes, document_doctype, encoding = load(args.issuer_signed)
    try:
        document = cbor2.loads(issuer_signed_bytes)
        sign1 = cose_sign1(document["issuerAuth"])
        mso, payload_tagged = mso_of(sign1)
        namespaces = document["nameSpaces"]
        items = wire_items(issuer_signed_bytes)
        value_digests = mso.get("valueDigests") or {}
        validity = raw_validity(sign1, payload_tagged)
        verifier = IssuerSigned(nameSpaces=namespaces, issuerAuth=document["issuerAuth"]).issuer_auth
    except Check:
        raise
    except Exception as e:  # anything the parsers refuse is a malformed IssuerSigned, not a crash
        raise Check(f"{type(e).__name__}: {e}")
    iaca = None
    if args.iaca:
        with open(args.iaca, "rb") as pem:
            iaca = x509.load_pem_x509_certificate(pem.read())
    holder = None
    if args.holder:
        with open(args.holder, encoding="utf-8") as f:
            holder = json.load(f)
    notes = []

    def doc_type():
        problems = []
        if args.doctype and mso.get("docType") != args.doctype:
            problems.append(f"MSO docType is {mso.get('docType')}, expected {args.doctype}")
        if document_doctype is not None and document_doctype != mso.get("docType"):
            problems.append(f"the Document's docType {document_doctype} is not the MSO's {mso.get('docType')}")
        if problems:
            raise Check("; ".join(problems))
        return f"docType {mso.get('docType')}"

    def signature():
        try:
            valid = verifier.verify_signature([iaca] if iaca is not None else None)
        except Exception as e:  # pymdoccbor raises on a malformed header or a chain that misses the root
            raise Check(f"pymdoccbor: {e}")
        if not valid:
            raise Check("the IssuerAuth signature does not verify with the x5chain leaf")
        return "pymdoccbor verifies the COSE_Sign1 with the x5chain leaf"

    def payload_tag():
        if not payload_tagged:
            raise Check("the MSO payload is not #6.24(bstr .cbor MobileSecurityObject)")
        return "tag 24"

    total = sum(len(w) for w in items.values())
    checks = [("issuerSigned.parse", lambda: f"{encoding}, {'Document' if document_doctype else 'IssuerSigned'}"),
              ("mso.docType", doc_type)]
    if iaca is not None:
        checks.append(("x5chain.iaca", lambda: check_chain(x5chain(sign1), iaca)))
    checks += [("issuerAuth.signature", signature),
               ("mso.payloadTag24", payload_tag),
               ("mso.nameSpaces", lambda: check_namespaces(namespaces, items, value_digests)),
               ("mso.valueDigests", lambda: check_value_digests(items, value_digests, mso.get("digestAlgorithm"))),
               ("mso.valueDigests.pymdoccbor", lambda: check_pymdoccbor_digests(
                   verifier, namespaces, mso.get("digestAlgorithm"), total, args.allow_partial, notes))]
    if holder is not None:
        checks.append(("mso.deviceKey", lambda: check_device_key(mso, holder)))
    checks += [("mso.validityInfo", lambda: check_validity(validity)),
               ("mso.validityInfo.tdateTags", lambda: check_tdate_tags(validity))]

    failures = 0
    print(f"{args.issuer_signed}: docType={mso.get('docType')} items={total} namespaces={len(items)} "
          f"digestAlgorithm={mso.get('digestAlgorithm')} encoding={encoding}")
    for name, run in checks:
        try:
            message = run()
        except Exception as e:
            reason = str(e) if isinstance(e, Check) else f"{type(e).__name__}: {e}"
            if name in gaps:
                print(f"  GAP  {name}: {reason} (accepted: {gaps[name]})")
            else:
                print(f"  FAIL {name}: {reason}")
                failures += 1
            continue
        print(f"  PASS {name}: {message}")
        if name in gaps:
            notes.append(f"{name} is a declared gap and passes here; certify-conformance-mdoc decides whether it is gone")
    for note in notes:
        print(f"  NOTE {note}")
    return 1 if failures else 0


def raw_validity(sign1, payload_tagged):
    """validityInfo with #6.0 kept as a tag (cbor2 would turn it into a datetime and hide the encoding)."""
    mso_bytes = cbor2.loads(sign1[2]).value if payload_tagged else sign1[2]
    entries, _ = map_entries(mso_bytes, 0)
    for k, v, e in entries:
        if cbor2.loads(mso_bytes[k:v]) == "validityInfo":
            validity = {}
            dates, _ = map_entries(mso_bytes[v:e], 0)
            block = mso_bytes[v:e]
            for dk, dv, de in dates:
                validity[cbor2.loads(block[dk:dv])] = raw_value(block[dv:de])
            return validity
    raise Check("MSO validityInfo is missing")


def raw_value(data):
    """A tstr or #6.N(tstr) decoded without cbor2's semantic conversion of the tag."""
    major, _, argument, nxt = head(data, 0)
    if major == 6:
        return cbor2.CBORTag(argument, cbor2.loads(data[nxt:]))
    return cbor2.loads(data)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Check as e:
        print(f"FAIL issuerSigned.parse: {e}")
        sys.exit(2)
