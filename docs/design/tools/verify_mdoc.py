#!/usr/bin/env python3
"""Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor, a library Certify does not maintain.

The second non-Java opinion on every mDoc the tests write to target/mdoc-samples/ (M-01 in
docs/design/20-mdl-issuer.md, decision D9). The Java harness uses Multipaz and Authlete; this uses pymdoccbor
(pycose + cryptography) for the COSE signature and a second digest opinion, cbor2 for the CBOR, and a small framing
walker of its own for the bytes as received, so one credential has to satisfy two independent stacks.

Input is the credential as issued: a bare IssuerSigned, or the draft-13 Document {docType, issuerSigned} the
0.14.0-compatible surface returns; raw CBOR, or the same bytes base64url-encoded.

Every check collects ALL its problems, each under a stable problem code, and reports them as <check>:<code>. The
check names and codes are those of the Java harness (IndependentMdocVerifier.PROBLEM_CODES; ProblemCodeRegistryTest
compares the table below with it), so one .gaps sidecar serves both. The checks this tool runs:

  credential.shape            documentWrapper: the credential is a Document {docType, issuerSigned}, not the bare
                              IssuerSigned.
  issuerSigned.parse          the file is an IssuerSigned (no CBOR map key twice, every item #6.24); exit 2 if not.
  issuerAuth.untagged         tagged: IssuerAuth carries a CBOR tag (ISO/IEC 18013-5 9.1.2.4: untagged COSE_Sign1).
  issuerAuth.signature.pymdoccbor   the COSE_Sign1 verifies with the x5chain leaf (this tool only, no gap covers it).
  mso.payloadTag24            notTag24.
  mso.nameSpaces              empty, emptyNamespace:<ns>, noValueDigests:<ns>, duplicateIdentifier:<ns>/<id>.
  mso.valueDigests            badAlgorithm, empty, noItems, nonPreferredHead:<ns>/<id>, noNamespace:<ns>,
                              noEntry:<ns>/<id>, mismatch:<ns>/<id>: digests over the bytes as received.
  mso.valueDigests.pymdoccbor pymdoccbor's own element-hash check (this tool only; SHA-256 only, --allow-partial).
  mso.valueDigests.digestIdsUnique  duplicate:<ns>/<digestID>.
  mso.deviceKey               noHolder, unsupportedHolder, missing, privateKey, kty, crv, x, y, yOnOkp (--holder).
  mso.docType                 missing, mismatch (--doctype), documentMismatch.
  mso.validityInfo            missing:<field>, notDate:<field>, signedAfterValidFrom, validFromNotBeforeValidUntil,
                              expectedUpdateBeforeValidFrom, expectedUpdateNotBeforeValidUntil, notYetValid, expired.
  mso.validityInfo.tdateTags  missing:<field>, untagged:<field>, notTdate:<field>, notRfc3339:<field>,
                              fractionalSeconds:<field>, notZulu:<field>, notCalendar:<field>.
  x5chain.iaca                noAnchorSupplied (no --iaca), onlyAnchor, notIssuedBy:<i>, notAnchored,
                              notValidAt:<i>, notValidAt:anchor.
  x5chain.noSelfSigned        selfSigned:<i>.
  x5chain.serialNumber        nonPositive, zero, tooLong (RFC 5280 4.1.2.2).

The Java harness alone runs issuerAuth.signature.multipaz/.authlete, mso.parse, mso.valueDigests.calculateDigest and
mdl.elementTypes, and reports the multipaz*/pkix* codes and duplicateHidden; a declared gap for those is a NOTE here.

With --gaps <sample>.gaps (the sidecar the producing test writes, one "<check>:<code> # <reason>" per line), a
reported problem the sidecar lists is an accepted gap; a reported problem it does not list fails, and a listed code of
a rule this tool implements that is no longer reported fails too ("gap no longer present"). The sidecar is refused when
it names a whole check, an unknown check or code, or a line without a reason.

Exit status: 0 every problem is an accepted gap, 1 a problem is not (or a gap is gone), 2 the credential is not an
IssuerSigned or the .gaps file is malformed.

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
import warnings
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pymdoccbor.mdoc.issuersigned import IssuerSigned

# BEGIN PROBLEM CODES (identical to IndependentMdocVerifier.PROBLEM_CODES; ProblemCodeRegistryTest compares them)
PROBLEM_CODES = {
    "credential.shape": ["documentWrapper"],
    "issuerSigned.parse": ["malformed"],
    "issuerAuth.untagged": ["tagged"],
    "issuerAuth.signature.multipaz": ["noAlg", "unsupportedAlg", "invalid"],
    "issuerAuth.signature.authlete": ["notCoseSign1", "noX5chain", "invalid"],
    "mso.payloadTag24": ["notTag24"],
    "mso.parse": ["refused"],
    "mso.nameSpaces": ["empty", "emptyNamespace:*", "noValueDigests:*", "duplicateIdentifier:*",
                       "multipazStructural", "multipazAgainstMso"],
    "mso.valueDigests": ["badAlgorithm", "empty", "noItems", "nonPreferredHead:*", "noNamespace:*", "noEntry:*",
                         "mismatch:*", "duplicateHidden"],
    "mso.valueDigests.calculateDigest": ["badAlgorithm", "noEntry:*", "mismatch:*"],
    "mso.valueDigests.digestIdsUnique": ["duplicate:*"],
    "mso.deviceKey": ["noHolder", "unsupportedHolder", "missing", "privateKey", "kty", "crv", "x", "y", "yOnOkp",
                      "multipazUnreadable", "multipazMismatch"],
    "mso.docType": ["missing", "mismatch", "documentMismatch"],
    "mso.validityInfo": ["missing:*", "notDate:*", "signedAfterValidFrom", "validFromNotBeforeValidUntil",
                         "expectedUpdateBeforeValidFrom", "expectedUpdateNotBeforeValidUntil", "notYetValid",
                         "expired", "multipazDisagrees:*", "multipazRejects"],
    "mso.validityInfo.tdateTags": ["missing:*", "untagged:*", "notTdate:*", "notRfc3339:*", "fractionalSeconds:*",
                                   "notZulu:*", "notCalendar:*"],
    "x5chain.iaca": ["noAnchorSupplied", "onlyAnchor", "notIssuedBy:*", "notAnchored", "notValidAt:*", "pkix:*",
                     "multipaz"],
    "x5chain.noSelfSigned": ["selfSigned:*"],
    "x5chain.serialNumber": ["nonPositive", "zero", "tooLong"],
    "mdl.elementTypes": ["noNamespace", "missing:*", "untyped:*", "notInDocType:*", "unmodelled:*"]
}
# END PROBLEM CODES

# What only the Java harness can report: whole checks, and per check the code kinds of its library opinions.
JAVA_ONLY_CHECKS = {"issuerAuth.signature.multipaz", "issuerAuth.signature.authlete", "mso.parse",
                    "mso.valueDigests.calculateDigest", "mdl.elementTypes"}
JAVA_ONLY_KINDS = {"mso.nameSpaces": {"multipazStructural", "multipazAgainstMso"},
                   "mso.valueDigests": {"duplicateHidden"},
                   "mso.deviceKey": {"multipazUnreadable", "multipazMismatch"},
                   "mso.validityInfo": {"multipazDisagrees", "multipazRejects"},
                   "x5chain.iaca": {"pkix", "multipaz"}}
# Checks only this tool runs; they are not in the shared table, so no .gaps line can accept them.
PYTHON_ONLY_CODES = {"issuerAuth.signature.pymdoccbor": ["invalid"],
                     "mso.valueDigests.pymdoccbor": ["partial", "mismatch", "count"]}

ERROR = "error"
CODE = re.compile(r"([A-Za-z][A-Za-z0-9]*)(?::([A-Za-z0-9_.\-/]+))?")
GAP_LINE = re.compile(r"([A-Za-z0-9_.]+):(\S+)\s+#\s*(\S.*)")
BARE_GAP_LINE = re.compile(r"[A-Za-z0-9_.]+\??(\s+#.*)?")
X5CHAIN_LABEL = 33
DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
VALIDITY_FIELDS = ("signed", "validFrom", "validUntil", "expectedUpdate")
EC2_CURVES = {"P-256": 1, "P-384": 2, "P-521": 3}
MAX_SERIAL_OCTETS = 20

# pymdoccbor logs every skipped chain validation at WARNING; a --iaca-less run is normal, an error is not
logging.getLogger("pymdoccbor").setLevel(logging.ERROR)
# cryptography warns whenever it reads a non-positive serial; x5chain.serialNumber reports it as a problem instead
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")


class Check(Exception):
    """The credential cannot be read as an IssuerSigned at all: issuerSigned.parse, exit 2."""


class Unusable(Exception):
    """An input other than the credential (the .gaps sidecar) is malformed: exit 2."""


def is_problem_code(check, code, registry=None):
    codes = (registry or PROBLEM_CODES).get(check)
    match = CODE.fullmatch(code or "")
    if codes is None or not match:
        return False
    return code in codes if match.group(2) is None else f"{match.group(1)}:*" in codes


def kind(code):
    return code.split(":", 1)[0]


def parameter(value):
    """A code parameter as both verifiers spell it: every character outside [A-Za-z0-9_.-/] becomes _."""
    text = "".join(c if c.isascii() and (c.isalnum() or c in "_.-/") else "_" for c in str(value))
    return text or "_"


class Problems:
    """The problems one check found, by code, in the order found; the same code twice keeps both messages."""

    def __init__(self, check):
        self.check = check
        self.found = {}

    def add(self, code, message):
        registry = PYTHON_ONLY_CODES if self.check in PYTHON_ONLY_CODES else PROBLEM_CODES
        if code != ERROR and not is_problem_code(self.check, code, registry):
            raise RuntimeError(f"the tool reports the unregistered problem code {self.check}:{code}")
        if code in self.found and self.found[code] != message:
            self.found[code] += "; " + message
        else:
            self.found.setdefault(code, message)


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
    """[(key_start, value_start, value_end)] of the CBOR map at pos, and the map's end. A key twice is refused: two
    decoders may keep different values for it (RFC 8949 5.6), so a namespace twice could hide signed items."""
    major, _, argument, nxt = head(data, pos)
    if major != 5:
        raise Check(f"CBOR item at offset {pos} is not a map")
    entries, seen = [], set()
    count = 0
    while argument is None or count < argument:
        if argument is None and data[nxt:nxt + 1] == b"\xff":
            return entries, nxt + 1
        value = skip(data, nxt)
        end = skip(data, value)
        key = cbor2.loads(data[nxt:value])
        marker = (type(key).__name__, key) if isinstance(key, (str, int, bytes)) else (None, data[nxt:value])
        if marker in seen:
            raise Check(f"the CBOR map at offset {pos} carries the key {key!r} twice")
        seen.add(marker)
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
    return found[0] if found else None


def wire_items(issuer_signed):
    """{namespace: [raw IssuerSignedItemBytes]} exactly as received; every item must be #6.24(bstr)."""
    namespaces = value_of(issuer_signed, "nameSpaces")
    if namespaces is None:
        return {}
    items = {}
    entries, _ = map_entries(namespaces, 0)
    for k, v, e in entries:
        namespace, block = cbor2.loads(namespaces[k:v]), namespaces[v:e]
        items[namespace] = [block[start:end] for start, end in array_items(block, 0)]
        for index, raw in enumerate(items[namespace]):
            tagged = cbor2.loads(raw)
            if not (isinstance(tagged, cbor2.CBORTag) and tagged.tag == 24 and isinstance(tagged.value, bytes)):
                raise Check(f"IssuerSignedItem {index} in {namespace} is not #6.24(bstr) (ISO/IEC 18013-5 9.1.2.5)")
            if not isinstance(cbor2.loads(tagged.value), dict):
                raise Check(f"IssuerSignedItem {index} in {namespace} is not a CBOR map")
    return items


def preferred_tag24_head(raw):
    """True when raw starts with the shortest encodings of tag 24 and of its bstr length."""
    if raw[:2] != b"\xd8\x18" or len(raw) < 3 or raw[2] >> 5 != 2:
        return False
    _, additional, length, _ = head(raw, 2)
    if length is None:
        return False
    shortest = 0 if length < 24 else 24 if length < 0x100 else 25 if length < 0x10000 else 26 if length < 2 ** 32 else 27
    return additional == shortest if length >= 24 else additional == length


# ---- the credential -------------------------------------------------------------------------------------------------

def load(path):
    """(IssuerSigned bytes, is a Document, Document docType or None, encoding)."""
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
            doc_type = document.get("docType")
            return value_of(raw, "issuerSigned"), True, doc_type if isinstance(doc_type, str) else None, encoding
        if isinstance(document, dict) and "issuerAuth" in document and "nameSpaces" in document:
            value_of(raw, "issuerAuth")  # the same key and trailing-byte rules as a Document
            return raw, False, None, encoding
    raise Check(f"{path}: not an IssuerSigned document (raw CBOR or base64url expected)")


def cose_sign1(issuer_auth):
    """The COSE_Sign1 array; a tag (the draft-13 #6.18) is reported by issuerAuth.untagged, not here."""
    if isinstance(issuer_auth, cbor2.CBORTag):
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


def raw_validity(sign1, payload_tagged):
    """validityInfo with #6.0 kept as a tag (cbor2 would turn it into a datetime and hide the encoding), or None."""
    mso_bytes = cbor2.loads(sign1[2]).value if payload_tagged else sign1[2]
    entries, _ = map_entries(mso_bytes, 0)
    for k, v, e in entries:
        if cbor2.loads(mso_bytes[k:v]) == "validityInfo":
            block = mso_bytes[v:e]
            if head(block, 0)[0] != 5:
                return None
            dates, _ = map_entries(block, 0)
            return {cbor2.loads(block[dk:dv]): raw_value(block[dv:de]) for dk, dv, de in dates}
    return None


def raw_value(data):
    """A tstr or #6.N(tstr) decoded without cbor2's semantic conversion of the tag."""
    major, _, argument, nxt = head(data, 0)
    if major == 6:
        return cbor2.CBORTag(argument, cbor2.loads(data[nxt:]))
    return cbor2.loads(data)


# ---- the checks: each adds every problem it finds and returns what it verified ---------------------------------------

def check_namespaces(p, namespaces, items, value_digests):
    if not isinstance(namespaces, dict) or not namespaces:
        p.add("empty", "IssuerSigned.nameSpaces is empty: there is nothing to verify")
    for namespace, wire in items.items():
        if not wire:
            p.add(f"emptyNamespace:{parameter(namespace)}", f"namespace {namespace} carries no IssuerSignedItem")
        if namespace not in value_digests:
            p.add(f"noValueDigests:{parameter(namespace)}",
                  f"namespace {namespace} is in nameSpaces but has no valueDigests entry in the MSO")
        identifiers = set()
        for raw in wire:
            identifier = cbor2.loads(cbor2.loads(raw).value).get("elementIdentifier")
            if identifier in identifiers:
                p.add(f"duplicateIdentifier:{parameter(f'{namespace}/{identifier}')}",
                      f"elementIdentifier {identifier} repeats in {namespace}")
            identifiers.add(identifier)
    return f"{sum(len(w) for w in items.values())} items in {len(items)} namespace(s), identifiers unique"


def check_value_digests(p, items, value_digests, algorithm):
    hasher = DIGESTS.get(algorithm) if isinstance(algorithm, str) else None
    if hasher is None:
        p.add("badAlgorithm", f"MSO digestAlgorithm {algorithm!r} is not SHA-256, SHA-384 or SHA-512 (ISO/IEC 18013-5 9.1.2.5)")
    if not value_digests:
        p.add("empty", "MSO valueDigests is missing or empty")
    total, verified = 0, 0
    for namespace, wire in items.items():
        for raw in wire:
            total += 1
            item = cbor2.loads(cbor2.loads(raw).value)
            name = f"{namespace}/{item.get('elementIdentifier')}"
            if not preferred_tag24_head(raw):
                p.add(f"nonPreferredHead:{parameter(name)}", f"{name} has a non-preferred #6.24 head {raw[:6].hex()}: "
                                                             "a verifier that re-encodes hashes other bytes than the issuer did")
            if namespace not in value_digests:
                p.add(f"noNamespace:{parameter(namespace)}",
                      f"nameSpaces carries {namespace} but valueDigests has no such namespace")
                continue
            expected = value_digests[namespace].get(item.get("digestID"))
            if expected is None:
                p.add(f"noEntry:{parameter(name)}", f"no valueDigests entry for {name} digestID {item.get('digestID')}")
                continue
            if hasher is None:
                continue
            if hasher(raw).digest() == expected:
                verified += 1
            else:
                p.add(f"mismatch:{parameter(name)}", f"digest mismatch for {name} digestID {item.get('digestID')}: "
                                                     "the received bytes do not hash to the declared digest")
    if total == 0:
        p.add("noItems", "IssuerSigned carries no IssuerSignedItem")
    return f"{verified}/{total} items hash to valueDigests under {algorithm}, over the received bytes"


def check_digest_ids_unique(p, items):
    for namespace, wire in items.items():
        seen = set()
        for raw in wire:
            item = cbor2.loads(cbor2.loads(raw).value)
            digest_id = item.get("digestID")
            if digest_id in seen:
                p.add(f"duplicate:{parameter(f'{namespace}/{digest_id}')}",
                      f"duplicate digestID {digest_id} in namespace {namespace} ({item.get('elementIdentifier')})")
            seen.add(digest_id)
    return "digestIDs unique per namespace"


def check_pymdoccbor_digests(p, verifier, namespaces, algorithm, total, allow_partial, notes):
    if algorithm != "SHA-256":
        message = f"pymdoccbor computes SHA-256 only and the MSO declares {algorithm}"
        if allow_partial:
            notes.append(f"partial run, {message}")
            return "not run (--allow-partial)"
        p.add("partial", f"{message} (pass --allow-partial to accept a partial verification)")
        return None
    results = verifier.verify_element_hashes(namespaces)
    if not results["valid"]:
        p.add("mismatch", f"IssuerSignedItem digests: {results['failed']}")
    if results["total"] != total or results["verified"] != total:
        p.add("count", f"pymdoccbor verified {results['verified']} of {results['total']}, the wire carries {total}")
    return f"pymdoccbor verifies {results['verified']}/{total}"


def b64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def check_device_key(p, mso, holder):
    if holder is None:
        p.add("noHolder", "no expected holder key supplied (--holder)")
        return None
    if holder.get("kty") == "EC" and holder.get("crv") in EC2_CURVES:
        expected = {1: 2, -1: EC2_CURVES[holder["crv"]], -2: b64url(holder["x"]), -3: b64url(holder["y"])}
    elif holder.get("kty") == "OKP" and holder.get("crv") == "Ed25519":
        expected = {1: 1, -1: 6, -2: b64url(holder["x"])}
    else:
        p.add("unsupportedHolder", f"unsupported holder key {holder.get('kty')} {holder.get('crv')}")
        return None
    info = mso.get("deviceKeyInfo")
    key = info.get("deviceKey") if isinstance(info, dict) else None
    if not isinstance(key, dict) or not key:
        p.add("missing", "MSO deviceKeyInfo.deviceKey is missing or not a COSE_Key map")
        return None
    if -4 in key:
        p.add("privateKey", "the MSO deviceKey carries a private key (COSE_Key label -4, d)")
    for label, code in ((1, "kty"), (-1, "crv"), (-2, "x"), (-3, "y")):
        if label in expected and key.get(label) != expected[label]:
            p.add(code, f"deviceKey label {label} ({code}) does not match the holder {holder['kty']} {holder['crv']} key")
    if -3 not in expected and -3 in key:
        p.add("yOnOkp", "OKP deviceKey carries a y coordinate (label -3)")
    return f"deviceKey is the {holder.get('crv')} holder key"


def check_doc_type(p, mso, expected, is_document, document_doctype):
    doc_type = mso.get("docType")
    if not isinstance(doc_type, str):
        p.add("missing", "MSO docType is missing or not a tstr")
    elif expected is not None and doc_type != expected:
        p.add("mismatch", f"MSO docType is {doc_type}, expected {expected}")
    if is_document and document_doctype != (doc_type if isinstance(doc_type, str) else None):
        p.add("documentMismatch", f"the Document's docType {document_doctype} is not the MSO's {doc_type}")
    return f"docType {doc_type}"


def instant(p, validity, field, required):
    """The instant a validityInfo date names, tagged or not and at any precision: the order must not depend on it."""
    if field not in validity:
        if required:
            p.add(f"missing:{field}", f"validityInfo.{field} is missing")
        return None
    value = validity[field]
    text = value.value if isinstance(value, cbor2.CBORTag) else value
    if not isinstance(text, str) or not RFC3339.fullmatch(text):
        p.add(f"notDate:{field}", f"validityInfo.{field} is not an RFC 3339 date-time: {value!r}")
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        p.add(f"notDate:{field}", f"validityInfo.{field} is not a calendar instant: {text}")
        return None


def check_validity(p, validity, now):
    """Every rule, not the first that fails: an accepted signedAfterValidFrom must not hide expired."""
    if validity is None:
        p.add("missing:validityInfo", "MSO validityInfo is missing or not a map")
        return None
    signed = instant(p, validity, "signed", True)
    valid_from = instant(p, validity, "validFrom", True)
    valid_until = instant(p, validity, "validUntil", True)
    expected_update = instant(p, validity, "expectedUpdate", False)
    if signed and valid_from and signed > valid_from:
        p.add("signedAfterValidFrom", f"signed {signed.isoformat()} is after validFrom {valid_from.isoformat()} "
                                      "(ISO/IEC 18013-5 9.1.2.4)")
    if valid_from and valid_until and not valid_from < valid_until:
        p.add("validFromNotBeforeValidUntil", f"validFrom {valid_from.isoformat()} is not before validUntil "
                                              f"{valid_until.isoformat()}")
    if expected_update and valid_from and expected_update < valid_from:
        p.add("expectedUpdateBeforeValidFrom", f"expectedUpdate {expected_update.isoformat()} is before validFrom "
                                               f"{valid_from.isoformat()} (ISO/IEC 18013-5 9.1.2.4)")
    if expected_update and valid_until and not expected_update < valid_until:
        p.add("expectedUpdateNotBeforeValidUntil", f"expectedUpdate {expected_update.isoformat()} is not before "
                                                   f"validUntil {valid_until.isoformat()}")
    if valid_from and valid_from > now:
        p.add("notYetValid", f"validFrom {valid_from.isoformat()} is in the future (at {now.isoformat()})")
    if valid_until and now > valid_until:
        p.add("expired", f"validUntil {valid_until.isoformat()} has passed (at {now.isoformat()})")
    return f"signed {signed} within {valid_from}..{valid_until}"


def tdate_problems(value):
    """Every way value misses tdate (#6.0 over RFC 3339 with whole seconds and Z), as (code, message) pairs."""
    problems, text = [], value
    if isinstance(value, cbor2.CBORTag):
        if value.tag != 0:
            problems.append(("notTdate", f"is not #6.0(tstr): {value!r}"))
        text = value.value
    elif isinstance(value, str):
        problems.append(("untagged", f"is a tstr without tag 0: {value!r}"))
    if not isinstance(text, str):
        return problems or [("notTdate", f"is not #6.0(tstr): {value!r}")]
    match = RFC3339.fullmatch(text)
    if not match:
        return problems + [("notRfc3339", f"is not an RFC 3339 date-time: {text}")]
    if match.group(1):
        problems.append(("fractionalSeconds", f"carries fractional seconds: {text}"))
    if match.group(2) != "Z":
        problems.append(("notZulu", f"has the offset {match.group(2)}, not Z: {text}"))
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        problems.append(("notCalendar", f"is not a calendar instant: {text}"))
    return problems


def check_tdate_tags(p, validity):
    if validity is None:
        p.add("missing:validityInfo", "MSO validityInfo is missing or not a map")
        return None
    for field in VALIDITY_FIELDS:
        if field not in validity:
            if field != "expectedUpdate":  # optional in ISO/IEC 18013-5 9.1.2.4
                p.add(f"missing:{field}", f"validityInfo.{field} is missing")
            continue
        for code, message in tdate_problems(validity[field]):
            p.add(f"{code}:{field}", f"{field} {message} (ISO/IEC 18013-5 9.1.2.4)")
    return "validityInfo dates are #6.0 whole-second tdate"


def issued_by(certificate, issuer):
    try:
        certificate.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def valid_at(certificate, now):
    return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc


def check_chain(p, certificates, iaca, now):
    if iaca is None:
        p.add("noAnchorSupplied", "no IACA supplied (--iaca): the chain-to-anchor decision cannot be made")
        return None
    chain = list(certificates)
    if chain[-1].fingerprint(hashes.SHA256()) == iaca.fingerprint(hashes.SHA256()):
        chain.pop()
    if not chain:
        p.add("onlyAnchor", "x5chain carries only the IACA")
        return None
    for index in range(len(chain) - 1):
        if not issued_by(chain[index], chain[index + 1]):
            p.add(f"notIssuedBy:{index}", f"x5chain certificate {index} is not issued by certificate {index + 1}")
    if not issued_by(chain[-1], iaca):
        p.add("notAnchored", f"{chain[-1].subject.rfc4514_string()} is not issued by the IACA {iaca.subject.rfc4514_string()}")
    for index, certificate in enumerate(chain):
        if not valid_at(certificate, now):
            p.add(f"notValidAt:{index}", f"{certificate.subject.rfc4514_string()} is not valid at {now.isoformat()}")
    if not valid_at(iaca, now):
        p.add("notValidAt:anchor", f"the IACA {iaca.subject.rfc4514_string()} is not valid at {now.isoformat()}")
    return f"x5chain reaches {iaca.subject.rfc4514_string()}"


def check_no_self_signed(p, certificates):
    for index, certificate in enumerate(certificates):
        if issued_by(certificate, certificate):
            p.add(f"selfSigned:{index}", f"x5chain certificate {index} ({certificate.subject.rfc4514_string()}) is "
                                         "self-signed (HAIP: the IACA must not be in x5chain)")
    return "no self-signed certificate in x5chain"


def der_octets(n):
    """The DER INTEGER content octets of n: minimal two's complement, as Java's BigInteger.toByteArray."""
    return (n.bit_length() if n >= 0 else (-n - 1).bit_length()) // 8 + 1


def check_serial_numbers(p, certificates):
    for index, certificate in enumerate(certificates):
        serial = certificate.serial_number
        subject = f"x5chain certificate {index} ({certificate.subject.rfc4514_string()})"
        if serial <= 0:
            p.add("nonPositive", f"{subject} has the non-positive serial {serial}")
        if serial == 0:
            p.add("zero", f"{subject} has the serial 0")
        if der_octets(serial) > MAX_SERIAL_OCTETS:
            p.add("tooLong", f"{subject} has a serial of {der_octets(serial)} octets, more than {MAX_SERIAL_OCTETS}")
    return f"{len(certificates)} x5chain certificate serial(s) positive and at most {MAX_SERIAL_OCTETS} octets"


# ---- gaps -----------------------------------------------------------------------------------------------------------

def read_gaps(path):
    """{check: {code: reason}} from a .gaps sidecar, refused like Java's AcceptedGaps.parse refuses it."""
    gaps = {}
    if not path:
        return gaps
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{path} line {number}"
        if BARE_GAP_LINE.fullmatch(line):
            raise Unusable(f"{where} names a whole check ({line}): a gap names one problem code, "
                           "\"<check>:<code> # <reason>\", and the optional marker '?' is gone")
        match = GAP_LINE.fullmatch(line)
        if not match:
            raise Unusable(f"{where} is not \"<check>:<code> # <reason>\": {line}")
        check, code, reason = match.group(1), match.group(2), match.group(3).strip()
        if check not in PROBLEM_CODES:
            raise Unusable(f"{where}: unknown check {check}")
        if not is_problem_code(check, code):
            raise Unusable(f"{where}: unknown problem code {check}:{code}; {check} reports {PROBLEM_CODES[check]}")
        if code in gaps.get(check, {}):
            raise Unusable(f"{where}: the gap {check}:{code} is declared twice")
        gaps.setdefault(check, {})[code] = reason
    return gaps


def runs_here(check, code, not_run):
    return (check not in JAVA_ONLY_CHECKS and kind(code) not in JAVA_ONLY_KINDS.get(check, ())
            and (check, kind(code)) not in not_run)


def evaluate(results, gaps, not_run=frozenset()):
    """Prints every result against the gaps; returns (lines, failures). results: [(check, Problems, message)]."""
    lines, failures = [], 0
    ran = {name for name, _, _ in results}
    for name, problems, message in results:
        declared = gaps.get(name, {})
        if not problems.found:
            lines.append(f"  PASS {name}: {message}")
        for code, text in problems.found.items():
            if code in declared:
                lines.append(f"  GAP  {name}:{code}: {text} (accepted: {declared[code]})")
            else:
                lines.append(f"  FAIL {name}:{code}: {text}")
                failures += 1
        for code, reason in declared.items():
            if code in problems.found:
                continue
            if runs_here(name, code, not_run):
                lines.append(f"  FAIL gap no longer present, remove {name}:{code} from the .gaps file: {name} "
                             f"{'passes now' if not problems.found else 'reports ' + str(list(problems.found))} "
                             f"(declared: {reason})")
                failures += 1
            else:
                lines.append(f"  NOTE {name}:{code} is decided by the Java harness only (declared: {reason})")
    for name, declared in gaps.items():
        if name not in ran:
            for code, reason in declared.items():
                lines.append(f"  NOTE {name}:{code} is a Java-harness check, not run here (declared: {reason})")
    return lines, failures


# ---- main -----------------------------------------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor")
    parser.add_argument("issuer_signed", help="raw CBOR or base64url IssuerSigned or draft-13 Document")
    parser.add_argument("--doctype", help="docType the MSO must declare, e.g. org.iso.18013.5.1.mDL")
    parser.add_argument("--iaca", help="PEM IACA the x5chain must reach")
    parser.add_argument("--holder", help="holder public JWK the MSO deviceKey must equal (the .holder.jwk sidecar)")
    parser.add_argument("--gaps", help="the sample's .gaps sidecar: the problems it lists are accepted gaps")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept a run where pymdoccbor cannot verify the element digests (non-SHA-256 algorithm)")
    args = parser.parse_args(argv)
    gaps = read_gaps(args.gaps)

    issuer_signed_bytes, is_document, document_doctype, encoding = load(args.issuer_signed)
    try:
        document = cbor2.loads(issuer_signed_bytes)
        items = wire_items(issuer_signed_bytes)  # first: the framing rules (a namespace twice) decide what is read
        sign1 = cose_sign1(document["issuerAuth"])
        mso, payload_tagged = mso_of(sign1)
        namespaces = document["nameSpaces"]
        value_digests = mso.get("valueDigests") if isinstance(mso.get("valueDigests"), dict) else {}
        validity = raw_validity(sign1, payload_tagged)
        certificates = x5chain(sign1)
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
    now = datetime.now(timezone.utc)
    notes = []
    not_run = set() if args.doctype else {("mso.docType", "mismatch")}

    def shape(p):
        if is_document:
            p.add("documentWrapper", "the credential is a Document {docType, issuerSigned} (the draft-13 0.14.0 "
                                     "shape), not the bare IssuerSigned OpenID4VCI Appendix A.2 returns")
        return "a bare IssuerSigned"

    def untagged(p):
        if isinstance(document["issuerAuth"], cbor2.CBORTag):
            p.add("tagged", f"IssuerAuth carries CBOR tag {document['issuerAuth'].tag}; ISO/IEC 18013-5 9.1.2.4 "
                            "defines IssuerAuth = COSE_Sign1, the untagged form (RFC 9052 4.2)")
        return "IssuerAuth is an untagged COSE_Sign1"

    def signature(p):
        try:
            valid = verifier.verify_signature([iaca] if iaca is not None else None)
        except Exception as e:  # pymdoccbor raises on a malformed header or a chain that misses the root
            p.add("invalid", f"pymdoccbor: {e}")
            return None
        if not valid:
            p.add("invalid", "the IssuerAuth signature does not verify with the x5chain leaf")
        return "pymdoccbor verifies the COSE_Sign1 with the x5chain leaf"

    def payload_tag(p):
        if not payload_tagged:
            p.add("notTag24", "the MSO payload is not #6.24(bstr .cbor MobileSecurityObject) (ISO/IEC 18013-5 9.1.2.4)")
        return "tag 24"

    total = sum(len(w) for w in items.values())
    checks = [("credential.shape", shape),
              ("issuerSigned.parse", lambda p: f"{encoding}, {'Document' if is_document else 'IssuerSigned'}"),
              ("issuerAuth.untagged", untagged),
              ("issuerAuth.signature.pymdoccbor", signature),
              ("mso.payloadTag24", payload_tag),
              ("mso.nameSpaces", lambda p: check_namespaces(p, namespaces, items, value_digests)),
              ("mso.valueDigests", lambda p: check_value_digests(p, items, value_digests, mso.get("digestAlgorithm"))),
              ("mso.valueDigests.pymdoccbor", lambda p: check_pymdoccbor_digests(
                  p, verifier, namespaces, mso.get("digestAlgorithm"), total, args.allow_partial, notes)),
              ("mso.valueDigests.digestIdsUnique", lambda p: check_digest_ids_unique(p, items)),
              ("mso.deviceKey", lambda p: check_device_key(p, mso, holder)),
              ("mso.docType", lambda p: check_doc_type(p, mso, args.doctype, is_document, document_doctype)),
              ("mso.validityInfo", lambda p: check_validity(p, validity, now)),
              ("mso.validityInfo.tdateTags", lambda p: check_tdate_tags(p, validity)),
              ("x5chain.iaca", lambda p: check_chain(p, certificates, iaca, now)),
              ("x5chain.noSelfSigned", lambda p: check_no_self_signed(p, certificates)),
              ("x5chain.serialNumber", lambda p: check_serial_numbers(p, certificates))]

    results = []
    for name, run in checks:
        problems, message = Problems(name), None
        try:
            message = run(problems)
        except Exception as e:  # what a check did not expect is its error, next to what it found
            problems.add(ERROR, f"{type(e).__name__}: {e}")
        results.append((name, problems, message))

    print(f"{args.issuer_signed}: docType={mso.get('docType')} items={total} namespaces={len(items)} "
          f"digestAlgorithm={mso.get('digestAlgorithm')} encoding={encoding}")
    lines, failures = evaluate(results, gaps, not_run)
    for line in lines:
        print(line)
    for note in notes:
        print(f"  NOTE {note}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Check as e:
        print(f"FAIL issuerSigned.parse:malformed: {e}")
        sys.exit(2)
    except Unusable as e:
        print(f"FAIL {e}")
        sys.exit(2)
