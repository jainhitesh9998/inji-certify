#!/usr/bin/env python3
"""Independent verifier of a Status List Token in CWT form, the CI second opinion of the Java harness (M-11f).

The Java gate is `certify-testkit-mdoc/IndependentStatusListVerifier` (M-11b), which reads the list a sample's mSO points
at with Multipaz's `CompressedStatusList.fromCwt` and Authlete's COSE verifier. This tool is the second, non-Java
opinion the plan's section 4.9 asks for: `pycose` 1.1.0 for the COSE_Sign1 signature, `cbor2` 5.9.0 for the CBOR and
`cryptography` 50.0.2 for the X.509 chain, all pinned in `requirements-verify.txt`. It implements the M-11b table except
the checks only Multipaz can decide (its `fromCwt` maximimum validity and its own `validateCwt` order) and the
`duplicateKey` walk Authlete's pair-keeping decoder does; those are reported as skipped, never as passing.

    python3.12 -m venv .venv-verify && .venv-verify/bin/pip install -r docs/design/tools/requirements-verify.txt
    .venv-verify/bin/python docs/design/tools/verify_status_list.py --list sample.statuslist.cwt \\
        --content-type "$(cat sample.statuslist.ct)" --mdoc sample.mdoc --iaca sample.iaca.pem

Every check prints PASS, FAIL or SKIP, and the exit status is 1 when any check failed. The problem codes are the ones
`certify-testkit-mdoc/IndependentStatusListVerifier.PROBLEM_CODES` reports, held equal by `ProblemCodeRegistryTest`, so a
FAIL line and a `.gaps` line mean the same thing. The two signature codes name the first and the second signature oracle,
in the same order as the Java harness: `invalid:multipaz` is pycose here, `invalid:authlete` is the raw `cryptography`
check over COSE's Sig_structure (RFC 9052 section 4.4), which is the verification Authlete performs.

Which parts of the M-11b table are decided:

  statusList.mso             the MSO's status.status_list: present, {uri: tstr, idx: uint}, and equal to --uri/--idx
  statusList.http            Content-Type is application/statuslist+cwt (parameters ignored; TSL 8.2)
  statusList.envelope        exactly tag 18 (not 61, not 17/MAC0), a COSE_Sign1 of four elements, a payload present,
                             a protected header, an unprotected header and a payload that are maps
  statusList.typ             the protected typ (16) is application/statuslist+cwt
  statusList.x5chain         the protected x5chain (33): present, no self-signed certificate, RFC 5280 serials
  statusList.signature       pycose and the raw Sig_structure check
  statusList.chain           each certificate issued by the next, the top by the IACA (cryptography
                             verify_directly_issued_by), every certificate valid at the evaluation time
  statusList.issuanceChain   the token's x5chain is the mDL's IssuerAuth x5chain, certificate for certificate
  statusList.claims          sub = the uri, iat, exp, ttl, exp not after the signer's notAfter
  statusList.list            bits 1, the zlib lst, idx in range, the status at idx
  statusList.signerPurpose   EKU 1.3.6.1.5.5.7.3.45 and digitalSignature when the signer is not the mDL's own key

Skipped, with the reason printed: `statusList.chain` without `--iaca` (`noAnchorSupplied`), the `duplicateKey` walk,
and everything that needs the mdoc (`statusList.mso`, `statusList.issuanceChain`, `statusList.signerPurpose`) without
`--mdoc`.
"""
import argparse
import io
import sys
import zlib
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

MEDIA_TYPE = "application/statuslist+cwt"
TYP = "application/statuslist+cwt"
# TSL section 10, IANA SMI PKIX extended key purpose 45; Credo assertStatusListSignerKeyPurpose.ts:14-25
EKU_STATUS_SIGNING = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.45")
# Multipaz validateCwt's own allowance for a list's iat (validateCwt.kt): 5 s, not the smoke run's 60.
IAT_FUTURE_ALLOWANCE = 5
# COSE algorithm identifiers (RFC 9053 sections 2 and 3) and the hash each signs with.
ALGORITHMS = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512}
MEDIA_TYPE_JWT = "application/statuslist+jwt"

# BEGIN PROBLEM CODES (a JSON-compatible literal; ProblemCodeRegistryTest parses it and holds it to IndependentStatusListVerifier.PROBLEM_CODES, order included, because one .gaps sidecar serves both verifiers)
PROBLEM_CODES = {
    "statusList.mso": ["malformed"],
    "statusList.http": ["contentType"],
    "statusList.envelope": ["notTagged18", "cwtTag61", "mac0", "detachedPayload", "duplicateKey"],
    "statusList.typ": ["missing", "unprotected", "notText", "wrong"],
    "statusList.x5chain": ["missing", "unprotectedOnly", "carriesAnchor", "serialNumber"],
    "statusList.signature": ["invalid:multipaz", "invalid:authlete"],
    "statusList.chain": ["untrusted", "noAnchorSupplied"],
    "statusList.issuanceChain": ["differs"],
    "statusList.claims": ["subMismatch", "iatMissing", "iatFuture", "iatAfterExp", "expMissing", "expired",
                          "expAfterSigner", "ttlInvalid"],
    "statusList.list": ["missing", "bitsNotOne", "lstNotZlib", "idxOutOfRange", "statusMismatch:*"],
    "statusList.signerPurpose": ["ekuMissing", "kuMissing"]
}
# END PROBLEM CODES

CHECKS = list(PROBLEM_CODES)
# The checks that need the mdoc a sample carries, beside the token.
MDOC_CHECKS = ["statusList.mso", "statusList.issuanceChain", "statusList.signerPurpose"]


class Report:
    """One entry per check of the table: the problems it found, and whether it ran at all."""

    def __init__(self):
        self.problems = {check: [] for check in CHECKS}
        self.ran = set()
        self.notes = {}

    def done(self, check, note=""):
        self.ran.add(check)
        if note:
            self.notes[check] = note

    def failed(self, check, code, message=""):
        self.ran.add(check)
        self.problems[check].append((code, message))

    def failed_any(self):
        return any(self.problems[check] for check in CHECKS)

    def problem_codes(self, check):
        return [code for code, _ in self.problems[check]]


class TokenShape:
    """What a token's bytes say before any check decides anything, including the shape defects a check reports."""

    def __init__(self, body, tags, protected, unprotected, payload, signature):
        self.body = body
        self.tags = tags
        self.protected = protected
        self.unprotected = unprotected
        self.payload = payload
        self.signature = signature
        self.header = None
        self.unprotected_header = None
        self.claims = None
        self.x5chain = []

    def leaf(self):
        return x509.load_der_x509_certificate(self.x5chain[0])


def untag(value):
    """The tag stack a value carries and the value under it (RFC 8949 section 3.4): cbor2 nests CBORTag objects."""
    tags = []
    while isinstance(value, cbor2.CBORTag):
        tags.append(value.tag)
        value = value.value
    return tags, value


def tag_stack(body):
    """The tags the wire carries around the item, read from the first bytes (RFC 8949 section 3.4), and the offset of
    the item itself. `cbor2.loads` would hide the self-describe tag 55799, and a self-describe tag is a tag stack this
    check refuses, so the stack is read here rather than from a decoder's objects."""
    tags, index = [], 0
    while index < len(body):
        head = body[index]
        if head >> 5 != 6:
            break
        additional = head & 0x1f
        if additional < 24:
            tag, index = additional, index + 1
        elif additional == 24:
            tag, index = body[index + 1], index + 2
        elif additional == 25:
            tag, index = int.from_bytes(body[index + 1:index + 3], "big"), index + 3
        elif additional == 26:
            tag, index = int.from_bytes(body[index + 1:index + 5], "big"), index + 5
        elif additional == 27:
            tag, index = int.from_bytes(body[index + 1:index + 9], "big"), index + 9
        else:
            break  # an indefinite-length tag is not one CBOR allows (section 3.4)
        tags.append(tag)
    return tags, index


def read_token(body):
    """A Status List Token's parts, or the shape problems that leave nothing to check. Never raises."""
    shape = []
    if not isinstance(body, (bytes, bytearray)) or not body:
        return None, [("notTagged18", "the body is empty")]
    if body.lstrip()[:3] == b"eyJ" or body.lstrip()[:1] in (b"{", b"["):
        return None, [("notTagged18", "the body is a JWT, not a CWT: an mDoc's status list is a CWT (ISO2 12.3.6.3), "
                                      "and @owf/mdoc (Paradym, Credo) refuses a JWT with "
                                      "JwtNotSupportForStatusListError")]
    stream = io.BytesIO(bytes(body))
    try:
        token = cbor2.CBORDecoder(stream).decode()
    except Exception as e:  # noqa: BLE001 - a body that is not CBOR is one finding
        return None, [("notTagged18", f"the body is not CBOR: {e}")]
    if stream.tell() != len(body):
        return None, [("notTagged18", f"{len(body) - stream.tell()} byte(s) follow the token")]
    tags, _ = tag_stack(bytes(body))
    _, value = untag(token)
    if 61 in tags:
        shape.append(("cwtTag61", "the token carries the CWT tag 61; TSL 5.2: a Status List Token MUST NOT be tagged "
                                 "with the CWT tag"))
    if 17 in tags:
        shape.append(("mac0", "the token is a COSE_Mac0 (tag 17); an mDoc's Status List Token is signed"))
    if tags != [18] and not shape:  # 61 and 17 are their own codes, not also "not 18"
        shape.append(("notTagged18", f"the tag stack is {tags}, not exactly [18] (COSE_Sign1_Tagged, RFC 9052 4.2)"))
    if not isinstance(value, list) or len(value) != 4:
        if not any(code == "notTagged18" for code, _ in shape):
            shape.append(("notTagged18", f"the tagged value is not the four-element COSE_Sign1 array: "
                                        f"{type(value).__name__}"))
        return None, shape
    protected, unprotected, payload, signature = value
    if payload is None:
        shape.append(("detachedPayload", "the payload is detached; a Status List Token carries its claims"))
    record = TokenShape(body, tags, protected, unprotected, payload, signature)
    try:
        record.header = cbor2.loads(protected if isinstance(protected, (bytes, bytearray)) else b"")
        record.unprotected_header = cbor2.loads(unprotected) if isinstance(unprotected, (bytes, bytearray)) \
            else unprotected if unprotected is not None else {}
    except Exception as e:  # noqa: BLE001
        shape.append(("notTagged18", f"the protected or unprotected header is not CBOR: {e}"))
        return record, shape
    if not isinstance(record.header, dict) or not isinstance(record.unprotected_header, dict):
        shape.append(("notTagged18", "the protected or unprotected header is not a map"))
        return record, shape
    if payload is not None:
        try:
            record.claims = cbor2.loads(payload)
        except Exception as e:  # noqa: BLE001
            shape.append(("notTagged18", f"the payload is not CBOR: {e}"))
            return record, shape
        if not isinstance(record.claims, dict):
            shape.append(("notTagged18", "the payload is not a map"))
    return record, shape


def verify_http(content_type, report):
    media_type = (content_type or "").split(";")[0].strip().lower()
    if media_type != MEDIA_TYPE:
        report.failed("statusList.http", "contentType", f"Content-Type {content_type!r} is not {MEDIA_TYPE} (TSL 8.2)")
    else:
        report.done("statusList.http", media_type)


def verify_envelope(shape, report):
    for code, message in shape:
        report.failed("statusList.envelope", code, message)
    report.done("statusList.envelope", "the duplicateKey walk is the Java harness's (Authlete keeps every pair of a map)")


def verify_typ(token, report):
    header, unprotected = token.header, token.unprotected_header
    if 16 in header:
        typ = header[16]
        if not isinstance(typ, str):
            report.failed("statusList.typ", "notText", f"the protected typ (16) is {typ!r}, not a text string")
        elif typ != TYP:
            report.failed("statusList.typ", "wrong", f"the protected typ (16) is {typ!r}, not {TYP!r} (TSL 5.2)")
        elif 16 in unprotected:
            report.failed("statusList.typ", "unprotected", "the typ (16) is also in the unprotected header (RFC 9052 3)")
        else:
            report.done("statusList.typ", typ)
    elif 16 in unprotected:
        report.failed("statusList.typ", "unprotected", "the typ (16) is in the unprotected header; TSL 5.2 requires "
                                                       "the protected one")
    else:
        report.failed("statusList.typ", "missing", "the protected header carries no typ (16); TSL 5.2 requires "
                                                   f"{TYP!r}")


def verify_x5chain(token, report):
    header, unprotected = token.header, token.unprotected_header
    if 33 not in header:
        if 33 in unprotected:
            report.failed("statusList.x5chain", "unprotectedOnly", "the x5chain (33) is in the unprotected header; "
                                                                   "ISO2 12.3.6.3 requires the protected one")
        else:
            report.failed("statusList.x5chain", "missing", "the protected header carries no x5chain (33)")
        return
    raw = header[33] if isinstance(header[33], list) else [header[33]]
    if 33 in unprotected:
        report.failed("statusList.x5chain", "unprotectedOnly", "the x5chain (33) is in both headers (RFC 9052 3)")
    certificates = []
    for der in raw:
        if not isinstance(der, (bytes, bytearray)) or not der:
            report.failed("statusList.x5chain", "serialNumber", f"{der!r} is not a certificate")
            return
        try:
            certificates.append(x509.load_der_x509_certificate(bytes(der)))
        except Exception as e:  # noqa: BLE001
            report.failed("statusList.x5chain", "serialNumber", f"a certificate of the x5chain does not parse: {e}")
            return
    for certificate in certificates:
        if certificate.subject == certificate.issuer:
            report.failed("statusList.x5chain", "carriesAnchor",
                          f"{certificate.subject.rfc4514_string()} is self-signed: the chain is stated without its "
                          f"anchors (ISO2 12.3.6.2, HAIP 6.1)")
        serial = certificate.serial_number
        if serial <= 0 or serial.bit_length() > 160:
            report.failed("statusList.x5chain", "serialNumber",
                          f"serial {serial} is not a positive integer of at most 20 octets (RFC 5280 4.1.2.2)")
    token.x5chain = [certificate.public_bytes(serialization.Encoding.DER) for certificate in certificates]
    report.done("statusList.x5chain", f"{len(certificates)} certificate(s), leaf "
                                      f"{certificates[0].subject.rfc4514_string()}")


def sig_structure(token):
    return cbor2.dumps(["Signature1", token.protected, b"", token.payload])


def verify_signature(token, report):
    if not token.x5chain:
        report.done("statusList.signature", "not run: no readable x5chain names the key")
        return
    leaf = token.leaf()
    algorithm = token.header.get(1)
    # oracle 1: pycose, a COSE implementation that parses the wire bytes itself (so a tag stack or an unprotected
    # header this tool reads differently is pycose's to refuse)
    try:
        message = Sign1Message.decode(token.body)
        message.key = CoseKey.from_pem_public_key(
            leaf.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        if not message.verify_signature():
            report.failed("statusList.signature", "invalid:multipaz", "pycose refuses the COSE_Sign1 signature")
    except Exception as e:  # noqa: BLE001 - a COSE message pycose cannot read is a signature it cannot accept
        report.failed("statusList.signature", "invalid:multipaz", f"pycose cannot verify the token: {e}")
    # oracle 2: the raw Sig_structure check over the leaf's public key, the verification Authlete performs
    hash_algorithm = ALGORITHMS.get(algorithm)
    if hash_algorithm is None:
        report.failed("statusList.signature", "invalid:authlete",
                      f"COSE algorithm {algorithm!r} is not one this tool verifies ({sorted(ALGORITHMS)})")
        return
    signature = token.signature or b""
    if len(signature) % 2 or not signature:
        report.failed("statusList.signature", "invalid:authlete", f"the signature is {len(signature)} bytes, not r || s")
        return
    half = len(signature) // 2
    der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
    try:
        leaf.public_key().verify(der, sig_structure(token), ec.ECDSA(hash_algorithm()))
    except Exception as e:  # noqa: BLE001 - InvalidSignature, or a key the signature cannot be checked with
        report.failed("statusList.signature", "invalid:authlete", f"the signature does not verify with the leaf: {e}")
        return
    report.done("statusList.signature", f"{algorithm} over the leaf of the x5chain")


def verify_chain(token, iaca, at, report):
    """The signer's chain to the IACA the mdoc trusts (ISO2 12.3.6.2): each certificate issued by the next, the top by
    the configured IACA, every certificate valid at the evaluation time."""
    if iaca is None:
        report.failed("statusList.chain", "noAnchorSupplied",
                      "no --iaca was given, so there is no trust point to judge the signer against (D16)")
        return
    if not token.x5chain:
        report.done("statusList.chain", "not run: no readable x5chain")
        return
    certificates = [x509.load_der_x509_certificate(der) for der in token.x5chain]
    untrusted = []
    for index, certificate in enumerate(certificates):
        issuer = certificates[index + 1] if index + 1 < len(certificates) else iaca
        try:
            certificate.verify_directly_issued_by(issuer)
        except Exception as e:  # noqa: BLE001 - a name or a signature that does not match
            untrusted.append(f"{certificate.subject.rfc4514_string()} is not issued by "
                             f"{issuer.subject.rfc4514_string()}: {e}")
    for certificate in certificates + [iaca]:
        if not (certificate.not_valid_before_utc <= at <= certificate.not_valid_after_utc):
            # cryptography normalises the deprecated naive accessors to the new UTC ones; the checks read the new ones
            untrusted.append(f"{certificate.subject.rfc4514_string()} is not valid at {at.isoformat()} "
                             f"({certificate.not_valid_before_utc.isoformat()} to "
                             f"{certificate.not_valid_after_utc.isoformat()})")
    if untrusted:
        for message in untrusted:
            report.failed("statusList.chain", "untrusted", message)
    else:
        report.done("statusList.chain", f"issued by {iaca.subject.rfc4514_string()}")


def verify_issuance_chain(token, issuer_auth_chain, report):
    if issuer_auth_chain is None:
        report.done("statusList.issuanceChain", "not run: no --mdoc gives the IssuerAuth chain")
        return
    if not token.x5chain:
        report.done("statusList.issuanceChain", "not run: no readable x5chain")
        return
    expected = [certificate.public_bytes(serialization.Encoding.DER) for certificate in issuer_auth_chain]
    if token.x5chain != expected:
        report.failed("statusList.issuanceChain", "differs",
                      "the list's x5chain is not the mDL's IssuerAuth x5chain certificate for certificate (Credo's "
                      f"receipt rule, mdocUtil.ts:76-115): list {describe(token.x5chain)}, "
                      f"mDL {describe(expected)}")
    else:
        report.done("statusList.issuanceChain", "equal to the IssuerAuth x5chain")


def verify_claims(token, uri, at, report):
    claims = token.claims or {}
    sub, exp, iat, ttl = claims.get(2), claims.get(4), claims.get(6), claims.get(65534)
    if not isinstance(sub, str) or not sub:
        report.failed("statusList.claims", "subMismatch", f"sub (2) {sub!r} is not a non-empty text string")
    elif uri is not None and sub != uri:
        report.failed("statusList.claims", "subMismatch",
                      f"sub (2) {sub!r} is not the uri the credential names {uri!r} (TSL 8.3 step 4a)")
    if not isinstance(iat, int) or isinstance(iat, bool):
        report.failed("statusList.claims", "iatMissing", f"iat (6) {iat!r} is missing or not an integer")
    else:
        if iat > at.timestamp() + IAT_FUTURE_ALLOWANCE:
            report.failed("statusList.claims", "iatFuture",
                          f"iat (6) {iat} is more than {IAT_FUTURE_ALLOWANCE} s ahead of {int(at.timestamp())} "
                          f"(Multipaz validateCwt's clock allowance)")
        if isinstance(exp, int) and not isinstance(exp, bool) and iat > exp:
            report.failed("statusList.claims", "iatAfterExp", f"iat (6) {iat} is after exp (4) {exp}")
    if not isinstance(exp, int) or isinstance(exp, bool):
        report.failed("statusList.claims", "expMissing",
                      f"exp (4) {exp!r} is missing; ISO2 12.3.6.3 makes an mDoc's list carry it")
    elif exp <= at.timestamp():
        report.failed("statusList.claims", "expired",
                      f"exp (4) {exp} is not after the evaluation time {int(at.timestamp())} "
                      f"(RFC 8392 3.1.4 through RFC 7519 4.1.4: the time MUST be before exp)")
    if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
        report.failed("statusList.claims", "ttlInvalid", f"ttl (65534) {ttl!r} is not a positive integer")
    if token.x5chain:
        not_after = token.leaf().not_valid_after_utc
        if isinstance(exp, int) and not isinstance(exp, bool) and exp > not_after.timestamp():
            report.failed("statusList.claims", "expAfterSigner",
                          f"exp (4) {exp} is after the signer's notAfter {int(not_after.timestamp())}: no verifier's "
                          f"path reaches it (ISO2 12.3.6.3)")
    if not report.problems["statusList.claims"]:
        report.done("statusList.claims", f"sub {sub}, iat {iat}, exp {exp}, ttl {ttl}")


def verify_list(token, uri, idx, expected_status, report):
    claims = token.claims or {}
    status_list = claims.get(65533)
    if not isinstance(status_list, dict):
        report.failed("statusList.list", "missing",
                      f"claim 65533 (status_list) {status_list!r} is missing or not a map (TSL 4.3)")
        return
    bits = status_list.get("bits")
    if bits != 1:
        report.failed("statusList.list", "bitsNotOne", f"bits {bits!r} is not 1 (ISO2 12.3.6.5)")
        return
    lst = status_list.get("lst")
    if not isinstance(lst, (bytes, bytearray)) or not lst:
        report.failed("statusList.list", "lstNotZlib", f"lst {lst!r} is not a bstr")
        return
    try:
        raw = zlib.decompress(bytes(lst))
    except Exception as e:  # noqa: BLE001 - zlib.error, and raw DEFLATE without the wrapper
        report.failed("statusList.list", "lstNotZlib", f"lst does not inflate as a zlib stream (RFC 1950): {e}")
        return
    capacity = len(raw) * 8 // bits
    if not 0 <= idx < capacity:
        report.failed("statusList.list", "idxOutOfRange",
                      f"idx {idx} is outside the {capacity} statuses the list carries (TSL 8.3 step 6)")
        return
    status = (raw[idx // 8] >> (idx % 8)) & 1  # bits=1, least significant bit first (TSL 4.1)
    if status != expected_status:
        report.failed("statusList.list", f"statusMismatch:{status}",
                      f"the status at {idx} is {status}, expected {expected_status}")
        return
    report.done("statusList.list", f"{capacity} statuses, status {status} at {idx}")


def verify_signer_purpose(token, issuer_auth_chain, report):
    """Credo's `assertStatusListSignerKeyPurpose` (1.4-25): a list key that is not the credential's own key needs the
    status-signing EKU and digitalSignature; a list signed by the mDL's Document Signer needs neither."""
    if issuer_auth_chain is None:
        report.done("statusList.signerPurpose", "not run: no --mdoc to compare the signer with")
        return
    if not token.x5chain or not issuer_auth_chain:
        report.done("statusList.signerPurpose", "not run: no readable x5chain")
        return
    leaf = token.leaf()
    credential_leaf = issuer_auth_chain[0]
    if leaf.public_key().public_numbers() == credential_leaf.public_key().public_numbers():
        report.done("statusList.signerPurpose", "the list is signed by the mDL's own Document Signer")
        return
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        report.failed("statusList.signerPurpose", "kuMissing", "the signer has no key usage extension")
    else:
        if not usage.digital_signature:
            report.failed("statusList.signerPurpose", "kuMissing", "the signer's key usage lacks digitalSignature")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        report.failed("statusList.signerPurpose", "ekuMissing",
                      "the signer has no extended key usage; TSL 10 delegates list signing with "
                      f"{EKU_STATUS_SIGNING.dotted_string}")
    else:
        if EKU_STATUS_SIGNING not in eku:
            report.failed("statusList.signerPurpose", "ekuMissing",
                          f"the signer's extended key usage does not carry {EKU_STATUS_SIGNING.dotted_string}")
    if not report.problems["statusList.signerPurpose"]:
        report.done("statusList.signerPurpose", "the signer is delegated the status-signing purpose")


# ---- the mdoc a sample carries (IssuerSigned, or a draft-13 Document) ----------------------------------------------

def mdoc_issuer_signed(blob):
    value = cbor2.loads(blob)
    if isinstance(value, dict) and "issuerSigned" in value:
        value = value["issuerSigned"]  # the draft-13 Document wrapper
    if not isinstance(value, dict) or "issuerAuth" not in value:
        raise ValueError("the credential is neither an IssuerSigned nor a Document carrying one")
    return value


def mdoc_issuer_auth(issuer_signed):
    """(x5chain as certificates, MSO map) of an IssuerSigned, read without verifying it: M-01 owns that."""
    tags, auth = untag(issuer_signed["issuerAuth"])
    if not isinstance(auth, list) or len(auth) != 4:
        raise ValueError(f"issuerAuth is not a COSE_Sign1 array (tag stack {tags})")
    protected, unprotected, payload, _ = auth
    header = cbor2.loads(protected)
    unprotected_header = cbor2.loads(unprotected) if isinstance(unprotected, (bytes, bytearray)) \
        else unprotected if unprotected is not None else {}
    raw = header.get(33, unprotected_header.get(33))
    if raw is None:
        raise ValueError("issuerAuth carries no x5chain (33)")
    chain = raw if isinstance(raw, list) else [raw]
    certificates = [x509.load_der_x509_certificate(bytes(cert)) for cert in chain]
    tags, payload = untag(cbor2.loads(payload))
    if isinstance(payload, (bytes, bytearray)):
        payload = cbor2.loads(bytes(payload))  # tag 24: the embedded CBOR of the MSO
    if not isinstance(payload, dict):
        raise ValueError("the IssuerAuth payload is not the MSO map")
    return certificates, payload


def mso_status_reference(mso):
    """(reference, problem): ISO2 12.3.6's `Status = {? status_list, ? identifier_list, * tstr => RFU}`."""
    status = mso.get("status")
    if status is None:
        return None, None
    if not isinstance(status, dict):
        return None, f"the MSO's status is not a map: {status!r}"
    if "status_list" not in status:
        return None, None  # an IdentifierList only, or no status at all: valid and absent for a Token Status List
    entry = status["status_list"]
    if not isinstance(entry, dict):
        return None, f"status.status_list is not a map: {entry!r}"
    uri, idx = entry.get("uri"), entry.get("idx")
    if not isinstance(uri, str) or not uri.strip():
        return None, f"status.status_list.uri {uri!r} is not a non-blank text string"
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        return None, f"status.status_list.idx {idx!r} is not an unsigned integer"
    return {"uri": uri, "idx": idx}, None


def read_mdoc(blob, uri, idx, report):
    """(IssuerAuth chain, status reference) of a sample, or (None, None) when the MSO has none; the mso check is filled
    here so the token checks can use what it read."""
    try:
        chain, mso = mdoc_issuer_auth(mdoc_issuer_signed(blob))
    except Exception as e:  # noqa: BLE001 - an unreadable credential is M-01's finding, not a status-list one
        report.done("statusList.mso", f"not run: the credential's IssuerAuth or MSO cannot be read ({e})")
        return None, None
    reference, problem = mso_status_reference(mso)
    if problem:
        report.failed("statusList.mso", "malformed", problem)
        return chain, None
    if reference is None:
        report.done("statusList.mso", "the MSO carries no status.status_list")
        return chain, None
    if uri is not None and reference["uri"] != uri:
        report.failed("statusList.mso", "malformed",
                      f"the MSO names {reference['uri']!r}, but --uri is {uri!r}")
    if idx is not None and reference["idx"] != idx:
        report.failed("statusList.mso", "malformed", f"the MSO names idx {reference['idx']}, but --idx is {idx}")
    if not report.problems["statusList.mso"]:
        report.done("statusList.mso", f"{reference['uri']} #{reference['idx']}")
    return chain, reference


def _bytes(source):
    """The bytes of a path or of an open file (the command line hands argparse file objects)."""
    return source.read_bytes() if hasattr(source, "read_bytes") else source.read()


def describe(chain):
    described = []
    for der in chain:
        try:
            described.append(x509.load_der_x509_certificate(der).subject.rfc4514_string())
        except Exception:  # noqa: BLE001
            described.append(f"<{len(der)} bytes that do not parse>")
    return "[" + ", ".join(described) + "]"


def verify(body, content_type, uri=None, idx=None, iaca_pem=None, mdoc=None, expected_status=0, at=None):
    """Every check of the table over one list (and, with `mdoc`, the credential that points at it). Returns the Report.

    `at` is the evaluation time, `datetime.now(timezone.utc)` when absent: the Java harness evaluates at its own clock,
    so a sample recorded earlier may be past its `exp` on a later run (TSL 8.2: exp and ttl are authoritative)."""
    at = at or datetime.now(timezone.utc)
    report = Report()
    iaca = x509.load_pem_x509_certificate(_bytes(iaca_pem)) if iaca_pem is not None else None
    issuer_auth_chain = None
    if mdoc is not None:
        issuer_auth_chain, reference = read_mdoc(_bytes(mdoc), uri, idx, report)
        if reference is not None:
            uri = reference["uri"] if uri is None else uri
            idx = reference["idx"] if idx is None else idx
    else:
        for check in MDOC_CHECKS:
            report.done(check, "not run: no --mdoc was given")
    if idx is None:
        idx = 0
    verify_http(content_type, report)
    token, shape = read_token(body)
    if token is None:
        for code, message in shape:
            report.failed("statusList.envelope", code, message)
        for check in CHECKS:
            if check not in report.ran:
                report.done(check, "not run: the token does not parse")
        return report
    verify_envelope(shape, report)
    if shape:
        # a body that is not a COSE_Sign1 of a Status List Token leaves nothing below it to check (the Java harness
        # reports the other token checks notRun for the same reason)
        for check in CHECKS:
            if check not in report.ran:
                report.done(check, "not run: the envelope is defective")
        return report
    verify_typ(token, report)
    verify_x5chain(token, report)
    verify_signature(token, report)
    verify_chain(token, iaca, at, report)
    verify_issuance_chain(token, issuer_auth_chain, report)
    verify_claims(token, uri, at, report)
    verify_list(token, uri, idx, expected_status, report)
    verify_signer_purpose(token, issuer_auth_chain, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="verify_status_list.py",
                                     description="Verify a Status List Token in CWT form (draft-ietf-oauth-status-list-21 "
                                                 "section 5.2, ISO/IEC 18013-5 second edition 12.3.6.3) against the "
                                                 "credential that points at it.")
    parser.add_argument("--list", type=argparse.FileType("rb"), required=True,
                        help="the list body exactly as the endpoint served it (a sample's .statuslist.cwt)")
    parser.add_argument("--content-type", help="the Content-Type it was served with (a sample's .statuslist.ct)")
    parser.add_argument("--uri", help="the status_list.uri the credential carries (checked against --mdoc when both)")
    parser.add_argument("--idx", type=int, help="the status_list.idx the credential carries")
    parser.add_argument("--iaca", type=argparse.FileType("rb"),
                        help="the IACA the mdoc trusts (PEM): without it statusList.chain is noAnchorSupplied")
    parser.add_argument("--mdoc", type=argparse.FileType("rb"),
                        help="the credential the list belongs to (a sample's .mdoc): gives the IssuerAuth x5chain and "
                             "the MSO's status.status_list")
    parser.add_argument("--expect-status", type=int, choices=(0, 1), default=0,
                        help="the status the list must report at idx: 0 VALID (default) or 1 INVALID for a revoked "
                             "sample (ISO2 12.3.6.1)")
    parser.add_argument("--at", help="the evaluation time as ISO 8601 or epoch seconds (default: now)")
    args = parser.parse_args(argv)
    at = None
    if args.at:
        try:
            at = datetime.fromtimestamp(float(args.at), timezone.utc)
        except ValueError:
            at = datetime.fromisoformat(args.at.replace("Z", "+00:00"))
            at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
    report = verify(args.list.read(), args.content_type, args.uri, args.idx, args.iaca, args.mdoc,
                    args.expect_status, at)
    failed = 0
    for check in CHECKS:
        problems = report.problems[check]
        if problems:
            failed += len(problems)
            for code, message in problems:
                print(f"FAIL {check}:{code}: {message}")
        elif check in report.ran:
            print(f"PASS {check}" + (f": {report.notes[check]}" if report.notes.get(check) else ""))
        else:
            print(f"SKIP {check}")
    print(f"{len(CHECKS)} checks, {failed} problem(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
