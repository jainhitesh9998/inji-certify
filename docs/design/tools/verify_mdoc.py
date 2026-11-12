#!/usr/bin/env python3
"""Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor, a library Certify does not maintain.

The second non-Java opinion on every mDoc the tests write to target/mdoc-samples/ (M-01 in
docs/design/20-mdl-issuer.md, decision D9). The Java harness uses Multipaz and Authlete; this uses pymdoccbor
(pycose + cryptography), so one credential has to satisfy two independent stacks.

Input is a bare IssuerSigned as the tests write it: raw CBOR, or the same bytes base64url-encoded.

Checks, in the order the failures are reported:

  0. structure       nameSpaces is a non-empty map, no namespace is empty, and every namespace present in
                     nameSpaces has a valueDigests entry in the MSO (pymdoccbor only warns about a missing one).
  1. docType         the MSO docType equals --doctype, when given.
  2. x5chain         RFC 9360 label 33 (bstr or array); each certificate signs the next, the last is the IACA
                     when --iaca is given, and every certificate is valid now. Uses the `cryptography` x509 API.
  3. IssuerAuth      the COSE_Sign1 signature verifies with the x5chain leaf (and, with --iaca, its chain).
  4. valueDigests    every IssuerSignedItem hashes to its valueDigests entry under the declared algorithm, and the
                     number of verified items equals the number of items on the wire. pymdoccbor computes SHA-256
                     only, so any other digestAlgorithm fails unless --allow-partial asks for a partial run.

Exit status: 0 every applicable check passed, 1 a check failed, 2 the file is not an IssuerSigned.

Usage:
    verify_mdoc.py <issuer-signed.mdoc> [--doctype org.iso.18013.5.1.mDL] [--iaca iaca.pem] [--allow-partial]
"""
import argparse
import base64
import logging
import sys
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pymdoccbor.mdoc.issuersigned import IssuerSigned

X5CHAIN_LABEL = 33

# pymdoccbor logs every skipped chain validation at WARNING; a --iaca-less run is normal, an error is not
logging.getLogger("pymdoccbor").setLevel(logging.ERROR)


def load_issuer_signed(path):
    """The IssuerSigned as a dict, from raw CBOR or base64url, plus which encoding matched."""
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
        if isinstance(document, dict) and "issuerAuth" in document and "nameSpaces" in document:
            return document, encoding
    raise SystemExit(f"FAIL {path}: not an IssuerSigned document (raw CBOR or base64url expected)")


def x5chain(issuer_auth):
    """The x5chain certificates, leaf first: COSE label 33 in the unprotected header, else the protected one."""
    chain = None
    if isinstance(issuer_auth, (list, tuple)) and len(issuer_auth) > 1 and isinstance(issuer_auth[1], dict):
        chain = issuer_auth[1].get(X5CHAIN_LABEL)
    if chain is None and isinstance(issuer_auth, (list, tuple)) and len(issuer_auth) > 0:
        protected = issuer_auth[0]
        if isinstance(protected, bytes) and protected:
            header = cbor2.loads(protected)
            if isinstance(header, dict):
                chain = header.get(X5CHAIN_LABEL)
    if chain is None:
        raise ValueError("no x5chain (COSE label 33) in IssuerAuth")
    entries = chain if isinstance(chain, list) else [chain]
    if not entries:
        raise ValueError("x5chain is empty")
    return [x509.load_der_x509_certificate(der) for der in entries]


def verify_chain(certificates, iaca, failures):
    """Each certificate signs the next, the chain reaches the IACA, and everything is valid now."""
    now = datetime.now(timezone.utc)
    for index in range(len(certificates) - 1):
        try:
            certificates[index].verify_directly_issued_by(certificates[index + 1])
        except Exception as e:
            failures.append(f"x5chain: certificate {index} is not issued by certificate {index + 1}: {e}")
    last = certificates[-1]
    if last.fingerprint(hashes.SHA256()) != iaca.fingerprint(hashes.SHA256()):
        try:
            last.verify_directly_issued_by(iaca)
        except Exception as e:
            failures.append(f"x5chain: {last.subject.rfc4514_string()} does not reach the IACA "
                            f"{iaca.subject.rfc4514_string()}: {e}")
    for certificate in certificates + [iaca]:
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            failures.append(f"x5chain: {certificate.subject.rfc4514_string()} is not valid at {now.isoformat()}")


def main():
    parser = argparse.ArgumentParser(description="Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor")
    parser.add_argument("issuer_signed", help="raw CBOR or base64url IssuerSigned file")
    parser.add_argument("--doctype", help="docType the MSO must declare, e.g. org.iso.18013.5.1.mDL")
    parser.add_argument("--iaca", help="PEM IACA the x5chain must reach")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept a run where pymdoccbor cannot verify the element digests (non-SHA-256 algorithm)")
    args = parser.parse_args()

    document, encoding = load_issuer_signed(args.issuer_signed)
    issuer_signed = IssuerSigned(nameSpaces=document["nameSpaces"], issuerAuth=document["issuerAuth"])
    mso_verifier = issuer_signed.issuer_auth
    mso = mso_verifier.payload_as_dict
    failures = []
    notes = []

    # 0. structure: an empty nameSpaces, an empty namespace or a namespace the MSO has no digests for would make
    #    the digest loop below silently verify nothing, so all three are failures, not warnings.
    namespaces = document["nameSpaces"]
    value_digests = mso.get("valueDigests") or {}
    if not isinstance(namespaces, dict) or not namespaces:
        failures.append("nameSpaces is empty: nothing to verify")
        namespaces = {}
    total_items = 0
    for namespace, items in namespaces.items():
        if not isinstance(items, list) or not items:
            failures.append(f"namespace {namespace} carries no IssuerSignedItem")
            continue
        total_items += len(items)
        if namespace not in value_digests:
            failures.append(f"namespace {namespace} is in nameSpaces but has no valueDigests entry in the MSO")

    # 1. docType
    if args.doctype and mso.get("docType") != args.doctype:
        failures.append(f"docType is {mso.get('docType')}, expected {args.doctype}")

    # 2. x5chain and the trust decision
    iaca = None
    if args.iaca:
        with open(args.iaca, "rb") as pem:
            iaca = x509.load_pem_x509_certificate(pem.read())
    try:
        certificates = x5chain(document["issuerAuth"])
        if iaca is not None:
            verify_chain(certificates, iaca, failures)
    except Exception as e:
        certificates = []
        failures.append(f"x5chain: {e}")

    # 3. IssuerAuth signature with the x5chain leaf
    try:
        signature_ok = mso_verifier.verify_signature([iaca] if iaca is not None else None)
    except Exception as e:  # pymdoccbor raises on a malformed header or a chain that misses the root
        signature_ok = False
        failures.append(f"IssuerAuth signature: {e}")
    if not signature_ok:
        failures.append("IssuerAuth signature does not verify with the x5chain leaf")

    # 4. IssuerSignedItem digests against valueDigests, and their count against the wire
    digest_algorithm = mso.get("digestAlgorithm")
    hash_results = None
    if digest_algorithm != "SHA-256":
        message = (f"cannot verify the element digests: MSO declares {digest_algorithm} and pymdoccbor computes "
                   "SHA-256 only")
        if args.allow_partial:
            notes.append(f"partial run, {message}")
        else:
            failures.append(f"{message} (pass --allow-partial to accept a partial verification)")
    else:
        hash_results = mso_verifier.verify_element_hashes(namespaces)
        if not hash_results["valid"]:
            failures.append(f"IssuerSignedItem digests: {hash_results['failed']}")
        if hash_results["total"] != total_items:
            failures.append(f"element digest check covered {hash_results['total']} items but the wire carries "
                            f"{total_items}")
        if hash_results["verified"] != total_items:
            failures.append(f"element digest check verified {hash_results['verified']} of {total_items} items")

    print(f"{args.issuer_signed}: docType={mso.get('docType')} items={total_items} "
          f"namespaces={len(namespaces)} digestAlgorithm={digest_algorithm} encoding={encoding} "
          f"chain={len(certificates)}")
    if hash_results is not None:
        print(f"  digests verified: {hash_results['verified']}/{hash_results['total']}")
    if iaca is not None:
        print(f"  chain anchored at {iaca.subject.rfc4514_string()}")
    for note in notes:
        print(f"  NOTE {note}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("PASS IssuerAuth signature and element digests verified by pymdoccbor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
