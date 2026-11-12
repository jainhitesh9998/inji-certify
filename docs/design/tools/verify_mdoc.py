#!/usr/bin/env python3
"""Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor, a library Certify does not maintain.

CI second opinion to the Java harness (certify-testkit-mdoc, M-01 in docs/design/20-mdl-issuer.md): the
testkit uses Multipaz and Authlete, this uses pymdoccbor (pycose + cryptography), so one credential must
satisfy two independent stacks. Input is a bare IssuerSigned as the tests write under target/mdoc-samples/,
raw CBOR or base64url. Checks the IssuerAuth COSE_Sign1 signature against the x5chain leaf and every
IssuerSignedItem digest against the MSO valueDigests (SHA-256 only; other algorithms are reported and
skipped). Exit 0 means every applicable check passed.

Usage: verify_mdoc.py <file> [--iaca iaca.pem]
"""
import argparse
import base64
import sys

import cbor2
from cryptography import x509
from pymdoccbor.mdoc.verifier import IssuerSigned


def load_issuer_signed(path):
    data = open(path, "rb").read()
    candidates = [("cbor", data)]
    text = b"".join(data.split())
    try:
        candidates.append(("base64url", base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))))
    except Exception:
        pass
    for encoding, raw in candidates:
        try:
            document = cbor2.loads(raw)
        except Exception:
            continue
        if isinstance(document, dict) and "issuerAuth" in document and "nameSpaces" in document:
            return document, encoding
    raise SystemExit(f"FAIL {path}: not an IssuerSigned document (raw CBOR or base64url expected)")


def main():
    parser = argparse.ArgumentParser(description="Verify an ISO/IEC 18013-5 IssuerSigned with pymdoccbor")
    parser.add_argument("issuer_signed", help="raw CBOR or base64url IssuerSigned file")
    parser.add_argument("--iaca", help="PEM IACA certificate the x5chain must reach")
    args = parser.parse_args()

    document, encoding = load_issuer_signed(args.issuer_signed)
    if not isinstance(document, dict) or "issuerAuth" not in document or "nameSpaces" not in document:
        print(f"FAIL {args.issuer_signed}: not an IssuerSigned document ({encoding})")
        return 2

    issuer_signed = IssuerSigned(nameSpaces=document["nameSpaces"], issuerAuth=document["issuerAuth"])
    mso_verifier = issuer_signed.issuer_auth
    mso = mso_verifier.payload_as_dict

    trusted_roots = None
    if args.iaca:
        with open(args.iaca, "rb") as pem:
            trusted_roots = [x509.load_pem_x509_certificate(pem.read())]

    failures = []

    # 1. COSE_Sign1 IssuerAuth signature with the x5chain leaf (and, with --iaca, the chain to that anchor).
    try:
        signature_ok = mso_verifier.verify_signature(trusted_roots)
    except Exception as e:  # pymdoccbor raises on a malformed header or a chain that misses the root
        signature_ok = False
        failures.append(f"IssuerAuth signature: {e}")
    if not signature_ok:
        failures.append("IssuerAuth signature does not verify with the x5chain leaf")

    # 2. IssuerSignedItem digests against valueDigests, under the MSO's declared algorithm.
    digest_algorithm = mso.get("digestAlgorithm")
    digests = mso.get("valueDigests", {})
    items = sum(len(namespace) for namespace in document["nameSpaces"].values())
    hash_results = None
    if digest_algorithm != "SHA-256":
        print(f"WARN digest check skipped: pymdoccbor only computes SHA-256, MSO declares {digest_algorithm}")
    else:
        hash_results = mso_verifier.verify_element_hashes(issuer_signed.namespaces)
        if not hash_results["valid"]:
            failures.append(f"IssuerSignedItem digests: {hash_results['failed']}")

    print(f"{args.issuer_signed}: docType={mso.get('docType')} items={items} "
          f"namespaces={len(digests)} digestAlgorithm={digest_algorithm} encoding={encoding}")
    if hash_results is not None:
        print(f"  digests verified: {hash_results['verified']}/{hash_results['total']}")
    if trusted_roots:
        print(f"  chain anchored at {trusted_roots[0].subject.rfc4514_string()}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("PASS IssuerAuth signature and element digests verified by pymdoccbor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
