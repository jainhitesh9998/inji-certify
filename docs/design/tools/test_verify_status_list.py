#!/usr/bin/env python3
"""Tests for verify_status_list.py (M-11f): one mutation per problem code of the M-11b table, mirroring
certify-testkit-mdoc/IndependentStatusListVerifierTest.

The fixtures are built here with `cryptography` and `cbor2` alone — an IACA, the Document Signer it issued, and a list
signed by that Document Signer as ISO/IEC 18013-5 second edition 12.3.6.3 and draft-ietf-oauth-status-list-21 section 5.2
describe — so a token that passes is one this tool's own reading accepts, and every mutation changes exactly one thing.

    .venv-verify/bin/python -m unittest docs/design/tools/test_verify_status_list.py
"""
import cbor2
import contextlib
import io
import tempfile
import unittest
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

import verify_status_list as v

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
URI = "https://credentials.example/v1/certify/credentials/token-status-list/1"
IDX = 3
EKU_STATUS_SIGNING = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.45")
EKU_MDL_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(common_name, country="IN"):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def certificate(subject_key, subject, issuer=None, issuer_key=None, ca=False, eku=None, digital_signature=True,
                serial=None, not_before=None, not_after=None):
    """A certificate; `ca` adds basicConstraints CA and keyCertSign, `eku` the extended key usage."""
    issuer = issuer or subject
    issuer_key = issuer_key or subject_key
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer)
               .public_key(subject_key.public_key())
               .serial_number(serial if serial is not None else x509.random_serial_number())
               .not_valid_before(not_before or NOW - timedelta(days=1))
               .not_valid_after(not_after or NOW + timedelta(days=365)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                                      key_encipherment=False, data_encipherment=False,
                                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                      encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                                                      key_encipherment=False, data_encipherment=False,
                                                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                                                      encipher_only=False, decipher_only=False), critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


class Fixture:
    """An IACA, the mDL's Document Signer, and a list signed by it."""

    def __init__(self):
        self.iaca_key, self.dsc_key = key(), key()
        self.iaca = certificate(self.iaca_key, name("Lorem Ipsum Demo IACA"), ca=True)
        self.dsc = certificate(self.dsc_key, name("Lorem Ipsum Demo Document Signer"), issuer=self.iaca.subject,
                               issuer_key=self.iaca_key, eku=[EKU_MDL_DS])

    def token(self, *, chain=None, claims=None, protected=None, unprotected={}, tags=(18,), signature=None,
              body=None, key_for_signature=None):
        """A Status List Token over the fixture's DSC: the default is the token that must pass every check."""
        claims = claims if claims is not None else self.claims()
        protected = protected if protected is not None else {1: -7, 16: v.TYP, 33: der(self.dsc)}
        protected = cbor2.dumps(protected, canonical=True)
        # the unprotected header is a map on the wire (RFC 9052 4.2), never a bstr
        payload = cbor2.dumps(claims, canonical=True)
        signature = signature if signature is not None else self.sign(protected, payload,
                                                                      key_for_signature or self.dsc_key)
        value = [protected, unprotected, payload, signature]
        token = cbor2.dumps(value)
        for tag in reversed(tags):
            token = cbor2.dumps(cbor2.CBORTag(tag, cbor2.loads(token)))
        return body if body is not None else token

    def claims(self, override=None):
        """The claims of a fresh list, with the given ones replaced (a None value removes a claim)."""
        claims = {2: URI, 4: int((NOW + timedelta(hours=2)).timestamp()), 6: int(NOW.timestamp()),
                  65533: {"lst": zlib.compress(bytes(16)), "bits": 1},
                  65534: 3600}
        claims.update(override or {})
        return {key: value for key, value in claims.items() if value is not None}

    @staticmethod
    def sign(protected, payload, signing_key):
        der_signature = signing_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def mdoc(self, chain=None, status="default"):
        """An IssuerSigned whose IssuerAuth carries the chain and whose MSO carries the status reference. Its own
        signature is not verified here, which is M-01's check."""
        mso = {"docType": "org.iso.18013.5.1.mDL", "validityInfo": {}}
        if status == "default":
            mso["status"] = {"status_list": {"uri": URI, "idx": IDX}}
        elif status is not None:
            mso["status"] = status
        chain = chain if chain is not None else [self.dsc]
        protected = cbor2.dumps({1: -7}, canonical=True)
        unprotected = cbor2.dumps({33: [der(cert) for cert in chain]})
        payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
        issuer_auth = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, b"\x00" * 64]))
        return cbor2.dumps({"nameSpaces": {}, "issuerAuth": cbor2.loads(issuer_auth)})


class Case(unittest.TestCase):

    def setUp(self):
        self.f = Fixture()
        self.directory = Path(tempfile.mkdtemp(prefix="status-list-"))
        self.iaca_path = self.directory / "iaca.pem"
        self.iaca_path.write_bytes(self.f.iaca.public_bytes(serialization.Encoding.PEM))
        self.mdoc_path = self.directory / "sample.mdoc"
        self.mdoc_path.write_bytes(self.f.mdoc())

    def report(self, body, *, content_type=v.MEDIA_TYPE, uri=URI, idx=IDX, iaca=True, mdoc=True, at=NOW,
               expected_status=0):
        return v.verify(body, content_type, uri, idx, self.iaca_path if iaca else None,
                        self.mdoc_path if mdoc else None, expected_status, at)

    def assertProblems(self, report, expected, message=""):
        actual = {check: report.problem_codes(check) for check in v.CHECKS if report.problems[check]}
        self.assertEqual(expected, actual, message or actual)

    # ---- the token that passes ----------------------------------------------------------------------------------

    def test_the_fixtures_token_passes_every_check(self):
        report = self.report(self.f.token())
        self.assertFalse(report.failed_any(), {c: report.problems[c] for c in v.CHECKS if report.problems[c]})
        self.assertEqual(set(v.CHECKS), report.ran, "every check of the table ran")

    def test_a_revoked_sample_passes_with_the_status_it_declares(self):
        body = self.f.token(claims=self.f.claims({65533: {"lst": zlib.compress(bytes([1 << IDX])), "bits": 1}}))
        report = self.report(body, expected_status=1)
        self.assertFalse(report.failed_any(), {c: report.problems[c] for c in v.CHECKS if report.problems[c]})

    # ---- statusList.http, statusList.envelope -------------------------------------------------------------------

    def test_a_jwt_content_type_or_body_is_refused(self):
        report = self.report(self.f.token(), content_type="application/statuslist+jwt")
        self.assertProblems(report, {"statusList.http": ["contentType"]})
        report = self.report(b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")
        self.assertProblems(report, {"statusList.envelope": ["notTagged18"]}, "a JWT body is not CBOR")

    def test_an_untagged_cose_sign1_is_refused(self):
        report = self.report(self.f.token(tags=()))
        self.assertProblems(report, {"statusList.envelope": ["notTagged18"]})

    def test_tag_61_and_tag_17_are_refused(self):
        report = self.report(self.f.token(tags=(61, 18)))
        self.assertProblems(report, {"statusList.envelope": ["cwtTag61"]})
        report = self.report(self.f.token(tags=(17,)))
        self.assertProblems(report, {"statusList.envelope": ["mac0"]}, "tag 17 has its own code")

    def test_the_self_describe_tag_and_a_doubled_tag_are_refused(self):
        for tags in ((55799, 18), (18, 18)):
            self.assertProblems(self.report(self.f.token(tags=tags)), {"statusList.envelope": ["notTagged18"]}, tags)

    def test_a_detached_payload_is_refused(self):
        body = self.f.token()
        token = cbor2.loads(body)
        value = list(token.value)
        value[2] = None
        self.assertProblems(self.report(cbor2.dumps(cbor2.CBORTag(18, value))),
                            {"statusList.envelope": ["detachedPayload"]})

    # ---- statusList.typ, statusList.x5chain ---------------------------------------------------------------------

    def test_the_typ_must_be_the_protected_status_list_one(self):
        cases = {
            "missing": ({1: -7, 33: der(self.f.dsc)}, None),
            "notText": ({1: -7, 16: 16, 33: der(self.f.dsc)}, None),
            "wrong": ({1: -7, 16: "statuslist+cwt", 33: der(self.f.dsc)}, None),
        }
        for code, (protected, _) in cases.items():
            self.assertProblems(self.report(self.f.token(protected=protected)),
                                {"statusList.typ": [code]}, code)
        # an unprotected typ is not the protected one (TSL 5.2)
        self.assertProblems(self.report(self.f.token(protected={1: -7, 16: v.TYP, 33: der(self.f.dsc)},
                                                     unprotected={16: v.TYP})),
                            {"statusList.typ": ["unprotected"]})
        self.assertProblems(self.report(self.f.token(protected={1: -7, 33: der(self.f.dsc)}, unprotected={16: v.TYP})),
                            {"statusList.typ": ["unprotected"]})

    def test_the_x5chain_must_be_protected_and_carry_no_anchor(self):
        self.assertProblems(self.report(self.f.token(protected={1: -7, 16: v.TYP})),
                            {"statusList.x5chain": ["missing"]})
        self.assertProblems(self.report(self.f.token(protected={1: -7, 16: v.TYP, 33: der(self.f.dsc)},
                                                     unprotected={33: der(self.f.dsc)})),
                            {"statusList.x5chain": ["unprotectedOnly"]})
        # a token signed by a self-signed certificate carries its own trust anchor
        self_signed_key = key()
        self_signed = certificate(self_signed_key, name("Self Signed"))
        self.assertIn("carriesAnchor",
                      self.report(self.f.token(protected={1: -7, 16: v.TYP, 33: der(self_signed)},
                                               key_for_signature=self_signed_key)).problem_codes("statusList.x5chain"))
        # RFC 5280 4.1.2.2 (a serial of at most 20 octets) has no fixture here: `cryptography` refuses to build a
        # certificate whose serial breaks it (positive and at most 159 bits), so the code is decided by the check and
        # only the Java harness, whose fixtures sign raw DER, has a negative one.

    # ---- statusList.signature, statusList.chain -----------------------------------------------------------------

    def test_a_bad_signature_names_both_oracles(self):
        good = self.f.sign(cbor2.dumps({1: -7, 16: v.TYP, 33: der(self.f.dsc)}, canonical=True),
                           cbor2.dumps(self.f.claims(), canonical=True), self.f.dsc_key)
        bad = bytes([good[0] ^ 0xFF]) + good[1:]
        self.assertProblems(self.report(self.f.token(signature=bad)),
                            {"statusList.signature": ["invalid:multipaz", "invalid:authlete"]})

    def test_an_unsupported_algorithm_is_refused_by_the_sig_structure_oracle(self):
        protected = {1: -8, 16: v.TYP, 33: der(self.f.dsc)}
        self.assertProblems(self.report(self.f.token(protected=protected)),
                            {"statusList.signature": ["invalid:multipaz", "invalid:authlete"]})

    def test_the_chain_must_reach_the_supplied_iaca(self):
        other_key = key()
        other = certificate(other_key, name("Another IACA"), ca=True)
        other_path = self.directory / "other-iaca.pem"
        other_path.write_bytes(other.public_bytes(serialization.Encoding.PEM))
        report = v.verify(self.f.token(), v.MEDIA_TYPE, URI, IDX, other_path, self.mdoc_path, 0, NOW)
        self.assertProblems(report, {"statusList.chain": ["untrusted"]})

    def test_without_an_iaca_the_chain_is_a_fail(self):
        # a trust point was not supplied: the tool decides nothing about the signer and says so with the Java harness's
        # code, which is a FAIL and not a SKIP (the check had everything a FAIL needs, the run just did not supply it)
        report = self.report(self.f.token(), iaca=False)
        self.assertProblems(report, {"statusList.chain": ["noAnchorSupplied"]})
        self.assertFalse(report.unchecked.get("statusList.chain"), "it was decided (and refused), not left unchecked")

    def test_a_certificate_outside_its_validity_fails_the_chain(self):
        expired_key = key()
        expired = certificate(expired_key, name("Expired Document Signer"), issuer=self.f.iaca.subject,
                              issuer_key=self.f.iaca_key, eku=[EKU_MDL_DS],
                              not_before=NOW - timedelta(days=30), not_after=NOW - timedelta(days=1))
        body = self.f.token(protected={1: -7, 16: v.TYP, 33: der(expired)}, key_for_signature=expired_key,
                            claims=self.f.claims({4: int((NOW - timedelta(days=2)).timestamp())}))
        # the chain is what refuses it: the signer's notAfter is before the evaluation time
        report = self.report(body)
        self.assertIn("untrusted", report.problem_codes("statusList.chain"))

    # ---- statusList.issuanceChain, statusList.mso, statusList.signerPurpose -------------------------------------

    def test_a_list_signed_by_another_key_than_the_mdls_is_refused(self):
        other_key = key()
        other = certificate(other_key, name("Another Document Signer"), issuer=self.f.iaca.subject,
                            issuer_key=self.f.iaca_key, eku=[EKU_MDL_DS])
        body = self.f.token(protected={1: -7, 16: v.TYP, 33: der(other)}, key_for_signature=other_key)
        report = self.report(body)
        self.assertEqual(["differs"], report.problem_codes("statusList.issuanceChain"))
        # Credo's rule is the reason: the list's validated chain is not the mDL's issuance chain
        self.assertIn("Credo", report.problems["statusList.issuanceChain"][0][1])

    def test_a_malformed_or_missing_status_reference_is_reported(self):
        for status, expected in (({"status_list": {"idx": "3", "uri": URI}}, ["malformed"]),
                                 ({"status_list": {"uri": URI}}, ["malformed"]),
                                 ({"status_list": {"idx": 3, "uri": ""}}, ["malformed"]),
                                 ({"status_list": "nope"}, ["malformed"]), ("broken", ["malformed"]),
                                 (None, []), ({"identifier_list": {"id": b"x", "uri": URI}}, [])):
            self.mdoc_path.write_bytes(self.f.mdoc(status=status))
            report = self.report(self.f.token())
            self.assertEqual(expected, report.problem_codes("statusList.mso"), status)

    def test_the_mso_the_uri_and_the_idx_must_agree(self):
        self.mdoc_path.write_bytes(self.f.mdoc(status={"status_list": {"uri": URI + "/2", "idx": IDX}}))
        self.assertIn("malformed", self.report(self.f.token()).problem_codes("statusList.mso"))
        self.mdoc_path.write_bytes(self.f.mdoc(status={"status_list": {"uri": URI, "idx": IDX + 1}}))
        self.assertIn("malformed", self.report(self.f.token()).problem_codes("statusList.mso"))

    def test_a_dedicated_signer_needs_the_status_signing_eku_and_digital_signature(self):
        dedicated_key = key()
        for eku, ku, expected in (([EKU_STATUS_SIGNING], True, []),
                                  ([EKU_STATUS_SIGNING], False, ["kuMissing"]),
                                  ([EKU_MDL_DS], True, ["ekuMissing"]),
                                  (None, True, ["ekuMissing"])):
            dedicated = certificate(dedicated_key, name("Status List Signer"), issuer=self.f.iaca.subject,
                                    issuer_key=self.f.iaca_key, eku=eku, digital_signature=ku)
            body = self.f.token(protected={1: -7, 16: v.TYP, 33: der(dedicated)}, key_for_signature=dedicated_key)
            report = self.report(body)
            self.assertEqual(expected, report.problem_codes("statusList.signerPurpose"), (eku, ku))
            self.assertEqual(["differs"], report.problem_codes("statusList.issuanceChain"),
                             "a dedicated signer is not the mDL's Document Signer")

    def test_the_mdls_own_signer_needs_no_status_eku(self):
        # the Document Signer's own EKU is the mDL one, and Credo's rule exempts the credential's key
        self.assertEqual([], self.report(self.f.token()).problem_codes("statusList.signerPurpose"))

    # ---- statusList.claims, statusList.list ---------------------------------------------------------------------

    def test_the_claims_are_held_to_tsl_5_2_and_8_3(self):
        exp = int((NOW + timedelta(hours=2)).timestamp())
        iat = int(NOW.timestamp())
        cases = {
            "subMismatch": {2: URI + "x"},
            "iatMissing": {6: None},
            "iatFuture": {6: iat + 60},
            "iatAfterExp": {6: exp + 1},  # also iatFuture: the iat moved past both
            "expMissing": {4: None},
            "expired": {4: iat},
            "ttlInvalid": {65534: 0},
        }
        for code, override in cases.items():
            report = self.report(self.f.token(claims=self.f.claims(override)))
            self.assertIn(code, report.problem_codes("statusList.claims"), code)
            self.assertTrue(set(report.problem_codes("statusList.claims")) <= {code, "iatFuture"},
                            report.problem_codes("statusList.claims"))
        self.assertProblems(self.report(self.f.token(claims=self.f.claims({4: int((NOW + timedelta(days=400)).timestamp())}))),
                            {"statusList.claims": ["expAfterSigner"]})

    def test_sub_is_compared_with_the_uri_the_credential_names(self):
        # with no --mdoc and no --uri there is nothing to compare sub with, so subMismatch cannot fire
        report = v.verify(self.f.token(claims=self.f.claims({2: "elsewhere"})), v.MEDIA_TYPE, None, IDX,
                          self.iaca_path, None, 0, NOW)
        self.assertEqual([], report.problem_codes("statusList.claims"))

    def test_the_list_is_held_to_bits_1_zlib_and_the_idx(self):
        cases = {
            "missing": {65533: None},
            "bitsNotOne": {65533: {"lst": zlib.compress(bytes(16)), "bits": 2}},
            "lstNotZlib": {65533: {"lst": b"not zlib at all", "bits": 1}},
            "idxOutOfRange": {65533: {"lst": zlib.compress(b""), "bits": 1}},
            "statusMismatch:1": {65533: {"lst": zlib.compress(bytes([1 << IDX])), "bits": 1}},
        }
        for code, override in cases.items():
            body = self.f.token(claims=self.f.claims(override))
            report = self.report(body, idx=IDX)
            self.assertEqual([code], report.problem_codes("statusList.list"), code)

    def test_raw_deflate_without_the_zlib_wrapper_is_refused(self):
        compressor = zlib.compressobj(wbits=-15)
        raw = compressor.compress(bytes(16)) + compressor.flush()
        body = self.f.token(claims=self.f.claims({65533: {"lst": raw, "bits": 1}}))
        self.assertEqual(["lstNotZlib"], self.report(body).problem_codes("statusList.list"))

    # ---- the command line ---------------------------------------------------------------------------------------

    def test_the_command_line_reports_each_check_and_exits_1_on_a_problem(self):
        good = self.directory / "good.cwt"
        good.write_bytes(self.f.token())
        listed = self.directory / "good.ct"
        listed.write_text(v.MEDIA_TYPE)
        status = v.main(["--list", str(good), "--content-type", listed.read_text(), "--mdoc", str(self.mdoc_path),
                         "--iaca", str(self.iaca_path), "--at", NOW.isoformat()])
        self.assertEqual(0, status)
        bad = self.directory / "bad.cwt"
        bad.write_bytes(self.f.token(protected={1: -7, 16: "wrong", 33: der(self.f.dsc)}))
        self.assertEqual(1, v.main(["--list", str(bad), "--content-type", v.MEDIA_TYPE, "--mdoc",
                                    str(self.mdoc_path), "--iaca", str(self.iaca_path), "--at", NOW.isoformat()]))

    # ---- what the run did not give the tool to decide ------------------------------------------------------------

    def test_a_check_with_nothing_to_decide_it_is_skipped_and_never_passes(self):
        report = self.report(self.f.token(), mdoc=False)
        self.assertFalse(report.failed_any(), {c: report.problems[c] for c in v.CHECKS if report.problems[c]})
        for check in v.MDOC_CHECKS:
            self.assertNotIn(check, report.ran, f"{check} did not run, so it is not a pass")
            self.assertIn(check, report.unchecked)
            self.assertTrue(report.unchecked[check])
        self.assertEqual(set(v.CHECKS) - set(v.MDOC_CHECKS), report.ran)

    def test_the_command_line_prints_skip_lines_and_still_exits_0(self):
        good = self.directory / "skip.cwt"
        good.write_bytes(self.f.token())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = v.main(["--list", str(good), "--content-type", v.MEDIA_TYPE, "--iaca", str(self.iaca_path),
                             "--at", NOW.isoformat()])
        lines = output.getvalue().splitlines()
        skipped = [line for line in lines if line.startswith("SKIP ")]
        self.assertEqual([f"SKIP {check}" for check in v.MDOC_CHECKS], [line.split(":")[0] for line in skipped], lines)
        for line in skipped:
            self.assertIn("--mdoc", line)  # the reason, so a SKIP is never a bare pass
        self.assertEqual(0, status, "a SKIP is not a problem: the exit status stays 0")
        self.assertEqual(len(v.CHECKS) - len(v.MDOC_CHECKS), len([line for line in lines if line.startswith("PASS ")]))

    def test_a_token_that_does_not_parse_reports_the_rest_as_skipped(self):
        report = self.report(b"not cbor")
        self.assertEqual(["notTagged18"], report.problem_codes("statusList.envelope"))
        self.assertNotIn("statusList.claims", report.ran)
        self.assertIn("statusList.claims", report.unchecked)

    def test_the_problem_codes_are_the_java_tables(self):
        # the same map ProblemCodeRegistryTest holds IndependentStatusListVerifier.PROBLEM_CODES to
        self.assertEqual(["statusList.mso", "statusList.http", "statusList.envelope", "statusList.typ",
                          "statusList.x5chain", "statusList.signature", "statusList.chain", "statusList.issuanceChain",
                          "statusList.claims", "statusList.list", "statusList.signerPurpose"], v.CHECKS)
        self.assertEqual(["notTagged18", "cwtTag61", "mac0", "detachedPayload", "duplicateKey"],
                         v.PROBLEM_CODES["statusList.envelope"])
        self.assertEqual(["invalid:multipaz", "invalid:authlete"], v.PROBLEM_CODES["statusList.signature"])


if __name__ == "__main__":
    unittest.main()
