#!/usr/bin/env python3
"""Tests for the comparison helpers of smoke_mdl.py (docs/design/20-mdl-issuer.md M-10, VALIDATE.md 6f): what the mDL
smoke run accepts as equal to holders.json and as a valid status list, without a running stack.

    python -m unittest discover -s docs/design/tools -p 'test_*.py'   # in the verify_mdoc venv; PyJWT not needed
"""
import base64
import json
import sys
import time
import types
import unittest
import zlib
from datetime import date, timedelta
from pathlib import Path

import cbor2

try:
    import jwt  # noqa: F401 - smoke_mdl imports it; the helpers tested here do not use it
except ImportError:  # the CI venv is requirements-verify.txt, without PyJWT
    sys.modules["jwt"] = types.ModuleType("jwt")

import smoke_mdl as s

NOW = 1_800_000_000  # the evaluation time the CWT checks are made against
HOLDERS = json.loads(s.HOLDERS.read_text())
RECORD = HOLDERS["mdl-demo-1"]
PORTRAIT = (s.HOLDERS.parent / RECORD["portrait"]).read_bytes()


def full_date(text):
    return cbor2.CBORTag(1004, text)


def issued(record, **override):
    """The elements and IssuerSignedItem bytes an mDL carries for this record, as Certify encodes them."""
    values = {name: record[name] for name in s.TEXTS + ["sex", "age_over_18"] if name in record}
    values.update({name: full_date(record[name]) for name in s.FULL_DATES})
    values["portrait"] = PORTRAIT
    values["driving_privileges"] = [{k: full_date(v) if k in s.PRIVILEGE_DATES else v for k, v in p.items()}
                                    for p in record["driving_privileges"]]
    values.update(override)
    elements, items = {}, {}
    for digest_id, (name, value) in enumerate(values.items()):
        item = cbor2.dumps({"digestID": digest_id, "random": b"\x01" * 16, "elementIdentifier": name, "elementValue": value})
        items[name] = item
        elements[name] = cbor2.loads(item)["elementValue"]
    return elements, items


class ElementProblems(unittest.TestCase):

    def problems(self, **override):
        elements, items = issued(RECORD, **override)
        return s.element_problems(RECORD, elements, items, PORTRAIT)

    def test_the_record_as_issued_has_no_problem(self):
        self.assertEqual([], self.problems())

    def test_a_date_as_text_is_refused(self):
        self.assertTrue(any(p.startswith("birth_date") for p in self.problems(birth_date=RECORD["birth_date"])))

    def test_a_date_as_tag_100_is_refused_although_cbor2_reads_a_date(self):
        days = (date.fromisoformat(RECORD["birth_date"]) - date(1970, 1, 1)).days
        self.assertEqual(["birth_date: not a tag 1004 full-date"], self.problems(birth_date=cbor2.CBORTag(100, days)))

    def test_another_date_is_refused(self):
        self.assertTrue(any(p.startswith("expiry_date") for p in self.problems(expiry_date=full_date("2031-01-15"))))

    def test_true_is_not_1(self):
        self.assertTrue(any(p.startswith("sex") for p in self.problems(sex=True)))
        self.assertTrue(any(p.startswith("age_over_18") for p in self.problems(age_over_18=1)))

    def test_the_whole_driving_privileges_are_compared(self):
        privileges = [dict(p) for p in issued(RECORD)[0]["driving_privileges"]]
        privileges[0] = {**privileges[0], "expiry_date": full_date("2029-01-15")}
        self.assertTrue(any(p.startswith("driving_privileges") for p in self.problems(driving_privileges=privileges)))
        dropped = [{"vehicle_category_code": p["vehicle_category_code"]} for p in RECORD["driving_privileges"]]
        self.assertTrue(any(p.startswith("driving_privileges") for p in self.problems(driving_privileges=dropped)))

    def test_a_privilege_date_as_tag_100_is_refused_when_another_privilege_shares_it(self):
        # mdl-demo-1's privileges share issue_date and expiry_date: a byte search for the tag 1004 encoding of the date
        # finds the other privilege's copy, so only a check at each path ([1].issue_date) catches this
        self.assertEqual(RECORD["driving_privileges"][0]["issue_date"], RECORD["driving_privileges"][1]["issue_date"])
        days = (date.fromisoformat(RECORD["driving_privileges"][1]["issue_date"]) - date(1970, 1, 1)).days
        privileges = issued(RECORD)[0]["driving_privileges"]
        tagged = [{k: full_date(v.isoformat()) if isinstance(v, date) else v for k, v in p.items()} for p in privileges]
        tagged[1]["issue_date"] = cbor2.CBORTag(100, days)
        self.assertEqual(["driving_privileges: not a tag 1004 full-date: [1] B.issue_date"],
                         self.problems(driving_privileges=tagged))

    def test_privilege_dates_as_text_are_refused(self):
        as_text = [dict(p) for p in RECORD["driving_privileges"]]
        self.assertTrue(any(p.startswith("driving_privileges") for p in self.problems(driving_privileges=as_text)))

    def test_another_portrait_is_refused(self):
        self.assertTrue(any(p.startswith("portrait") for p in self.problems(portrait=PORTRAIT + b"\0")))

    def test_text_values_compare_exactly(self):
        self.assertTrue(any(p.startswith("family_name") for p in self.problems(family_name="demo")))


class CborTagged(unittest.TestCase):

    def test_tags_are_kept_where_cbor2_would_turn_them_into_dates(self):
        data = cbor2.dumps({"a": [cbor2.CBORTag(1004, "2024-01-15"), cbor2.CBORTag(100, 19737)], "b": cbor2.CBORTag(24, b"x")})
        self.assertEqual({"a": [cbor2.CBORTag(1004, "2024-01-15"), cbor2.CBORTag(100, 19737)], "b": cbor2.CBORTag(24, b"x")},
                         s.cbor_tagged(data))
        self.assertEqual(date(2024, 1, 15), cbor2.loads(data)["a"][1])  # why cbor2.loads cannot tell them apart

    def test_untagged_values_decode_as_cbor2_does(self):
        value = {"i": [0, 23, 24, 255, 65536, 2**40, -1, -500], "t": "Bengaluru ಬೆಂಗಳೂರು", "b": b"\x00\xff",
                 "s": [True, False, None], "f": [1.5, 0.1], 1: {"nested": []}}
        for canonical in (False, True):
            self.assertEqual(cbor2.loads(cbor2.dumps(value, canonical=canonical)), s.cbor_tagged(cbor2.dumps(value, canonical=canonical)))

    def test_indefinite_lengths(self):
        # [_ "ab" "c"] as an indefinite text string, inside an indefinite array, inside an indefinite map
        self.assertEqual({"k": ["abc", 1]}, s.cbor_tagged(bytes.fromhex("bf616b9f7f6261626163ff01ffff")))

    def test_truncated_or_trailing_bytes_fail(self):
        for bad in (bytes.fromhex("82 01"), bytes.fromhex("6461"), bytes.fromhex("01 02")):
            with self.assertRaises((ValueError, IndexError)):
                s.cbor_tagged(bad)

    def test_unreadable_element_bytes_give_none(self):
        # truncated, trailing, and a map with an array key (unhashable: TypeError)
        for bad in (bytes.fromhex("82 01"), bytes.fromhex("01 02"), bytes.fromhex("a1 80 01")):
            self.assertIsNone(s.element_value_tagged(bad))


class StatusListProblems(unittest.TestCase):
    URI = "https://issuer.example/v1/certify/status/1"
    NOW = 1_800_000_000

    def payload(self, bit=0, **claims):
        bits = bytearray(16)
        bits[0] = bit << 3
        lst = base64.urlsafe_b64encode(zlib.compress(bytes(bits))).rstrip(b"=").decode()
        return {"sub": self.URI, "iat": self.NOW - 10, "exp": self.NOW + 3600, "status_list": {"bits": 1, "lst": lst}} | claims

    def test_a_fresh_list_with_the_bit_clear_passes(self):
        self.assertEqual([], s.status_list_problems(self.payload(), self.URI, 3, self.NOW))

    def test_the_bit_set_fails(self):
        self.assertEqual(1, len(s.status_list_problems(self.payload(bit=1), self.URI, 3, self.NOW)))

    def test_sub_must_be_the_uri_of_the_mso(self):
        problems = s.status_list_problems(self.payload(sub="http://localhost:8091/v1/certify/status/1"), self.URI, 3, self.NOW)
        self.assertTrue(problems and problems[0].startswith("sub"))

    def test_expired_missing_or_future_times_fail(self):
        for claims in ({"exp": self.NOW}, {"exp": None}, {"iat": self.NOW + s.CLOCK_SKEW + 1}, {"iat": None}, {"iat": True}):
            payload = {k: v for k, v in self.payload(**claims).items() if v is not None}
            self.assertEqual(1, len(s.status_list_problems(payload, self.URI, 3, self.NOW)), claims)


class StatusEntry(unittest.TestCase):
    """The MSO's status entry is optional (ISO/IEC 18013-5 9.1.2.4); the demo issues none until M-11 (F-21)."""

    def test_an_mso_without_a_status_member_has_none(self):
        self.assertFalse(s.has_status({"docType": s.MDL_DOCTYPE, "valueDigests": {}}))

    def test_a_status_member_is_present_whatever_it_holds(self):
        # absent is the member not being there (F-21 review round 2): null, a string, an empty map, an IdentifierList
        # only (ISO2 12.3.6: Status = { ? status_list, ? identifier_list, * tstr => RFU }) and a null status_list are
        # present, and malformed for a Token Status List entry
        for status in (None, "broken", {}, {"identifier_list": {}}, {"status_list": None}, {"status_list": {}},
                       {"status_list": {"idx": 3, "uri": "https://i/v1/certify/status/1"}}):
            self.assertTrue(s.has_status({"status": status}), status)

    def test_values_that_are_not_an_mso_have_none(self):
        for mso in (None, [], "status"):
            self.assertFalse(s.has_status(mso), mso)

    def test_the_run_reports_the_missing_entry_as_a_pass_and_makes_no_request(self):
        s.results.clear()
        smoke = s.Smoke("http://localhost:1", s.MDL_DOCTYPE, "mdl-demo-1", Path("."))  # nothing listens there
        smoke.status({"docType": s.MDL_DOCTYPE})
        self.assertEqual([("MSO carries no status entry (status disabled on this demo until M-11)", True)],
                         [(step, ok) for step, ok, _ in s.results])
        s.results.clear()


class StatusExpectation(unittest.TestCase):
    """`--expect-status` (F-21 review round 1): the demo issues no status until M-11, and a restore must not go
    unnoticed. A present entry is held to {idx: uint, uri: tstr} before anything is fetched."""

    URI = "https://issuer.example/v1/certify/credentials/token-status-list/1"

    def status(self, mso, expect):
        s.results.clear()
        smoke = s.Smoke("http://localhost:1", s.MDL_DOCTYPE, "mdl-demo-1", Path("."), expect_status=expect)
        smoke.status(mso)  # nothing listens on port 1: a run that fetched would fail differently
        steps = [(step, ok) for step, ok, _ in s.results]
        s.results.clear()
        return steps

    def mso(self, entry="default", **override):
        mso = {"docType": s.MDL_DOCTYPE}
        if entry == "default":
            mso["status"] = {"status_list": {"idx": 3, "uri": self.URI}}
        elif entry is not None:
            mso["status"] = entry
        mso.update(override)
        return mso

    def test_the_demos_default_expectation_passes_without_an_entry(self):
        self.assertEqual([("MSO carries no status entry (status disabled on this demo until M-11)", True)],
                         self.status({"docType": s.MDL_DOCTYPE}, "absent"))

    def test_an_entry_fails_the_default_expectation(self):
        steps = self.status(self.mso(), "absent")
        self.assertEqual([(False, "absent")], [(ok, "absent") for _, ok in steps][:1], steps)
        self.assertIn("--expect-status absent", steps[0][0])
        # the entry is still shape-checked, so the report says what is there
        self.assertEqual("MSO status.status_list {idx: uint, uri: tstr} (Token Status List)", steps[1][0])

    def test_the_m11_runbook_expectation_fails_without_an_entry(self):
        steps = self.status({"docType": s.MDL_DOCTYPE}, "present")
        self.assertEqual([("MSO status entry matches --expect-status present (M-11 restored)", False)], steps)

    def test_the_m11_runbook_expectation_passes_with_a_well_formed_entry(self):
        steps = self.status(self.mso(), "present")
        self.assertEqual([("MSO status entry matches --expect-status present (M-11 restored)", True),
                          ("MSO status.status_list {idx: uint, uri: tstr} (Token Status List)", True)], steps[:2])

    def test_a_malformed_entry_fails_and_is_not_fetched(self):
        for entry in ({"status_list": {"idx": "3", "uri": self.URI}}, {"status_list": {"idx": 3}},
                      {"status_list": {"idx": True, "uri": self.URI}}, {"status_list": {"idx": -1, "uri": self.URI}},
                      {"status_list": {"idx": 3, "uri": ""}}, {"status_list": {"idx": 3, "uri": self.URI, "x": 1}},
                      {"status_list": "nope"}, {"status_list": {"idx": 3.5, "uri": self.URI}}):
            problems = s.status_entry_problems({"status": entry})
            self.assertTrue(problems, entry)
            steps = self.status(self.mso(entry), "present")
            self.assertEqual(("MSO status.status_list {idx: uint, uri: tstr} (Token Status List)", False), steps[-1], entry)

    def test_a_present_but_malformed_status_fails_both_expectations(self):
        # F-21 review round 2: {"status": {"status_list": null}} and {"status": "broken"} passed --expect-status absent
        # because they carried no usable entry; a present member is malformed content, not an absent one
        for status in (None, "broken", 7, [], {}, {"identifier_list": {"id": b"x", "uri": self.URI}},
                       {"status_list": None}, {"status_list": "nope"}, {"status_list": {}}):
            mso = {"docType": s.MDL_DOCTYPE, "status": status}
            self.assertTrue(s.status_entry_problems(mso), status)
            for expect in ("absent", "present"):
                steps = self.status(mso, expect)
                self.assertTrue(steps and not all(ok for _, ok in steps), (status, expect, steps))
                self.assertEqual(("MSO status.status_list {idx: uint, uri: tstr} (Token Status List)", False), steps[-1],
                                 (status, expect, steps))

    def test_only_a_missing_member_passes_the_default_expectation(self):
        self.assertEqual([("MSO carries no status entry (status disabled on this demo until M-11)", True)],
                         self.status({"docType": s.MDL_DOCTYPE}, "absent"))
        self.assertEqual([], s.status_entry_problems({"docType": s.MDL_DOCTYPE}))

    def test_an_mso_that_is_not_a_map_fails(self):
        for mso in (None, [], "x"):
            self.assertEqual([("MSO status entry: the MSO is a map", False)], self.status(mso, "absent"), mso)


class TalaoPath(unittest.TestCase):
    """What a wallet that looks for an authorization endpoint even on a pre-authorized offer needs (F-21), and RFC 8414
    section 2 with it."""
    TOKEN = "https://issuer.example/v1/certify/oauth/token"
    AUTHORIZE = "https://issuer.example/v1/certify/oauth/authorize"
    PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    def test_the_demo_document_has_no_problem(self):
        document = {"authorization_endpoint": self.AUTHORIZE, "token_endpoint": self.TOKEN,
                    "grant_types_supported": ["authorization_code", self.PRE_AUTH]}
        self.assertEqual([], s.talao_path_problems(document))

    def test_a_pre_authorized_only_document_fails_because_it_has_no_authorization_endpoint(self):
        # the document the demo served before F-21: Talao refused it (G29)
        problems = s.talao_path_problems({"token_endpoint": self.TOKEN,
                                          "grant_types_supported": [self.PRE_AUTH]})
        self.assertEqual(["authorization_endpoint None is missing or blank"], problems)
        # ... and listing authorization_code without it is the RFC 8414 section 2 violation on top
        self.assertEqual(2, len(s.talao_path_problems({"token_endpoint": self.TOKEN,
                                                       "grant_types_supported": ["authorization_code", self.PRE_AUTH]})))

    def test_a_blank_or_non_string_endpoint_is_as_absent_as_a_missing_one(self):
        for blank in ("", "   ", None, 7, [self.AUTHORIZE]):
            self.assertTrue(s.talao_path_problems({"authorization_endpoint": blank, "token_endpoint": self.TOKEN}), blank)
            self.assertTrue(s.talao_path_problems({"authorization_endpoint": self.AUTHORIZE, "token_endpoint": blank}), blank)

    def test_authorization_code_needs_a_way_to_obtain_a_code(self):
        ends = {"authorization_endpoint": self.AUTHORIZE, "token_endpoint": self.TOKEN}
        self.assertEqual([], s.talao_path_problems(ends | {"grant_types_supported": ["authorization_code"]}))
        self.assertEqual([], s.talao_path_problems(ends | {"grant_types_supported": [self.PRE_AUTH]}))
        problems = s.talao_path_problems({"token_endpoint": self.TOKEN, "grant_types_supported": ["authorization_code"]})
        self.assertEqual(2, len(problems), problems)
        self.assertTrue(problems[1].startswith("authorization_code is listed with no authorization_endpoint"), problems)

    def test_the_interactive_authorization_endpoint_does_not_satisfy_the_talao_path(self):
        # RFC 8414 consistency holds through the IAE (the owner-approved compatibility interpretation), but a wallet
        # that looks for an authorization_endpoint still finds none, so both checks are reported separately
        iae = {"interactive_authorization_endpoint": "https://issuer.example/v1/certify/oauth/iae",
               "token_endpoint": self.TOKEN, "grant_types_supported": ["authorization_code"]}
        self.assertEqual(["authorization_endpoint None is missing or blank"], s.talao_path_problems(iae))


class IssuerHint(unittest.TestCase):

    def test_the_public_url_is_suggested_when_the_base_differs(self):
        hint = s.issuer_hint("http://localhost:8091", "https://credentials.example/v1/certify/oid4vci")
        self.assertIn("pass the stack's public URL", hint)
        self.assertIn("smoke.py --mdl https://credentials.example", hint)

    def test_no_hint_when_the_issuer_is_under_the_base(self):
        self.assertIsNone(s.issuer_hint("http://localhost:8091/", "http://localhost:8091/v1/certify/oid4vci"))
        self.assertIsNotNone(s.issuer_hint("http://localhost:80", "http://localhost:8091/v1/certify/oid4vci"))


def _certificate(subject_key, common_name, issuer=None, issuer_key=None, ca=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone
    now = datetime.fromtimestamp(NOW, timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
               .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    return builder.sign(issuer_key or subject_key, hashes.SHA256())


class Cwt:
    """A Status List Token in CWT form (ISO/IEC 18013-5 second edition 12.3.6.3) built here with cbor2 and
    cryptography, and the IACA/Document Signer it is signed under: the bytes a smoke run reads from the endpoint."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.iaca_key, self.dsc_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        self.iaca = _certificate(self.iaca_key, "Lorem Ipsum Demo IACA")
        self.dsc = _certificate(self.dsc_key, "Lorem Ipsum Demo Document Signer", issuer=self.iaca.subject,
                                issuer_key=self.iaca_key)

    @staticmethod
    def der(certificate):
        from cryptography.hazmat.primitives import serialization
        return certificate.public_bytes(serialization.Encoding.DER)

    def claims(self, override=None):
        values = {2: self.URI, 4: self.NOW + 3600, 6: self.NOW, 65533: {"lst": zlib.compress(bytes(16)), "bits": 1},
                  65534: 3600}
        values.update(override or {})
        return {key: value for key, value in values.items() if value is not None}

    def token(self, claims=None, protected=None, unprotected=None, tags=(18,), key=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        claims = claims if claims is not None else self.claims()
        protected = cbor2.dumps(protected if protected is not None
                                else {1: -7, 16: s.STATUS_LIST_CWT, 33: self.der(self.dsc)}, canonical=True)
        payload = cbor2.dumps(claims, canonical=True)
        der = (key or self.dsc_key).sign(cbor2.dumps(["Signature1", protected, b"", payload]),
                                         ec.ECDSA(hashes.SHA256()))
        r, v = decode_dss_signature(der)
        value = [protected, unprotected if unprotected is not None else {}, payload,
                 r.to_bytes(32, "big") + v.to_bytes(32, "big")]
        body = cbor2.dumps(value)
        for tag in reversed(tags):
            body = cbor2.dumps(cbor2.CBORTag(tag, cbor2.loads(body)))
        return body

    URI = "https://issuer.example/v1/certify/credentials/token-status-list/1"
    INDEX = 3
    NOW = 1_800_000_000


class StatusListCwtParser(unittest.TestCase):
    """`smoke.py --mdl --expect-status present` reads the list an mTouch mSO names: a JWT, tag 61, an unprotected
    x5chain, a missing exp and an x5chain that differs from the mDL's IssuerAuth one must each be refused on the bytes
    (M-11f negative tests), so a list Paradym would refuse cannot pass the smoke run."""

    def setUp(self):
        self.cwt = Cwt()
        self.chain = [self.cwt.dsc]

    def problems(self, body, **kwargs):
        return s.status_list_cwt_problems(body, kwargs.pop("content_type", s.STATUS_LIST_CWT), self.cwt.URI,
                                          self.cwt.INDEX, kwargs.pop("chain", self.chain), self.cwt.NOW, **kwargs)

    def test_the_fixtures_token_has_no_problem(self):
        self.assertEqual([], self.problems(self.cwt.token()))

    def test_a_jwt_body_is_refused(self):
        problems = self.problems(b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", content_type="application/statuslist+jwt")
        self.assertEqual(2, len(problems), problems)
        self.assertIn("application/statuslist+cwt", problems[0])
        self.assertIn("JWT", problems[1])

    def test_tag_61_is_refused(self):
        self.assertTrue(any("61" in problem for problem in self.problems(self.cwt.token(tags=(61, 18)))))

    def test_an_unprotected_x5chain_is_refused(self):
        body = self.cwt.token(protected={1: -7, 16: s.STATUS_LIST_CWT}, unprotected={33: self.cwt.der(self.cwt.dsc)})
        self.assertTrue(any("no x5chain" in problem and "unprotected" in problem for problem in self.problems(body)),
                        self.problems(body))

    def test_a_missing_exp_is_refused(self):
        self.assertTrue(any(problem.startswith("exp (4)") for problem in self.problems(self.cwt.token(claims=self.cwt.claims({4: None})))))

    def test_an_x5chain_that_differs_from_the_issuerauth_one_is_refused(self):
        problems = self.problems(self.cwt.token(), chain=[_certificate(self.cwt.dsc_key, "Another Document Signer")])
        self.assertTrue(any("IssuerAuth" in problem for problem in problems), problems)
        self.assertEqual([], self.problems(self.cwt.token(), require_issuance_chain=False),
                         "--status-signer dedicated skips this one check")

    def test_a_signature_by_another_key_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        body = self.cwt.token(key=ec.generate_private_key(ec.SECP256R1()))
        self.assertTrue(any(problem.startswith("the signature does not verify") for problem in self.problems(body)))


class SmokeStatusExpectation(unittest.TestCase):
    """`--expect-status present` over HTTP against recorded bytes, served by a local test server (M-11f): a CWT signed by
    another key, a JWT list and a missing status entry each fail it, and `--expect-status absent` still passes with no
    status member."""

    @classmethod
    def setUpClass(cls):
        import http.server, threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", cls.served["type"])
                self.end_headers()
                self.wfile.write(cls.served["body"])

            def log_message(self, *args):
                pass

        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Cwt.NOW = int(time.time())  # the smoke run evaluates against this machine's clock
        self.cwt = Cwt()
        self.uri = f"{self.base}/v1/certify/credentials/token-status-list/1"

    def body(self, key=None):
        return self.cwt.token(claims=self.cwt.claims({2: self.uri}), key=key)

    def status(self, body, content_type=s.STATUS_LIST_CWT, entry="default", expect="present", chain=None):
        self.__class__.served = {"body": body, "type": content_type}
        s.results.clear()
        smoke = s.Smoke(self.base, s.MDL_DOCTYPE, "mdl-demo-1", Path("."), expect_status=expect)
        mso = {"docType": s.MDL_DOCTYPE}
        if entry == "default":
            mso["status"] = {"status_list": {"idx": Cwt.INDEX, "uri": self.uri}}
        elif entry is not None:
            mso["status"] = entry
        smoke.status(mso, chain if chain is not None else [self.cwt.dsc])
        steps = [(step, ok) for step, ok, _ in s.results]
        s.results.clear()
        return steps

    def test_a_cwt_signed_by_the_mdls_document_signer_passes(self):
        steps = self.status(self.body())
        self.assertTrue(all(ok for _, ok in steps), steps)

    def test_a_cwt_signed_by_another_key_fails(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        steps = self.status(self.body(key=ec.generate_private_key(ec.SECP256R1())))
        self.assertFalse(all(ok for _, ok in steps), steps)

    def test_a_jwt_list_fails(self):
        steps = self.status(b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", content_type="application/statuslist+jwt")
        self.assertFalse(all(ok for _, ok in steps), steps)

    def test_a_missing_status_entry_fails_present_and_passes_absent(self):
        self.assertFalse(all(ok for _, ok in self.status(b"", entry=None, expect="present")))
        steps = self.status(b"", entry=None, expect="absent")
        self.assertTrue(all(ok for _, ok in steps), steps)

    def test_the_jwt_format_option_keeps_the_jwt_check(self):
        # --status-format jwt is a deployment on mdoc.token-format=jwt: a CWT body is not the JWT its run expects
        self.__class__.served = {"body": b"", "type": "application/statuslist+cwt"}
        s.results.clear()
        smoke = s.Smoke(self.base, s.MDL_DOCTYPE, "mdl-demo-1", Path("."), expect_status="present",
                        status_format="jwt", status_signer="document-signer")
        smoke.status({"docType": s.MDL_DOCTYPE, "status": {"status_list": {"idx": Cwt.INDEX, "uri": self.uri}}},
                     [self.cwt.dsc])
        steps = [(step, ok) for step, ok, _ in s.results]
        s.results.clear()
        self.assertFalse(all(ok for _, ok in steps), steps)


class Holders(unittest.TestCase):

    def test_a_missing_holders_file_or_subject_fails_the_run(self):
        s.results.clear()
        s.Smoke("http://localhost:1", s.MDL_DOCTYPE, "mdl-demo-1", Path("."), holders=Path("/nonexistent/holders.json")).run()
        self.assertEqual([False], [ok for _, ok, _ in s.results])
        s.results.clear()
        s.Smoke("http://localhost:1", s.MDL_DOCTYPE, "nobody", Path("."), holders=s.HOLDERS).run()
        self.assertEqual([False], [ok for _, ok, _ in s.results])
        s.results.clear()


if __name__ == "__main__":
    unittest.main()
