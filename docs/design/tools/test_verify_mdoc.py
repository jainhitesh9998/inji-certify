#!/usr/bin/env python3
"""Regression tests for verify_mdoc.py (docs/design/20-mdl-issuer.md M-01): the problem codes, the .gaps rules and the
framing rules, each with the input that must pass and the mutation that must fail.

    python -m unittest discover -s docs/design/tools -p 'test_*.py'   # in the verify_mdoc venv
"""
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import cbor2

import verify_mdoc as v

# verify_mdoc.py refuses an interpreter older than 3.11 in main() with a message; these tests exercise its answers and
# exit codes (including main()'s refusals) on whatever interpreter runs the suite, and its parsing is written to give the
# same answer on all of them, so the CLI's version check is allowed to pass here.
os.environ.setdefault("VERIFY_MDOC_ALLOW_OLD_PYTHON", "1")

HERE = os.path.dirname(os.path.abspath(__file__))
NS = "org.iso.18013.5.1"


def item(digest_id, identifier, value):
    inner = cbor2.dumps({"digestID": digest_id, "random": b"\0" * 16, "elementIdentifier": identifier,
                         "elementValue": value})
    return cbor2.dumps(cbor2.CBORTag(24, inner))


def tdate(text):
    return cbor2.CBORTag(0, text)


def codes(check, run):
    problems = v.Problems(check)
    run(problems)
    return list(problems.found)


class DuplicatedNamespaceKey(unittest.TestCase):
    """A namespace twice: a decoder that keeps the last one would drop the items the first one carried."""

    def fixture(self):
        namespaces = (b"\xa2" + cbor2.dumps(NS) + b"\x81" + item(0, "family_name", "Demo")
                      + cbor2.dumps(NS) + b"\x81" + item(1, "given_name", "Test"))
        issuer_signed = (b"\xa2" + cbor2.dumps("issuerAuth") + cbor2.dumps([b"", {}, b"", b""])
                         + cbor2.dumps("nameSpaces") + namespaces)
        handle, path = tempfile.mkstemp(suffix=".mdoc")
        with os.fdopen(handle, "wb") as f:
            f.write(issuer_signed)
        self.addCleanup(os.remove, path)
        return path

    def test_main_refuses_it(self):
        with self.assertRaises(v.Check) as refused:
            v.main([self.fixture()])
        self.assertIn("twice", str(refused.exception))

    def test_the_command_exits_2(self):
        run = subprocess.run([sys.executable, "-I", os.path.join(HERE, "verify_mdoc.py"), self.fixture()],
                             capture_output=True, text=True)
        self.assertEqual(2, run.returncode, run.stdout + run.stderr)
        self.assertIn("FAIL issuerSigned.parse:malformed", run.stdout)
        self.assertIn(f"'{NS}' twice", run.stdout)

    def test_a_single_namespace_is_read(self):
        namespaces = b"\xa1" + cbor2.dumps(NS) + b"\x82" + item(0, "family_name", "Demo") + item(1, "given_name", "Test")
        issuer_signed = b"\xa1" + cbor2.dumps("nameSpaces") + namespaces
        self.assertEqual(2, len(v.wire_items(issuer_signed)[NS]))


class GapsFile(unittest.TestCase):

    def read(self, text):
        handle, path = tempfile.mkstemp(suffix=".gaps")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return v.read_gaps(path)

    def test_problem_code_lines_parse(self):
        gaps = self.read("# header\n\nmso.validityInfo:signedAfterValidFrom # G8\n"
                         "mdl.elementTypes:untyped:birth_date # G2\nx5chain.serialNumber:nonPositive # G27\n")
        self.assertEqual({"mso.validityInfo": {"signedAfterValidFrom": "G8"},
                          "mdl.elementTypes": {"untyped:birth_date": "G2"},
                          "x5chain.serialNumber": {"nonPositive": "G27"}}, gaps)

    def test_refused_like_java(self):
        for text, why in [("mso.validityInfo # G8\n", "a bare check name"),
                          ("x5chain.serialNumber? # G27\n", "the optional marker"),
                          ("mso.noSuchCheck:expired # x\n", "an unknown check"),
                          ("mso.validityInfo:tooLate # x\n", "an unknown code"),
                          ("mso.validityInfo:expired:now # x\n", "a parameter on a code without one"),
                          ("mdl.elementTypes:untyped # x\n", "a parameterised code without its parameter"),
                          ("mso.validityInfo:error # x\n", "an unexpected error"),
                          ("mso.validityInfo:expired\n", "no reason"),
                          ("mso.docType:mismatch # a\nmso.docType:mismatch # b\n", "twice")]:
            with self.subTest(why):
                with self.assertRaises(v.Unusable):
                    self.read(text)


class Validity(unittest.TestCase):
    NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)

    def test_every_rule_is_reported_not_the_first(self):
        expired_and_late = {"signed": tdate("2020-01-01T00:00:05Z"), "validFrom": tdate("2020-01-01T00:00:00Z"),
                            "validUntil": tdate("2021-01-01T00:00:00Z")}
        self.assertEqual(["signedAfterValidFrom", "expired"],
                         codes("mso.validityInfo", lambda p: v.check_validity(p, expired_and_late, self.NOW)))

    def test_untagged_and_milliseconds_are_read_for_the_order(self):
        core = {"signed": tdate("2026-11-13T00:00:00.004Z"), "validFrom": "2026-11-13T00:00:00.002Z",
                "validUntil": "2028-11-13T00:00:00.002Z"}
        self.assertEqual(["signedAfterValidFrom"],
                         codes("mso.validityInfo", lambda p: v.check_validity(p, core, self.NOW + timedelta(hours=1))))
        self.assertEqual(["fractionalSeconds:signed", "untagged:validFrom", "fractionalSeconds:validFrom",
                          "untagged:validUntil", "fractionalSeconds:validUntil"],
                         codes("mso.validityInfo.tdateTags", lambda p: v.check_tdate_tags(p, core)))

    def test_missing_and_unreadable_dates(self):
        validity = {"validFrom": tdate("2026-13-01T00:00:00Z"), "validUntil": tdate("2030-01-01T00:00:00Z"),
                    "expectedUpdate": tdate("2029-01-01T00:00:00Z")}
        self.assertEqual(["missing:signed", "notDate:validFrom"],
                         codes("mso.validityInfo", lambda p: v.check_validity(p, validity, self.NOW)))

    def test_tdate_codes_match_the_java_harness(self):
        self.assertEqual([], [c for c, _ in v.tdate_problems(tdate("2026-11-13T10:15:30Z"))])
        self.assertEqual(["fractionalSeconds"], [c for c, _ in v.tdate_problems(tdate("2026-11-13T10:15:30.123Z"))])
        self.assertEqual(["untagged", "fractionalSeconds"], [c for c, _ in v.tdate_problems("2026-11-13T10:15:30.123Z")])
        self.assertEqual(["fractionalSeconds", "notZulu"],
                         [c for c, _ in v.tdate_problems(tdate("2026-11-13T10:15:30.5+05:30"))])
        self.assertEqual(["notCalendar"], [c for c, _ in v.tdate_problems(tdate("2026-02-30T10:15:30Z"))])
        self.assertEqual(["notRfc3339"], [c for c, _ in v.tdate_problems(tdate("2026-11-13 10:15:30Z"))])
        self.assertEqual(["notTdate", "notRfc3339"], [c for c, _ in v.tdate_problems(cbor2.CBORTag(1004, "2026-11-13"))])
        self.assertEqual(["notTdate"], [c for c, _ in v.tdate_problems(b"\x01")])

    def test_a_fraction_of_any_length_is_read_the_same_on_every_interpreter(self):
        # before Python 3.11 `datetime.fromisoformat` accepts only 0, 3 or 6 fraction digits, so `.4Z` was notCalendar
        for seconds, expected in (("00.4Z", ["fractionalSeconds"]), ("00.12345Z", ["fractionalSeconds"]),
                                  ("00.123456789Z", ["fractionalSeconds"]), ("00Z", [])):
            self.assertEqual(expected, [c for c, _ in v.tdate_problems(tdate("2026-11-13T10:15:" + seconds))], seconds)
        # the order keeps the sub-second part, so two dates in one second still compare
        self.assertEqual(v.parse_instant("2026-11-13T00:00:00.004Z"),
                         v.parse_instant("2026-11-13T00:00:00.004000Z"))
        self.assertGreater(v.parse_instant("2026-11-13T00:00:00.004Z"), v.parse_instant("2026-11-13T00:00:00.002Z"))
        self.assertEqual(["signedAfterValidFrom"], codes("mso.validityInfo", lambda p: v.check_validity(p, {
            "signed": tdate("2026-11-13T00:00:00.004Z"), "validFrom": "2026-11-13T00:00:00.002Z",
            "validUntil": "2028-11-13T00:00:00.002Z"}, self.NOW + timedelta(hours=1))))


class Serials(unittest.TestCase):

    @staticmethod
    def certificate(serial):
        return SimpleNamespace(serial_number=serial, subject=SimpleNamespace(rfc4514_string=lambda: "CN=x"))

    def serial_codes(self, serial):
        return codes("x5chain.serialNumber", lambda p: v.check_serial_numbers(p, [self.certificate(serial)]))

    def test_codes(self):
        self.assertEqual([], self.serial_codes(1))
        self.assertEqual([], self.serial_codes(2 ** 158))  # 20 octets
        self.assertEqual(["tooLong"], self.serial_codes(2 ** 159))  # a sign octet makes 21
        self.assertEqual(["nonPositive"], self.serial_codes(-5))
        self.assertEqual(["nonPositive", "zero"], self.serial_codes(0))

    def test_der_octets_is_javas_to_byte_array_length(self):
        for value, octets in [(0, 1), (127, 1), (128, 2), (-128, 1), (-129, 2), (2 ** 158, 20), (2 ** 159, 21)]:
            self.assertEqual(octets, v.der_octets(value), value)


class Evaluate(unittest.TestCase):

    def result(self, check, found):
        problems = v.Problems(check)
        for code, message in found.items():
            problems.add(code, message)
        return check, problems, "ok"

    def test_an_expired_credential_fails_with_g8_declared(self):
        results = [self.result("mso.validityInfo", {"signedAfterValidFrom": "late", "expired": "past"})]
        lines, failures = v.evaluate(results, {"mso.validityInfo": {"signedAfterValidFrom": "G8"}})
        self.assertEqual(1, failures, lines)
        self.assertIn("  FAIL mso.validityInfo:expired: past", lines)

    def test_a_declared_code_no_longer_reported_fails(self):
        results = [self.result("x5chain.serialNumber", {})]
        lines, failures = v.evaluate(results, {"x5chain.serialNumber": {"nonPositive": "G27"}})
        self.assertEqual(1, failures, lines)
        self.assertTrue(any("gap no longer present, remove x5chain.serialNumber:nonPositive" in line for line in lines))

    def test_a_zero_serial_fails_with_non_positive_declared(self):
        results = [self.result("x5chain.serialNumber", {"nonPositive": "0", "zero": "0"})]
        lines, failures = v.evaluate(results, {"x5chain.serialNumber": {"nonPositive": "G27"}})
        self.assertEqual(1, failures, lines)
        self.assertIn("  FAIL x5chain.serialNumber:zero: 0", lines)

    def test_java_only_gaps_are_notes(self):
        results = [self.result("mso.validityInfo", {})]
        lines, failures = v.evaluate(results, {"mso.validityInfo": {"multipazRejects": "x"},
                                               "mdl.elementTypes": {"missing:given_name": "G3"}})
        self.assertEqual(0, failures, lines)
        self.assertEqual(2, sum(1 for line in lines if line.startswith("  NOTE")), lines)

    def test_parameters_are_spelled_like_java(self):
        self.assertEqual("org.iso.18013.5.1/family_name", v.parameter("org.iso.18013.5.1/family_name"))
        self.assertEqual("a_b_", v.parameter("a bé"))


if __name__ == "__main__":
    unittest.main()
