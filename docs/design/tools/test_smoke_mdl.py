#!/usr/bin/env python3
"""Tests for the comparison helpers of smoke_mdl.py (docs/design/20-mdl-issuer.md M-10, VALIDATE.md 6f): what the mDL
smoke run accepts as equal to holders.json and as a valid status list, without a running stack.

    python -m unittest discover -s docs/design/tools -p 'test_*.py'   # in the verify_mdoc venv; PyJWT not needed
"""
import base64
import json
import sys
import types
import unittest
import zlib
from datetime import date
from pathlib import Path

import cbor2

try:
    import jwt  # noqa: F401 - smoke_mdl imports it; the helpers tested here do not use it
except ImportError:  # the CI venv is requirements-verify.txt, without PyJWT
    sys.modules["jwt"] = types.ModuleType("jwt")

import smoke_mdl as s

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


class IssuerHint(unittest.TestCase):

    def test_the_public_url_is_suggested_when_the_base_differs(self):
        hint = s.issuer_hint("http://localhost:8091", "https://credentials.example/v1/certify/oid4vci")
        self.assertIn("pass the stack's public URL", hint)
        self.assertIn("smoke.py --mdl https://credentials.example", hint)

    def test_no_hint_when_the_issuer_is_under_the_base(self):
        self.assertIsNone(s.issuer_hint("http://localhost:8091/", "http://localhost:8091/v1/certify/oid4vci"))
        self.assertIsNotNone(s.issuer_hint("http://localhost:80", "http://localhost:8091/v1/certify/oid4vci"))


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
