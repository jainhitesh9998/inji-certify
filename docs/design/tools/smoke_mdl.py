#!/usr/bin/env python3
"""mDL smoke run of a running Certify with the compose mdl profile (docs/design/20-mdl-issuer.md M-10, VALIDATE.md 6f).

Plays a wallet against the public URL (certify-nginx, CERTIFY_PUBLIC_URL), only through what the offer and the
metadata say:

  1. pre-authorized offers for the mDL configuration with "issuer": "oid4vci", by reference and by value;
  2. issuer metadata at the OpenID4VCI 1.0 section 12.2.2 location derived from the offer's credential_issuer - also
     GET and HEAD with no Accept, application/jwt, text/html, application/json and */*, each of which must answer 200
     application/json, every GET with the same bytes (12.2.2; G30) - and the authorization
     server metadata (RFC 8414) of its authorization server: a present, non-empty grant_types_supported, and every
     authorization_code it lists completable through authorization_endpoint or interactive_authorization_endpoint (gap
     G29: the demo listed the grant without either and Talao's wallet aborted), plus the "Talao path" - a non-blank
     authorization_endpoint and token_endpoint, the pair such a wallet looks for even on a pre-authorized offer (F-21);
  3. a P-256 holder: token (anonymous pre-authorized grant, Bearer), nonce, credential with an ES256 jwt proof,
     notification, nonce replay refused;
  4. an Ed25519 holder: a DPoP-bound token, nonce, credential with an EdDSA jwt proof (ISO/IEC 18013-5 9.1.5.2);
  5. every mDL read back: each element equals the holders.json record in value and CBOR type (full-date as tag 1004,
     bool, uint, bstr, the whole driving_privileges), MSO docType, x5chain without the anchor, and the status entry:
     the demo issues none until M-11 (F-21: an MSO's status is optional, and the only list the stack can write is signed
     by a key outside the IACA, G23), which is a PASS under the default `--expect-status absent` and skips the list
     checks; `--expect-status present` (the M-11 runbook's step) fails when the entry is missing, and an entry that is
     there is held to `{idx: uint, uri: tstr}` before anything is fetched. With an entry, every list check runs - the
     list served, its bit clear, sub equal to the MSO's uri, iat not in the future and exp not passed (exp is
     RECOMMENDED by draft-ietf-oauth-status-list; requiring it is Certify policy); then
     docs/design/tools/verify_mdoc.py (pymdoccbor, a verifier Certify does not maintain) with --doctype, --holder (the
     proof key) and --iaca: the IACA named by the Document Signer's CRL distribution point, downloaded from
     /v1/certify/mdoc/iaca/<id>.pem, or with --iaca <file> the operator's offline IACA, which the published one must
     equal;
  6. the CRL at that distribution point verified with `openssl crl -CAfile`, and the Document Signer with
     `openssl verify -x509_strict -crl_check`;
  7. refusals: an offer for a subject holders.json does not know ends in credential_request_denied, and an admin API,
     a keymanager controller and springdoc are refused for a request that looks public (the nginx allow-list, M-12).

From the repository root:

    python3.12 -m venv .venv && .venv/bin/pip install -r docs/design/tools/requirements-smoke.txt
    .venv/bin/python docs/design/tools/smoke.py --mdl http://localhost:8091
    .venv/bin/python docs/design/tools/smoke.py --mdl "$CERTIFY_PUBLIC_URL" --iaca /path/to/deploy/iaca.pem

The base URL must be the one the stack was started with (CERTIFY_PUBLIC_URL): the offer's credential_issuer and every
endpoint derive from it.

Exit status 0 when every check passes. The credentials, holder keys, IACA and CRL are kept in --out (a new temporary
directory by default) for a second look.
"""
import argparse
import base64
import hashlib
import json
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import date
from pathlib import Path

# Behind Cloudflare the IPv6 addresses of a host can stall for 20 s each before urllib falls back to IPv4
# (workflows.py does the same); localhost resolves to 127.0.0.1 either way.
_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda host, port, family=0, type=0, proto=0, flags=0: _getaddrinfo(host, port, socket.AF_INET, type, proto, flags)

import cbor2
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parents[2]
HOLDERS = REPO / "docker-compose/docker-compose-injistack/config/mdl/holders.json"
MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
MDL_NAMESPACE = "org.iso.18013.5.1"
MANDATORY = ["family_name", "given_name", "birth_date", "issue_date", "expiry_date", "issuing_country",
             "issuing_authority", "document_number", "portrait", "driving_privileges", "un_distinguishing_sign"]
PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
X5CHAIN = 33
TX_CODE = "1234"
# ISO/IEC 18013-5 Table 5 types of the elements holders.json carries; full-date is CBOR tag 1004 over "YYYY-MM-DD"
# (RFC 8943), decoded by cbor2 to datetime.date (as is tag 100, so the tag itself is checked with cbor_tagged)
FULL_DATES = ["birth_date", "issue_date", "expiry_date"]
TEXTS = ["family_name", "given_name", "issuing_country", "issuing_authority", "document_number", "un_distinguishing_sign",
         "nationality", "resident_city"]
PRIVILEGE_DATES = ["issue_date", "expiry_date"]
CLOCK_SKEW = 60  # seconds a status list's iat may lie ahead of this machine's clock

results = []


def check(step, ok, detail=""):
    ok = bool(ok)
    results.append((step, ok, detail))
    print(("PASS " if ok else "FAIL ") + step + (": " + str(detail)[:400] if detail not in ("", None) else ""), flush=True)
    return ok


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(method, url, body=None, headers=None, form=None, binary=False):
    """(status, headers with lower-case names, parsed JSON | text | bytes)."""
    h = {"User-Agent": "certify-mdl-smoke/1.0"}  # Cloudflare answers 1010 to Python's default agent
    h.update(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with OPENER.open(request, timeout=60) as r:
            status, response_headers, raw = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, response_headers, raw = e.code, e.headers, e.read()
    except urllib.error.URLError as e:
        return 0, {}, f"{url}: {e.reason}"
    lower = {k.lower(): v for k, v in response_headers.items()}
    if binary:
        return status, lower, raw
    text = raw.decode("utf-8", "replace")
    if text.strip().startswith(("{", "[")):
        try:
            return status, lower, json.loads(text)
        except ValueError:
            pass
    return status, lower, text


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_jwk(key):
    public = key.public_key()
    if isinstance(public, ed25519.Ed25519PublicKey):
        return {"kty": "OKP", "crv": "Ed25519",
                "x": b64url(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    numbers = public.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}


def jose_alg(key):
    return "EdDSA" if isinstance(key, ed25519.Ed25519PrivateKey) else "ES256"


def holder_proof(key, audience, nonce):
    """OpenID4VCI 1.0 Appendix F.1: typ openid4vci-proof+jwt, the holder key as jwk, aud the issuer, the c_nonce."""
    return jwt.encode({"aud": audience, "iat": int(time.time()), "nonce": nonce}, private_pem(key), algorithm=jose_alg(key),
                      headers={"typ": "openid4vci-proof+jwt", "jwk": public_jwk(key)})


def dpop_proof(key, method, url, access_token=None):
    """RFC 9449 section 4.2."""
    claims = {"jti": secrets.token_urlsafe(16), "htm": method, "htu": url, "iat": int(time.time())}
    if access_token:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode()).digest())
    return jwt.encode(claims, private_pem(key), algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})


def well_known(identifier, suffix):
    """RFC 8414 section 3 / OpenID4VCI 1.0 section 12.2.2: the well-known segment goes between host and path."""
    u = urllib.parse.urlparse(identifier)
    return f"{u.scheme}://{u.netloc}/.well-known/{suffix}{u.path.rstrip('/')}"


def query_param(link, name):
    return urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get(name, [None])[0]


def decode_mdoc(encoded):
    """IssuerSigned -> (raw CBOR, elements by identifier, the IssuerSignedItem bytes by identifier, MSO, x5chain
    certificates as received)."""
    raw = b64url_decode(encoded)
    issuer_signed = cbor2.loads(raw)
    issuer_auth = issuer_signed["issuerAuth"]
    if isinstance(issuer_auth, cbor2.CBORTag):
        issuer_auth = issuer_auth.value
    payload = cbor2.loads(issuer_auth[2])
    mso = cbor2.loads(payload.value if isinstance(payload, cbor2.CBORTag) else payload)
    elements, items = {}, {}
    for item in issuer_signed["nameSpaces"].get(MDL_NAMESPACE, []):
        decoded = cbor2.loads(item.value)
        elements[decoded["elementIdentifier"]] = decoded["elementValue"]
        items[decoded["elementIdentifier"]] = item.value
    chain = issuer_auth[1].get(X5CHAIN)
    chain = [chain] if isinstance(chain, bytes) else list(chain or [])
    return raw, elements, items, mso, [x509.load_der_x509_certificate(c) for c in chain]


def same(actual, expected):
    """Equal in value and in type, recursively: True is not 1, a date is not its text, a list keeps its order."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same(actual[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same(a, e) for a, e in zip(actual, expected))
    return actual == expected


def cbor_tagged(data):
    """The CBOR data item in `data` with every tag kept as a cbor2.CBORTag around its content, so the type of a value
    can be checked at its own path: cbor2.loads turns tag 1004 (full-date) and tag 100 (days since the epoch) alike into
    a datetime.date and offers no switch to keep them. Definite and indefinite lengths; maps become dicts (keys are the
    text and integers an mDoc uses). Trailing bytes are an error."""
    def length(info, pos):
        if info < 24:
            return info, pos
        if info in (24, 25, 26, 27):
            size = 1 << (info - 24)
            return int.from_bytes(data[pos:pos + size], "big"), pos + size
        if info == 31:
            return None, pos
        raise ValueError(f"reserved additional information {info} at byte {pos - 1}")

    def item(pos):
        if pos >= len(data):
            raise ValueError("truncated CBOR")
        major, info = data[pos] >> 5, data[pos] & 0x1F
        pos += 1
        if major == 7:
            if info < 24:
                return {20: False, 21: True, 22: None, 23: cbor2.undefined}.get(info, cbor2.CBORSimpleValue(info)), pos
            if info == 24:
                return cbor2.CBORSimpleValue(data[pos]), pos + 1
            if info in (25, 26, 27):
                size = 1 << (info - 24)
                return cbor2.loads(data[pos - 1:pos + size]), pos + size
            raise ValueError(f"unexpected break or reserved simple value at byte {pos - 1}")
        n, pos = length(info, pos)
        if major == 0:
            return n, pos
        if major == 1:
            return -1 - n, pos
        if major in (2, 3):
            if n is None:
                chunks = []
                while data[pos] != 0xFF:
                    chunk, pos = item(pos)
                    chunks.append(chunk)
                joined = b"".join(chunks) if major == 2 else "".join(chunks)
                return joined, pos + 1
            raw = data[pos:pos + n]
            if len(raw) != n:
                raise ValueError("truncated CBOR string")
            return (raw if major == 2 else raw.decode("utf-8")), pos + n
        if major == 4:
            values = []
            while (n is None and data[pos] != 0xFF) or (n is not None and len(values) < n):
                value, pos = item(pos)
                values.append(value)
            return values, pos + (1 if n is None else 0)
        if major == 5:
            entries, count = {}, 0
            while (n is None and data[pos] != 0xFF) or (n is not None and count < n):
                key, pos = item(pos)
                entries[key], pos = item(pos)
                count += 1
            return entries, pos + (1 if n is None else 0)
        if n is None:
            raise ValueError(f"indefinite length for major type {major}")
        content, pos = item(pos)
        return cbor2.CBORTag(n, content), pos

    value, end = item(0)
    if end != len(data):
        raise ValueError(f"{len(data) - end} bytes after the data item")
    return value


def full_date_tag(node, value):
    """`node` (from cbor_tagged) is `value` as tag 1004 over its "YYYY-MM-DD" text (RFC 8943, ISO/IEC 18013-5 full-date)."""
    return isinstance(node, cbor2.CBORTag) and node.tag == 1004 and node.value == value.isoformat()


def element_value_tagged(item):
    """The elementValue of an IssuerSignedItem's bytes, tags kept; None when the bytes cannot be read."""
    try:
        decoded = cbor_tagged(item)
    except (ValueError, IndexError, UnicodeDecodeError, TypeError):  # TypeError: an unhashable map key
        return None
    return decoded.get("elementValue") if isinstance(decoded, dict) else None


def element_problems(record, elements, items, portrait):
    """What differs between a holders.json record and the elements of an issued mDL: [problem, ...], empty when every
    element the record has is present with the record's value and the Table 5 type."""
    problems = []
    for name in TEXTS:
        if name in record and not same(elements.get(name), record[name]):
            problems.append(f"{name}: {elements.get(name)!r} != {record[name]!r}")
    for name in FULL_DATES:
        try:
            expected = date.fromisoformat(record[name])
        except (KeyError, TypeError, ValueError):
            problems.append(f"{name}: holders.json has no full-date {record.get(name)!r}")
            continue
        if not same(elements.get(name), expected):
            problems.append(f"{name}: {elements.get(name)!r} != {expected!r}")
        elif not full_date_tag(element_value_tagged(items.get(name, b"")), expected):
            problems.append(f"{name}: not a tag 1004 full-date")
    if "sex" in record and not same(elements.get("sex"), record["sex"]):
        problems.append(f"sex: {elements.get('sex')!r} != {record['sex']!r} (uint)")
    if "age_over_18" in record and not same(elements.get("age_over_18"), record["age_over_18"]):
        problems.append(f"age_over_18: {elements.get('age_over_18')!r} != {record['age_over_18']!r} (bool)")
    if portrait is not None and not same(elements.get("portrait"), portrait):
        problems.append("portrait: not the bytes of " + str(record.get("portrait")))
    expected_privileges = []
    for privilege in record.get("driving_privileges", []):
        privilege = dict(privilege)
        for name in PRIVILEGE_DATES:
            if name in privilege:
                try:
                    privilege[name] = date.fromisoformat(privilege[name])
                except (TypeError, ValueError):
                    problems.append(f"driving_privileges: holders.json has no full-date {privilege[name]!r}")
        expected_privileges.append(privilege)
    if not same(elements.get("driving_privileges"), expected_privileges):
        problems.append(f"driving_privileges: {elements.get('driving_privileges')!r} != {expected_privileges!r}")
    else:
        # each date at its own path ([i].issue_date): two privileges sharing a date must each carry tag 1004
        tagged = element_value_tagged(items.get("driving_privileges", b""))
        tagged = tagged if isinstance(tagged, list) and len(tagged) == len(expected_privileges) else [{}] * len(expected_privileges)
        untagged = [f"[{i}] {p['vehicle_category_code']}.{name}" for i, p in enumerate(expected_privileges)
                    for name in PRIVILEGE_DATES
                    if name in p and not (isinstance(tagged[i], dict) and full_date_tag(tagged[i].get(name), p[name]))]
        if untagged:
            problems.append("driving_privileges: not a tag 1004 full-date: " + ", ".join(untagged))
    return problems


def status_list_problems(payload, uri, index, now):
    """The Token Status List JWT claims (draft-ietf-oauth-status-list): sub is the uri the MSO names (REQUIRED), iat not
    in the future (REQUIRED), and the credential's bit clear; and, as Certify policy rather than the draft (which makes
    exp RECOMMENDED), exp present and not passed: Certify always sets it and re-signs a list before it lapses (F-10).
    [problem, ...]."""
    problems = []
    if payload.get("sub") != uri:
        problems.append(f"sub {payload.get('sub')!r} is not the MSO's uri {uri!r}")
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool) or iat > now + CLOCK_SKEW:
        problems.append(f"iat {iat!r} missing or in the future (now {int(now)})")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp <= now:
        problems.append(f"exp {exp!r} missing or passed (now {int(now)}; Certify policy, the draft makes exp RECOMMENDED)")
    try:
        bit = token_status_bit(payload["status_list"]["lst"], index)
    except Exception as e:  # noqa: BLE001 - reported as a problem
        problems.append(f"status_list.lst unreadable: {e}")
    else:
        if bit != 0:
            problems.append(f"bit {index} is {bit}, not 0 (valid)")
    return problems


def has_status(mso):
    """Whether the MSO carries a status entry at all. ISO/IEC 18013-5 9.1.2.4 makes `status` OPTIONAL, and the demo
    issues no status until M-11 (F-21): the only list the compose stack can write is a statuslist+jwt signed by
    keymanager's key, which does not chain to the IACA (G23), so a wallet that requires that chain rejects the mDL.
    A `status` map with no `status_list` (an IdentifierList only, ISO2 12.3.6) carries no entry either."""
    status = mso.get("status") if isinstance(mso, dict) else None
    return isinstance(status, dict) and "status_list" in status


def status_entry_problems(mso):
    """Every way a PRESENT status entry is malformed, as a list of problems: ISO/IEC 18013-5 9.1.2.4 makes the MSO's
    `status` a map carrying `status_list`, and draft-ietf-oauth-status-list gives that entry `{idx: uint, uri: tstr}`.
    [] for a well-formed entry and for an MSO without one (see has_status)."""
    if not has_status(mso):
        return []
    status = mso["status"]
    if not isinstance(status, dict):
        return [f"status is not a map: {status!r}"]
    entry = status["status_list"]
    if not isinstance(entry, dict):
        return [f"status.status_list is not a map: {entry!r}"]
    problems = []
    idx, uri = entry.get("idx"), entry.get("uri")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        problems.append(f"status_list.idx {idx!r} is not an unsigned integer")
    if not isinstance(uri, str) or not uri.strip():
        problems.append(f"status_list.uri {uri!r} is not a non-blank string")
    extra = sorted(set(entry) - {"idx", "uri"})
    if extra:
        problems.append(f"status_list carries unknown members {extra}")
    return problems


def talao_path_problems(as_metadata):
    """What a wallet that looks for an authorization endpoint even on a pre-authorized offer needs (Talao, F-21), and
    RFC 8414 section 2 with it: a non-blank authorization_endpoint and token_endpoint, and authorization_code listed
    only when a code can be obtained there (the authorization endpoint, or the interactive authorization endpoint of
    the OpenID4VCI 1.1 editor's draft). [problem, ...]."""
    def present(value):
        return isinstance(value, str) and value.strip() != ""

    problems = []
    for member in ("authorization_endpoint", "token_endpoint"):
        if not present(as_metadata.get(member)):
            problems.append(f"{member} {as_metadata.get(member)!r} is missing or blank")
    grants = as_metadata.get("grant_types_supported") or []
    if "authorization_code" in grants and not (present(as_metadata.get("authorization_endpoint"))
                                              or present(as_metadata.get("interactive_authorization_endpoint"))):
        problems.append("authorization_code is listed with no authorization_endpoint and no interactive_authorization_endpoint")
    return problems


def issuer_hint(base, issuer):
    """The run's base URL must be the stack's CERTIFY_PUBLIC_URL, the origin of credential_issuer."""
    if not issuer or issuer.startswith(base.rstrip("/") + "/"):
        return None
    u = urllib.parse.urlparse(issuer)
    return (f"credential_issuer {issuer} is not under {base}: pass the stack's public URL (CERTIFY_PUBLIC_URL) as the "
            f"base, smoke.py --mdl {u.scheme}://{u.netloc}")


def crl_distribution_point(certificate):
    try:
        points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None
    for point in points:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                return name.value
    return None


def token_status_bit(lst, index):
    raw = zlib.decompress(b64url_decode(lst))
    return (raw[index // 8] >> (index % 8)) & 1  # bits=1, least significant bit first


def run_openssl(*args):
    binary = shutil.which("openssl")
    if binary is None:
        return None, "openssl not found"
    p = subprocess.run([binary, *args], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


class Smoke:
    def __init__(self, base, configuration, subject, out, pinned_iaca=None, holders=HOLDERS, expect_status="absent"):
        self.base = base.rstrip("/")
        self.certify = self.base + "/v1/certify"
        self.configuration = configuration
        self.subject = subject
        self.out = out
        self.holders_path = holders
        self.holders = json.loads(holders.read_text()) if holders.exists() else None
        self.pinned_iaca = pinned_iaca
        self.expect_status = expect_status
        self.metadata = self.as_metadata = self.issuer = None
        self.iaca_path = self.dsc = None

    # ---------------------------------------------------------------------------------------------- offers
    def offer(self, by_value, subject=None):
        request = {"credential_configuration_id": self.configuration, "subject": subject or self.subject, "issuer": "oid4vci",
                   "expires_in": 600, "tx_code": TX_CODE}
        if by_value:
            request["offer_by_value"] = True
        s, _, response = call("POST", self.certify + "/pre-authorized-data", request)
        link = response.get("credential_offer_uri", "") if isinstance(response, dict) else ""
        if by_value:
            embedded = query_param(link, "credential_offer")
            document = json.loads(embedded) if embedded else None
            ok = s == 200 and document is not None and document == response.get("credential_offer")
            return ok, document, {"status": s, "link": link[:90]} if not ok else "credential_offer in the response equals the one in the deep link"
        offer_url = query_param(link, "credential_offer_uri")
        if s != 200 or not offer_url:
            return False, None, {"status": s, "body": response}
        s, _, document = call("GET", offer_url)
        return s == 200 and isinstance(document, dict), document, offer_url

    def offers(self):
        ok, by_reference, detail = self.offer(False)
        code_ok = isinstance(by_reference, dict) and self.configuration in by_reference.get("credential_configuration_ids", []) \
            and by_reference.get("grants", {}).get(PRE_AUTH, {}).get("pre-authorized_code")
        self.issuer = by_reference.get("credential_issuer") if isinstance(by_reference, dict) else None
        hint = issuer_hint(self.base, self.issuer)
        check("offer by reference: credential_issuer is the /oid4vci identifier",
              ok and code_ok and (self.issuer or "").endswith("/v1/certify/oid4vci") and hint is None,
              hint or ({"credential_issuer": self.issuer, "offer": detail} if ok else detail))
        ok, by_value, detail = self.offer(True)
        check("offer by value: the same issuer, its own pre-authorized code",
              ok and by_value.get("credential_issuer") == self.issuer
              and by_value["grants"][PRE_AUTH].get("tx_code", {}).get("length") == len(TX_CODE), detail)
        return by_reference if code_ok else None, by_value if ok else None

    # ---------------------------------------------------------------------------------------------- discovery
    def discovery(self):
        url = well_known(self.issuer, "openid-credential-issuer")
        s, h, metadata = call("GET", url)
        configuration = (metadata.get("credential_configurations_supported") or {}).get(self.configuration, {}) if isinstance(metadata, dict) else {}
        self.metadata = metadata if isinstance(metadata, dict) else {}
        check("issuer metadata at the 12.2.2 location: credential_issuer equals the offer's",
              s == 200 and self.metadata.get("credential_issuer") == self.issuer and self.metadata.get("nonce_endpoint")
              and self.metadata.get("credential_endpoint", "").startswith(self.issuer),
              {"url": url, "credential_issuer": self.metadata.get("credential_issuer"), "status": s})
        issuer_names = [d.get("name") for d in self.metadata.get("display") or []]
        check("issuer display: Lorem Ipsum Demo Credentials", "Lorem Ipsum Demo Credentials" in issuer_names, issuer_names)
        proofs = configuration.get("proof_types_supported", {}).get("jwt", {}).get("proof_signing_alg_values_supported", [])
        check("mDL configuration: mso_mdoc, doctype, cose_key, ES256 (-7), jwt proofs ES256 and EdDSA",
              configuration.get("format") == "mso_mdoc" and configuration.get("doctype") == MDL_DOCTYPE
              and configuration.get("cryptographic_binding_methods_supported") == ["cose_key"]
              and configuration.get("credential_signing_alg_values_supported") == [-7] and {"ES256", "EdDSA"} <= set(proofs),
              {k: configuration.get(k) for k in ("format", "doctype", "cryptographic_binding_methods_supported",
                                                 "credential_signing_alg_values_supported")} | {"proof algs": proofs})
        metadata_block = configuration.get("credential_metadata", {})
        paths = [c.get("path") for c in metadata_block.get("claims", [])]
        named = all(c.get("display") and c["display"][0].get("name") for c in metadata_block.get("claims", []))
        check("credential_metadata: claims by [namespace, element] with display names, credential display",
              all([MDL_NAMESPACE, e] in paths for e in MANDATORY) and named and metadata_block.get("display"),
              {"claims": len(paths), "display": [d.get("name") for d in metadata_block.get("display") or []]})
        servers = self.metadata.get("authorization_servers") or [self.issuer]
        as_url = well_known(servers[0], "oauth-authorization-server")
        s, _, as_metadata = call("GET", as_url)
        self.as_metadata = as_metadata if isinstance(as_metadata, dict) else {}
        check("authorization server metadata: anonymous pre-authorized grant advertised",
              s == 200 and self.as_metadata.get("issuer") == servers[0]
              and isinstance(self.as_metadata.get("token_endpoint"), str) and self.as_metadata.get("token_endpoint").strip()
              and PRE_AUTH in self.as_metadata.get("grant_types_supported", [])
              and self.as_metadata.get("pre-authorized_grant_anonymous_access_supported") is True,
              {"url": as_url, "status": s} | {k: self.as_metadata.get(k) for k in ("issuer", "token_endpoint", "pre-authorized_grant_anonymous_access_supported")})
        # RFC 8414 section 2: the document advertises only grants it can complete. grant_types_supported must be present
        # and non-empty (an absent list defaults to authorization_code and implicit), and authorization_code needs
        # authorization_endpoint - or the interactive authorization endpoint of the OpenID4VCI 1.1 editor's draft, which
        # is the owner-approved compatibility interpretation (1.0 final has no such endpoint; G29). A blank string is as
        # absent as a missing member. The demo listed authorization_code with neither and a wallet that follows
        # authorization_servers[0] aborted (G29).
        def present(value):
            return isinstance(value, str) and value.strip() != ""

        grants = self.as_metadata.get("grant_types_supported") or []
        authorization_code_completable = (present(self.as_metadata.get("authorization_endpoint"))
                                         or present(self.as_metadata.get("interactive_authorization_endpoint")))
        check("authorization server metadata: non-empty grant_types_supported, authorization_code completable (RFC 8414 s2)",
              bool(grants) and all(present(g) for g in grants)
              and ("authorization_code" not in grants or authorization_code_completable),
              {"grant_types_supported": grants,
               "authorization_endpoint": self.as_metadata.get("authorization_endpoint"),
               "interactive_authorization_endpoint": self.as_metadata.get("interactive_authorization_endpoint")})
        # The "Talao path" (F-21, decision log 2026-11-13): that wallet looks for an authorization endpoint even on a
        # pre-authorized offer and refused the document the demo served without one. The mDL profile now advertises
        # Certify's own code flow (PAR, PKCE S256, one registered client, subject mode `none`), so both endpoints are
        # there and the RFC 8414 consistency above holds for the same document.
        problems = talao_path_problems(self.as_metadata)
        check("authorization server metadata: Talao path (authorization_endpoint and token_endpoint non-blank, RFC 8414 s2)",
              not problems,
              {"authorization_endpoint": self.as_metadata.get("authorization_endpoint"),
               "token_endpoint": self.as_metadata.get("token_endpoint"),
               "problems": problems} if problems else self.as_metadata.get("authorization_endpoint"))
        # Talao reads <as>/.well-known/openid-configuration before the RFC 8414 document and uses it if it parses as
        # OpenID Connect Discovery. This issuer serves no such document, so the path must stay 404/non-JSON: one that
        # parsed with other members would be believed instead of the RFC 8414 document checked above (F-21 review 1).
        oidc_url = well_known(servers[0], "openid-configuration")
        oidc_status, _, oidc = call("GET", oidc_url)
        oidc_parses = isinstance(oidc, dict) and "issuer" in oidc
        check("authorization server metadata: the OIDC discovery path is 404/non-JSON (Talao tries it first)",
              not oidc_parses or all(oidc.get(k) == value for k, value in self.as_metadata.items()),
              {"url": oidc_url, "status": oidc_status, "parses as OIDC discovery": oidc_parses})
        # OpenID4VCI 1.0 section 12.2.2: the unsigned form is the one this issuer serves and its Content-Type must say
        # so. A wallet that prefers the signed form (Accept: application/jwt) or a browser (text/html) must still get the
        # document, not a 406, at the root-mapped location the proxy serves; HEAD answers the same way (G30).
        _, _, reference = call("GET", url, headers={"Accept": "application/json"}, binary=True)
        answers = []
        for method in ("GET", "HEAD"):
            for accept in (None, "application/jwt", "text/html", "application/json", "*/*"):
                status, headers, body = call(method, url, headers={"Accept": accept} if accept else None, binary=True)
                content_type = (headers.get("content-type") or "").lower()
                same_bytes = method == "HEAD" or body == reference
                if status != 200 or not content_type.startswith("application/json") or not same_bytes:
                    answers.append({"method": method, "accept": accept, "status": status, "content-type": content_type,
                                    "same bytes as Accept: application/json": same_bytes})
        check("issuer metadata at the 12.2.2 location: GET and HEAD answer 200 application/json for every Accept, one document",
              not answers and isinstance(reference, bytes) and b'"credential_issuer"' in reference, answers)
        return bool(self.metadata.get("credential_endpoint") and self.as_metadata.get("token_endpoint"))

    # ---------------------------------------------------------------------------------------------- the flow
    def token(self, offer, dpop_key=None):
        code = offer["grants"][PRE_AUTH]["pre-authorized_code"]
        headers = {"DPoP": dpop_proof(dpop_key, "POST", self.as_metadata["token_endpoint"])} if dpop_key else {}
        s, _, token = call("POST", self.as_metadata["token_endpoint"], headers=headers,
                           form={"grant_type": PRE_AUTH, "pre-authorized_code": code, "tx_code": TX_CODE})
        return (token if s == 200 and isinstance(token, dict) and token.get("access_token") else None), {"status": s, "body": token}

    def nonce(self):
        s, h, response = call("POST", self.metadata["nonce_endpoint"])
        return (response.get("c_nonce") if s == 200 and isinstance(response, dict) else None), h.get("cache-control")

    def credential(self, token, holder, nonce, dpop_key=None):
        headers = {"Authorization": token.get("token_type", "Bearer") + " " + token["access_token"]}
        if dpop_key:
            headers["DPoP"] = dpop_proof(dpop_key, "POST", self.metadata["credential_endpoint"], token["access_token"])
        return call("POST", self.metadata["credential_endpoint"], {"credential_configuration_id": self.configuration,
                                                                    "proofs": {"jwt": [holder_proof(holder, self.issuer, nonce)]}}, headers)

    def holder_run(self, label, offer, holder, dpop_key=None):
        token, detail = self.token(offer, dpop_key)
        expected_type = "DPoP" if dpop_key else "Bearer"
        claims = jwt.decode(token["access_token"], options={"verify_signature": False}) if token else {}
        check(f"{label}: token ({expected_type}, anonymous pre-authorized grant), sub {self.subject}",
              token and token.get("token_type") == expected_type and claims.get("sub") == self.subject
              and (not dpop_key or claims.get("cnf", {}).get("jkt")),
              {"token_type": token.get("token_type"), "sub": claims.get("sub"), "aud": claims.get("aud")} if token else detail)
        if not token:
            return None
        nonce, cache_control = self.nonce()
        check(f"{label}: nonce (Cache-Control no-store)", nonce and "no-store" in (cache_control or ""), cache_control)
        s, _, response = self.credential(token, holder, nonce, dpop_key)
        credentials = response.get("credentials") if isinstance(response, dict) else None
        encoded = credentials[0].get("credential") if credentials else None
        check(f"{label}: credential with a {jose_alg(holder)} jwt proof", s == 200 and isinstance(encoded, str) and response.get("notification_id"),
              {"status": s, "body": response} if s != 200 else {"bytes": len(encoded or ""), "notification_id": response.get("notification_id")})
        if not isinstance(encoded, str):
            return None
        return {"label": label, "token": token, "nonce": nonce, "encoded": encoded, "holder": holder,
                "notification_id": response.get("notification_id"), "dpop_key": dpop_key}

    # ---------------------------------------------------------------------------------------------- the mDL itself
    def inspect(self, issued):
        label = issued["label"]
        raw, elements, items, mso, chain = decode_mdoc(issued["encoded"])
        name = label.split(" ")[0].lower()
        mdoc_path = self.out / f"{name}.mdoc"
        holder_path = self.out / f"{name}.holder.jwk"
        mdoc_path.write_bytes(raw)
        holder_path.write_text(json.dumps(public_jwk(issued["holder"])))
        record = (self.holders or {}).get(self.subject)
        missing = [e for e in MANDATORY if e not in elements]
        if record is None:
            mismatched = [f"no record {self.subject} in {self.holders_path}"]
        else:
            portrait_file = self.holders_path.parent / record["portrait"] if record.get("portrait") else None
            portrait = portrait_file.read_bytes() if portrait_file and portrait_file.is_file() else None
            mismatched = element_problems(record, elements, items, portrait)
            if record.get("portrait") and portrait is None:
                mismatched.append(f"portrait: {portrait_file} not found")
        check(f"{label}: every Table 5 mandatory element, values and CBOR types equal holders.json[{self.subject}]",
              not missing and not mismatched and elements.get("issuing_country") == "IN" and elements.get("un_distinguishing_sign") == "IND"
              and isinstance(elements.get("portrait"), bytes) and elements["portrait"][:2] == b"\xff\xd8",
              {"missing": missing, "mismatched": mismatched} if missing or mismatched else sorted(elements))
        check(f"{label}: MSO docType {MDL_DOCTYPE}, x5chain is the Document Signer alone (no anchor, HAIP)",
              mso.get("docType") == MDL_DOCTYPE and len(chain) == 1 and chain[0].issuer != chain[0].subject,
              {"docType": mso.get("docType"), "x5chain": [c.subject.rfc4514_string() for c in chain]})
        if self.dsc is None and chain:
            self.dsc = chain[0]
            self.trust()
        if self.iaca_path:
            p = subprocess.run([sys.executable, str(TOOLS / "verify_mdoc.py"), str(mdoc_path), "--doctype", MDL_DOCTYPE,
                                "--iaca", str(self.iaca_path), "--holder", str(holder_path)], capture_output=True, text=True)
            output = (p.stdout + p.stderr).strip()
            print("\n".join("    | " + line for line in output.splitlines()))
            check(f"{label}: verify_mdoc.py (pymdoccbor) with --iaca, --doctype, --holder: no problem", p.returncode == 0,
                  "exit 0" if p.returncode == 0 else f"exit {p.returncode}")
        return mso

    def trust(self):
        """The IACA the Document Signer names (its CRL distribution point .../mdoc/iaca/<id>.crl), from the publication."""
        dp = crl_distribution_point(self.dsc)
        anchor_id = dp.rsplit("/", 1)[-1][:-len(".crl")] if dp and dp.endswith(".crl") and "/mdoc/iaca/" in dp else None
        s, _, listing = call("GET", self.certify + "/mdoc/iaca")
        entry = next((e for e in listing if e.get("id") == anchor_id), None) if isinstance(listing, list) else None
        check("IACA list (GET /mdoc/iaca) names the Document Signer's IACA by its CRL distribution point",
              s == 200 and entry is not None and entry.get("country") == "IN" and entry.get("crl"),
              {"crl_dp": dp, "ids": [e.get("id") for e in listing] if isinstance(listing, list) else listing})
        if entry is None:
            return
        s, h, pem = call("GET", f"{self.certify}/mdoc/iaca/{anchor_id}.pem", binary=True)
        iaca = x509.load_pem_x509_certificate(pem) if s == 200 else None
        fingerprint = iaca.fingerprint(hashes.SHA256()).hex() if iaca else None
        check(f"IACA download /mdoc/iaca/{anchor_id}.pem matches the list's sha256, issued the DSC",
              iaca is not None and fingerprint == entry.get("sha256").replace(":", "").lower()
              and self.dsc.issuer == iaca.subject and "Lorem Ipsum Demo IACA" in iaca.subject.rfc4514_string(),
              {"subject": iaca.subject.rfc4514_string() if iaca else s, "content-type": h.get("content-type")})
        if iaca is None:
            return
        self.iaca_path = self.out / "iaca.pem"
        self.iaca_path.write_bytes(pem)
        if self.pinned_iaca is not None:
            # The operator's offline IACA (D3) is the trust anchor; the published copy must be that certificate, or a
            # wallet that fetched it would trust something else.
            pinned = x509.load_pem_x509_certificate(self.pinned_iaca.read_bytes())
            same_certificate = pinned.public_bytes(serialization.Encoding.DER) == iaca.public_bytes(serialization.Encoding.DER)
            check(f"published IACA equals the pinned --iaca {self.pinned_iaca}", same_certificate,
                  {"pinned sha256": pinned.fingerprint(hashes.SHA256()).hex(), "published sha256": fingerprint})
            if not same_certificate:
                self.iaca_path = None
                return
            self.iaca_path = self.out / "iaca.pinned.pem"
            self.iaca_path.write_bytes(pinned.public_bytes(serialization.Encoding.PEM))
        dsc_path = self.out / "dsc.pem"
        dsc_path.write_bytes(self.dsc.public_bytes(serialization.Encoding.PEM))
        # An operator IACA names the public host in its CRL distribution point; a run against another URL (a local stack
        # before it goes public) fetches the same path from that URL, and says so.
        url = dp
        dp_url, base_url = urllib.parse.urlparse(dp), urllib.parse.urlparse(self.base)
        if (dp_url.scheme, dp_url.netloc) != (base_url.scheme, base_url.netloc):
            url = self.base + dp_url.path
        s, h, crl = call("GET", url, binary=True)
        crl_path = self.out / "iaca.crl"
        crl_path.write_bytes(crl if s == 200 else b"")
        code, output = run_openssl("crl", "-inform", "DER", "-in", str(crl_path), "-CAfile", str(self.iaca_path), "-noout")
        check("CRL at the Document Signer's distribution point: openssl crl -CAfile <IACA> verifies it",
              s == 200 and h.get("content-type", "").startswith("application/pkix-crl") and code == 0 and "verify OK" in output,
              {"url": url} | ({"distribution point": dp} if url != dp else {}) | {"status": s, "openssl": output})
        crl_pem = self.out / "iaca.crl.pem"
        run_openssl("crl", "-inform", "DER", "-in", str(crl_path), "-out", str(crl_pem))
        code, output = run_openssl("verify", "-x509_strict", "-crl_check", "-CAfile", str(self.iaca_path),
                                   "-CRLfile", str(crl_pem), str(dsc_path))
        check("Document Signer: openssl verify -x509_strict -crl_check under the IACA and its CRL", code == 0 and output.endswith("OK"), output)

    def status(self, mso):
        """The MSO's status entry and its Token Status List, held to `--expect-status` (F-21 review round 1).

        The demo issues no status until M-11 (the only list it can write is signed outside the IACA, which Paradym
        rejects, G23; ISO/IEC 18013-5 makes `status` optional), so `--expect-status absent` is the default - and a run
        against a stack that restored the block says `present`, which fails here if the restore did not take. A present
        entry is shape-checked before anything is fetched, so a malformed one is a failure and not a skip."""
        entry = mso["status"]["status_list"] if has_status(mso) else None
        if entry is None:
            if self.expect_status == "present":
                check("MSO status entry matches --expect-status present (M-11 restored)", False,
                      {"expect-status": "present", "status": mso.get("status") if isinstance(mso, dict) else mso})
            else:
                check("MSO carries no status entry (status disabled on this demo until M-11)", True,
                      mso.get("status") if isinstance(mso, dict) else mso)
            return
        if self.expect_status != "present":
            check("MSO status entry matches --expect-status absent (status disabled on this demo until M-11)", False,
                  {"expect-status": self.expect_status, "status": mso["status"]})
        else:
            check("MSO status entry matches --expect-status present (M-11 restored)", True, entry)
        problems = status_entry_problems(mso)
        if not check("MSO status.status_list {idx: uint, uri: tstr} (Token Status List)", not problems,
                     problems or entry):
            return
        name = ("status list served as statuslist+jwt, signature verifies with its x5c, sub is the uri, iat, "
                "exp (Certify policy), bit clear")
        s, h, token = call("GET", entry["uri"])
        try:
            header = jwt.get_unverified_header(token)
            leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
            # time claims are checked below, against one clock, with their values in the report
            payload = jwt.decode(token, leaf.public_key(), algorithms=[header["alg"]],
                                 options={"verify_aud": False, "verify_exp": False, "verify_iat": False, "verify_nbf": False})
        except Exception as e:  # noqa: BLE001 - reported as the check's detail
            check(name, False, {"status": s, "error": str(e)})
            return
        problems = status_list_problems(payload, entry["uri"], entry["idx"], time.time())
        check(name, s == 200 and header.get("typ") == "statuslist+jwt" and not problems,
              {"content-type": h.get("content-type"), "typ": header.get("typ"), "problems": problems} if problems or s != 200
              else {"typ": header.get("typ"), "sub": payload.get("sub"), "iat": payload.get("iat"), "exp": payload.get("exp")})

    # ---------------------------------------------------------------------------------------------- the rest
    def notification(self, issued):
        endpoint = self.metadata.get("notification_endpoint")
        headers = {"Authorization": "Bearer " + issued["token"]["access_token"]}
        s, _, body = call("POST", endpoint, {"notification_id": issued["notification_id"], "event": "credential_accepted"}, headers)
        check("notification credential_accepted: 204", s == 204, {"status": s, "body": body} if s != 204 else "")

    def replay(self, issued):
        s, _, body = self.credential(issued["token"], ec.generate_private_key(ec.SECP256R1()), issued["nonce"])
        check("nonce replay refused: invalid_nonce", s == 400 and isinstance(body, dict) and body.get("error") == "invalid_nonce", body)

    def unknown_subject(self):
        ok, offer, detail = self.offer(True, subject="mdl-demo-unknown")
        token, _ = self.token(offer) if ok else (None, None)
        if token is None:
            check("unknown subject refused: credential_request_denied", False, detail)
            return
        nonce, _ = self.nonce()
        s, _, body = self.credential(token, ec.generate_private_key(ec.SECP256R1()), nonce)
        check("unknown subject refused: credential_request_denied", s == 400 and isinstance(body, dict)
              and body.get("error") == "credential_request_denied", {"status": s, "body": body})

    def admin_guard(self):
        # certify-nginx's allow-list (M-12): an admin API, a keymanager controller and springdoc, as from the public
        # host; docs/design/tools/check-public-guard.sh covers the whole list against a stub upstream
        statuses = {}
        for method, path in (("GET", "/v2/credential-configurations"), ("POST", "/jwtSign"), ("GET", "/v3/api-docs")):
            statuses[f"{method} {path}"], _, _ = call(method, self.certify + path, headers={"CF-Ray": "mdl-smoke"},
                                                     **({"body": {}} if method == "POST" else {}))
        check("admin, keymanager and springdoc paths refused for a public request (certify-nginx, M-12)",
              all(s == 403 for s in statuses.values()), statuses)

    def run(self):
        if not check(f"holders.json has the record {self.subject}", self.holders is not None and self.subject in self.holders,
                     f"{self.holders_path} " + ("not found" if self.holders is None else f"has {sorted(self.holders)}")):
            return
        by_reference, by_value = self.offers()
        if not (by_reference and by_value and self.discovery()):
            return
        p256 = self.holder_run("P-256 holder", by_reference, ec.generate_private_key(ec.SECP256R1()))
        ed = self.holder_run("Ed25519 holder (DPoP)", by_value, ed25519.Ed25519PrivateKey.generate(),
                             dpop_key=ec.generate_private_key(ec.SECP256R1()))
        if p256:
            mso = self.inspect(p256)
            self.status(mso)
            self.notification(p256)
            self.replay(p256)
        if ed:
            self.inspect(ed)
        self.unknown_subject()
        self.admin_guard()


def table():
    width = max(len(step) for step, _, _ in results)
    rule = "+-----+-" + "-" * width + "-+------+"
    print("\n" + rule)
    print(f"| {'#':>3} | {'step'.ljust(width)} | res  |")
    print(rule)
    for i, (step, ok, _) in enumerate(results, 1):
        print(f"| {i:>3} | {step.ljust(width)} | {'PASS' if ok else 'FAIL'} |")
    print(rule)
    failed = [r for r in results if not r[1]]
    print(f"{len(results)} checks, {len(failed)} failed")
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser(prog="smoke.py --mdl", description="mDL smoke run against certify-nginx (the public URL)")
    parser.add_argument("base", nargs="?", default="http://localhost:8091", help="CERTIFY_PUBLIC_URL (default http://localhost:8091)")
    parser.add_argument("--configuration", default=MDL_DOCTYPE, help="credential configuration id (default org.iso.18013.5.1.mDL)")
    parser.add_argument("--subject", default="mdl-demo-1", help="holders.json record (default mdl-demo-1)")
    parser.add_argument("--expect-status", choices=("absent", "present"), default="absent",
                        help="the MSO's status entry the configuration is expected to produce: absent until the M-11 "
                             "restore lands (the demo's default), present on a stack that restored the block")
    parser.add_argument("--out", help="directory for the credentials, holder keys, IACA and CRL (default: a new temporary one)")
    parser.add_argument("--iaca", type=Path, help="the operator's offline IACA (PEM, mdl-operator): the published IACA must be "
                                                   "this certificate, and the mDLs are verified against it")
    parser.add_argument("--holders", type=Path, default=HOLDERS, help=f"the holders.json the stack serves (default {HOLDERS})")
    args = parser.parse_args(argv)
    if args.iaca is not None and not args.iaca.is_file():
        parser.error(f"--iaca {args.iaca}: no such file")
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="mdl-smoke-"))
    out.mkdir(parents=True, exist_ok=True)
    print(f"mDL smoke against {args.base}, configuration {args.configuration}, subject {args.subject}; files in {out}")
    Smoke(args.base, args.configuration, args.subject, out, args.iaca, args.holders, args.expect_status).run()
    return 1 if table() or not results else 0


if __name__ == "__main__":
    sys.exit(main())
