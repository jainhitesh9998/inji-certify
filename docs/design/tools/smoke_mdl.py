#!/usr/bin/env python3
"""mDL smoke run of a running Certify with the compose mdl profile (docs/design/20-mdl-issuer.md M-10, VALIDATE.md 6f).

Plays a wallet against the public URL (certify-nginx, CERTIFY_PUBLIC_URL), only through what the offer and the
metadata say:

  1. pre-authorized offers for the mDL configuration with "issuer": "oid4vci", by reference and by value;
  2. issuer metadata at the OpenID4VCI 1.0 section 12.2.2 location derived from the offer's credential_issuer, and the
     authorization server metadata (RFC 8414) of its authorization server;
  3. a P-256 holder: token (anonymous pre-authorized grant, Bearer), nonce, credential with an ES256 jwt proof,
     notification, nonce replay refused;
  4. an Ed25519 holder: a DPoP-bound token, nonce, credential with an EdDSA jwt proof (ISO/IEC 18013-5 9.1.5.2);
  5. every mDL read back: elements equal the holders.json record, MSO docType, x5chain without the anchor, the Token
     Status List entry served with its bit clear; then docs/design/tools/verify_mdoc.py (pymdoccbor, a verifier
     Certify does not maintain) with --doctype, --holder (the proof key) and --iaca downloaded from
     /v1/certify/mdoc/iaca/<id>.pem, the IACA named by the Document Signer's CRL distribution point;
  6. the CRL at that distribution point verified with `openssl crl -CAfile`, and the Document Signer with
     `openssl verify -x509_strict -crl_check`;
  7. refusals: an offer for a subject holders.json does not know ends in credential_request_denied, and an admin API
     is refused for a request that looks public (the nginx guard of M-12a).

    python3.12 -m venv .venv && .venv/bin/pip install -r docs/design/tools/requirements-verify.txt pyjwt
    .venv/bin/python docs/design/tools/smoke.py --mdl http://localhost:8091

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
    """IssuerSigned -> (raw CBOR, elements by identifier, MSO, x5chain certificates as received)."""
    raw = b64url_decode(encoded)
    issuer_signed = cbor2.loads(raw)
    issuer_auth = issuer_signed["issuerAuth"]
    if isinstance(issuer_auth, cbor2.CBORTag):
        issuer_auth = issuer_auth.value
    payload = cbor2.loads(issuer_auth[2])
    mso = cbor2.loads(payload.value if isinstance(payload, cbor2.CBORTag) else payload)
    elements = {}
    for item in issuer_signed["nameSpaces"].get(MDL_NAMESPACE, []):
        decoded = cbor2.loads(item.value)
        elements[decoded["elementIdentifier"]] = decoded["elementValue"]
    chain = issuer_auth[1].get(X5CHAIN)
    chain = [chain] if isinstance(chain, bytes) else list(chain or [])
    return raw, elements, mso, [x509.load_der_x509_certificate(c) for c in chain]


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
    def __init__(self, base, configuration, subject, out):
        self.base = base.rstrip("/")
        self.certify = self.base + "/v1/certify"
        self.configuration = configuration
        self.subject = subject
        self.out = out
        self.holders = json.loads(HOLDERS.read_text()) if HOLDERS.exists() else {}
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
        check("offer by reference: credential_issuer is the /oid4vci identifier",
              ok and code_ok and (self.issuer or "").endswith("/v1/certify/oid4vci") and self.issuer.startswith(self.base),
              {"credential_issuer": self.issuer, "offer": detail} if ok else detail)
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
              s == 200 and self.as_metadata.get("issuer") == servers[0] and self.as_metadata.get("token_endpoint")
              and PRE_AUTH in self.as_metadata.get("grant_types_supported", [])
              and self.as_metadata.get("pre-authorized_grant_anonymous_access_supported") is True,
              {"url": as_url, "status": s} | {k: self.as_metadata.get(k) for k in ("issuer", "token_endpoint", "pre-authorized_grant_anonymous_access_supported")})
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
        raw, elements, mso, chain = decode_mdoc(issued["encoded"])
        name = label.split(" ")[0].lower()
        mdoc_path = self.out / f"{name}.mdoc"
        holder_path = self.out / f"{name}.holder.jwk"
        mdoc_path.write_bytes(raw)
        holder_path.write_text(json.dumps(public_jwk(issued["holder"])))
        record = self.holders.get(self.subject, {})
        portrait = HOLDERS.parent / record["portrait"] if record.get("portrait") else None
        mismatched = [k for k in ("family_name", "given_name", "document_number", "issuing_country", "issuing_authority",
                                  "un_distinguishing_sign", "nationality", "resident_city", "sex", "age_over_18")
                      if k in record and elements.get(k) != record[k]]
        if portrait and portrait.exists() and elements.get("portrait") != portrait.read_bytes():
            mismatched.append("portrait")
        privileges = [p.get("vehicle_category_code") for p in elements.get("driving_privileges") or []]
        if record and privileges != [p["vehicle_category_code"] for p in record.get("driving_privileges", [])]:
            mismatched.append("driving_privileges")
        missing = [e for e in MANDATORY if e not in elements]
        check(f"{label}: every Table 5 mandatory element, values equal holders.json[{self.subject}]",
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
        dsc_path = self.out / "dsc.pem"
        dsc_path.write_bytes(self.dsc.public_bytes(serialization.Encoding.PEM))
        s, h, crl = call("GET", dp, binary=True)
        crl_path = self.out / "iaca.crl"
        crl_path.write_bytes(crl if s == 200 else b"")
        code, output = run_openssl("crl", "-inform", "DER", "-in", str(crl_path), "-CAfile", str(self.iaca_path), "-noout")
        check("CRL at the Document Signer's distribution point: openssl crl -CAfile <IACA> verifies it",
              s == 200 and h.get("content-type", "").startswith("application/pkix-crl") and code == 0 and "verify OK" in output,
              {"url": dp, "status": s, "openssl": output})
        crl_pem = self.out / "iaca.crl.pem"
        run_openssl("crl", "-inform", "DER", "-in", str(crl_path), "-out", str(crl_pem))
        code, output = run_openssl("verify", "-x509_strict", "-crl_check", "-CAfile", str(self.iaca_path),
                                   "-CRLfile", str(crl_pem), str(dsc_path))
        check("Document Signer: openssl verify -x509_strict -crl_check under the IACA and its CRL", code == 0 and output.endswith("OK"), output)

    def status(self, mso):
        entry = mso.get("status", {}).get("status_list", {}) if isinstance(mso.get("status"), dict) else {}
        if not check("MSO status.status_list {idx, uri} (Token Status List)", isinstance(entry.get("idx"), int) and isinstance(entry.get("uri"), str), entry):
            return
        s, h, token = call("GET", entry["uri"])
        try:
            header = jwt.get_unverified_header(token)
            leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
            payload = jwt.decode(token, leaf.public_key(), algorithms=[header["alg"]], options={"verify_aud": False})
            bit = token_status_bit(payload["status_list"]["lst"], entry["idx"])
        except Exception as e:  # noqa: BLE001 - reported as the check's detail
            check("status list served as statuslist+jwt, signature verifies with its x5c, bit clear", False, {"status": s, "error": str(e)})
            return
        check("status list served as statuslist+jwt, signature verifies with its x5c, bit clear",
              s == 200 and header.get("typ") == "statuslist+jwt" and payload.get("sub") == entry["uri"] and bit == 0,
              {"content-type": h.get("content-type"), "typ": header.get("typ"), "bit": bit})

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
        s, _, _ = call("GET", self.certify + "/v2/credential-configurations", headers={"CF-Ray": "mdl-smoke"})
        check("admin API refused for a public request (certify-nginx, M-12a)", s == 403, {"status": s})

    def run(self):
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
    parser.add_argument("--out", help="directory for the credentials, holder keys, IACA and CRL (default: a new temporary one)")
    args = parser.parse_args(argv)
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="mdl-smoke-"))
    out.mkdir(parents=True, exist_ok=True)
    print(f"mDL smoke against {args.base}, configuration {args.configuration}, subject {args.subject}; files in {out}")
    Smoke(args.base, args.configuration, args.subject, out).run()
    return 1 if table() or not results else 0


if __name__ == "__main__":
    sys.exit(main())
