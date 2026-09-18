#!/usr/bin/env python3
"""Smoke run of a running Certify (docs/design/VALIDATE.md, section 6d): the pre-authorized code flow with self-made
holder proofs on both the compatibility surface and the new /oid4vci surface, the notification endpoint, nonce replay,
the v2 configuration API and did.json.

    python3 -m venv .venv && .venv/bin/pip install pyjwt cryptography
    .venv/bin/python docs/design/tools/smoke.py http://localhost:8090/v1/certify FarmerCredential
"""
import json, sys, time, urllib.request, urllib.parse, urllib.error
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090/v1/certify"
CONFIG = sys.argv[2] if len(sys.argv) > 2 else "FarmerCredential"
results = []

def call(method, path, body=None, headers=None, form=None):
    url = path if path.startswith("http") else BASE + path
    data = None
    h = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, dict(r.headers), (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, dict(e.headers), (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)

def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (": " + str(detail)[:300] if detail else ""))

def proof(aud, nonce):
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_numbers()
    import base64
    def b64(n): return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64(pub.x), "y": b64(pub.y)}
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return jwt.encode({"aud": aud, "iat": int(time.time()), "nonce": nonce}, pem, algorithm="ES256",
                      headers={"typ": "openid4vci-proof+jwt", "jwk": jwk})

# 1. metadata on both surfaces
s, _, legacy = call("GET", "/.well-known/openid-credential-issuer")
check("legacy metadata", s == 200 and CONFIG in legacy.get("credential_configurations_supported", {}), legacy.get("credential_issuer"))
s, _, new = call("GET", "/oid4vci/.well-known/openid-credential-issuer")
check("new-surface metadata", s == 200 and new.get("credential_issuer", "").endswith("/oid4vci") and "notification_endpoint" in new and "batch_credential_issuance" in new,
      {k: new.get(k) for k in ("credential_issuer", "nonce_endpoint", "notification_endpoint", "batch_credential_issuance")})
s, _, asmeta = call("GET", "/.well-known/oauth-authorization-server")
token_endpoint = asmeta.get("token_endpoint") if isinstance(asmeta, dict) else None
check("authorization server metadata", s == 200 and token_endpoint is not None, token_endpoint)

# 2. offer + token
s, _, offer = call("POST", "/pre-authorized-data", {"credential_configuration_id": CONFIG, "claims": {"fullName": "Gorge Cooper", "phone": "9876543210", "dateOfBirth": "1990-05-25", "gender": "Male"}, "expires_in": 600, "tx_code": "1234"})
uri = offer.get("credential_offer_uri", "") if isinstance(offer, dict) else ""
check("credential offer created", s == 200 and "credential_offer" in uri, uri[:120])
offer_url = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query).get("credential_offer_uri", [""])[0]
if offer_url:
    s, _, offer_doc = call("GET", offer_url.replace("http://certify-nginx:80", BASE.rsplit("/v1", 1)[0]))
else:
    offer_doc = {}
grants = offer_doc.get("grants", {}) if isinstance(offer_doc, dict) else {}
code = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {}).get("pre-authorized_code")
check("credential offer fetched", bool(code), offer_doc if not code else "pre-authorized code received")

def token():
    s, _, tok = call("POST", token_endpoint, form={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": code, "tx_code": "1234"})
    return s, tok

s, tok = token()
access = tok.get("access_token") if isinstance(tok, dict) else None
check("access token", s == 200 and access is not None, {k: tok.get(k) for k in ("token_type", "expires_in", "c_nonce")} if isinstance(tok, dict) else tok)
auth = {"Authorization": "Bearer " + (access or "")}

# 3. legacy surface
s, _, n = call("POST", "/nonce")
legacy_nonce = n.get("c_nonce") if isinstance(n, dict) else None
check("legacy nonce", s == 200 and legacy_nonce is not None)
s, _, cred = call("POST", "/issuance/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(legacy["credential_issuer"], legacy_nonce)]}}, auth)
legacy_vc = (cred.get("credentials") or [{}])[0].get("credential") if isinstance(cred, dict) else None
check("legacy /issuance/credential", s == 200 and isinstance(legacy_vc, dict) and "proof" in legacy_vc,
      {"status": s, "type": legacy_vc.get("type") if isinstance(legacy_vc, dict) else cred, "vm": (legacy_vc or {}).get("proof", {}).get("verificationMethod") if isinstance(legacy_vc, dict) else None})

# 4. new surface: nonce, credential, notification, replay
s, _, n = call("POST", "/oid4vci/nonce")
new_nonce = n.get("c_nonce") if isinstance(n, dict) else None
check("new-surface nonce", s == 200 and new_nonce is not None)
s, _, cred2 = call("POST", "/oid4vci/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(new["credential_issuer"], new_nonce)]}}, auth)
new_vc = (cred2.get("credentials") or [{}])[0].get("credential") if isinstance(cred2, dict) else None
notification_id = cred2.get("notification_id") if isinstance(cred2, dict) else None
check("new /oid4vci/credential", s == 200 and isinstance(new_vc, dict) and "proof" in new_vc and notification_id,
      {"status": s, "type": new_vc.get("type") if isinstance(new_vc, dict) else cred2, "notification_id": notification_id})
s, _, note = call("POST", "/oid4vci/notification", {"notification_id": notification_id, "event": "credential_accepted"}, auth)
check("notification accepted", s == 204, s if s != 204 else "")
s, _, note = call("POST", "/oid4vci/notification", {"notification_id": "no-such-id", "event": "credential_accepted"}, auth)
check("notification unknown id", s == 400 and note.get("error") == "invalid_notification_id", note)
s, _, replay = call("POST", "/oid4vci/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(new["credential_issuer"], new_nonce)]}}, auth)
check("nonce replay refused", s == 400 and isinstance(replay, dict) and replay.get("error") == "invalid_nonce", replay)
s, _, unauth = call("POST", "/oid4vci/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(new["credential_issuer"], new_nonce)]}})
check("new surface without token", s == 401, {"status": s, "body": unauth})

# 5. DID document names the verification methods
s, _, did = call("GET", "/.well-known/did.json")
vms = [m.get("id") for m in did.get("verificationMethod", [])] if isinstance(did, dict) else []
vm = (new_vc or {}).get("proof", {}).get("verificationMethod") if isinstance(new_vc, dict) else None
check("did.json lists the proof's verification method", s == 200 and vm in vms, {"id": did.get("id") if isinstance(did, dict) else did, "vm": vm})

# 6. v2 configuration API through the real security chain
s, _, listing = call("GET", "/v2/credential-configurations")
check("v2 list", s == 200 and isinstance(listing, list) and any(c.get("id") == CONFIG for c in listing), {"status": s, "count": len(listing) if isinstance(listing, list) else listing})
s, _, one = call("GET", "/v2/credential-configurations/" + CONFIG)
check("v2 get", s == 200 and isinstance(one, dict) and one.get("configVersion") == 2 and one.get("template", {}).get("version") == 1,
      {k: one.get(k) for k in ("format", "configVersion", "issuanceStrategy")} if isinstance(one, dict) else one)
s, _, prev = call("POST", "/v2/credential-configurations/" + CONFIG + "/preview", {"claims": {"fullName": "Preview Person", "phone": "0", "dateOfBirth": "2000-01-01"}})
check("v2 preview", s == 200 and isinstance(prev, dict) and prev.get("format") and "credential" in prev,
      {"status": s, "keys": list(prev.get("credential", {}).keys())[:6] if isinstance(prev, dict) and isinstance(prev.get("credential"), dict) else prev})

# 7. deprecation headers on the compatibility credential endpoint (the legacy /nonce stays, docs/design/09)
s, _, n = call("POST", "/nonce")
s, h, _ = call("POST", "/issuance/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(legacy["credential_issuer"], n.get("c_nonce", ""))]}}, auth)
print("INFO legacy /issuance/credential deprecation headers (P1-11f on hold):", {k: v for k, v in h.items() if k.lower() in ("deprecation", "sunset", "link")} or "none")

failed = [r for r in results if not r[1]]
print("\n%d checks, %d failed" % (len(results), len(failed)))
sys.exit(1 if failed else 0)
