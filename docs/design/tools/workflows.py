#!/usr/bin/env python3
"""Every issuance workflow against a running Certify (docs/design/VALIDATE.md, section 6e), as a wallet, an issuer
coordinator and an operator would drive them: the pre-authorized code flow on the compatibility, draft-13 and
/oid4vci surfaces; the authorization code flow of Certify's own AS with PAR, PKCE, client attestation and DPoP; key
attestations on jwt proofs and the attestation proof type; batch issuance; SD-JWT VC under the x509-file dev CA with a
Token Status List and its revocation; mDoc; Bitstring status revocation through today's API and through VC-API;
VC-API issuance; the v2 configuration API; did.json; deprecation headers.

The stack must run the `workflows` profile (docs/design/VALIDATE.md 6e lists the properties: an AS client `wallet`
with fixed subject 2154189532, attesters, x509-file dev keys `sdjwt-es256` and `mdoc-es256`, VC-API client
`coordinator`/`s3cret`, a 10 s status list batch).

    python3 -m venv .venv && .venv/bin/pip install pyjwt cryptography cbor2
    .venv/bin/python docs/design/tools/workflows.py https://certify.example/v1/certify FarmerCredential 2154189532 attester.pem
"""
import base64, gzip, hashlib, json, os, secrets, socket, sys, time, urllib.error, urllib.parse, urllib.request, zlib
from pathlib import Path

# urllib tries every address a host resolves to in order; behind Cloudflare the IPv6 ones can hang for 20 s each
# before the IPv4 fallback, so resolve IPv4 only (curl's happy-eyeballs hides this).
_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda host, port, family=0, type=0, proto=0, flags=0: _getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090/v1/certify"
CONFIG = sys.argv[2] if len(sys.argv) > 2 else "FarmerCredential"
SUBJECT = sys.argv[3] if len(sys.argv) > 3 else "2154189532"
ATTESTER_PEM = sys.argv[4] if len(sys.argv) > 4 else None
REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "certify-service/src/test/resources/goldens/templates"
results = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(method, path, body=None, headers=None, form=None, raw=None):
    url = path if path.startswith("http") else BASE + path
    data = None
    h = dict(headers or {})
    h.setdefault("User-Agent", "certify-workflows/1.0")  # Cloudflare answers 1010 to Python's default agent
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw is not None:
        data = raw.encode()
        h.setdefault("Content-Type", "application/json")
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with OPENER.open(req, timeout=60) as r:
            text = r.read().decode()
            return r.status, dict(r.headers), parse(text)
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        return e.code, dict(e.headers), parse(text)


def parse(text):
    t = text.strip()
    if t.startswith(("{", "[")):
        try:
            return json.loads(t)
        except ValueError:
            return text
    return text


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (": " + str(detail)[:400] if detail else ""), flush=True)
    return ok


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_jwk(key, kid=None):
    pub = key.public_key().public_numbers()
    j = {"kty": "EC", "crv": "P-256", "x": b64url(pub.x.to_bytes(32, "big")), "y": b64url(pub.y.to_bytes(32, "big"))}
    if kid:
        j["kid"] = kid
    return j


def thumbprint(jwk):
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


def proof(aud, nonce, key=None, extra_headers=None):
    key = key or new_key()
    headers = {"typ": "openid4vci-proof+jwt", "jwk": public_jwk(key)}
    headers.update(extra_headers or {})
    return jwt.encode({"aud": aud, "iat": int(time.time()), "nonce": nonce}, pem(key), algorithm="ES256", headers=headers)


def dpop(key, htm, htu, access_token=None):
    claims = {"jti": secrets.token_urlsafe(16), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode()).digest())
    return jwt.encode(claims, pem(key), algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})


ATTESTER = None
if ATTESTER_PEM and os.path.exists(ATTESTER_PEM):
    ATTESTER = serialization.load_pem_private_key(open(ATTESTER_PEM, "rb").read(), password=None)


def client_attestation(client_id, instance_key, attester=None):
    attester = attester or ATTESTER
    now = int(time.time())
    attestation = jwt.encode({"iss": "https://wallet-provider.example", "sub": client_id, "iat": now, "exp": now + 600,
                              "cnf": {"jwk": public_jwk(instance_key)}}, pem(attester), algorithm="ES256",
                             headers={"typ": "oauth-client-attestation+jwt", "kid": "wallet-provider-1"})
    return attestation


def client_attestation_pop(client_id, instance_key, audience):
    now = int(time.time())
    return jwt.encode({"iss": client_id, "aud": audience, "jti": secrets.token_urlsafe(12), "iat": now, "exp": now + 300},
                      pem(instance_key), algorithm="ES256", headers={"typ": "oauth-client-attestation-pop+jwt"})


def key_attestation(keys, nonce, key_storage=("iso_18045_high",), exp=True, attester=None):
    attester = attester or ATTESTER
    now = int(time.time())
    claims = {"iss": "https://wallet-provider.example", "iat": now, "attested_keys": [public_jwk(k) for k in keys],
              "key_storage": list(key_storage), "user_authentication": ["iso_18045_high"]}
    if exp:
        claims["exp"] = now + 600
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(claims, pem(attester), algorithm="ES256", headers={"typ": "key-attestation+jwt", "kid": "wallet-provider-1"})


def jwt_parts(compact):
    header, payload = compact.split(".")[:2]
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(payload))


def bitstring_bit(encoded_list, index):
    raw = gzip.decompress(b64url_decode(encoded_list[1:]))  # multibase 'u' prefix
    return (raw[index // 8] >> (7 - index % 8)) & 1


def token_status_bit(lst, index):
    raw = zlib.decompress(b64url_decode(lst))
    return (raw[index // 8] >> (index % 8)) & 1  # bits=1, least significant bit first


def offer_and_token(configuration_id, subject=SUBJECT, dpop_key=None):
    """The pre-authorized code flow: offer, offer document, token (DPoP-bound when a key is given)."""
    s, _, offer = call("POST", "/pre-authorized-data", {"credential_configuration_id": configuration_id, "expires_in": 600, "tx_code": "1234", "subject": subject})
    uri = offer.get("credential_offer_uri", "") if isinstance(offer, dict) else ""
    offer_url = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query).get("credential_offer_uri", [""])[0]
    if not offer_url:
        return None, {"offer": offer}
    s, _, doc = call("GET", offer_url)
    code = doc.get("grants", {}).get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {}).get("pre-authorized_code") if isinstance(doc, dict) else None
    if not code:
        return None, {"offer_document": doc}
    headers = {}
    if dpop_key:
        headers["DPoP"] = dpop(dpop_key, "POST", TOKEN_ENDPOINT)
    s, _, tok = call("POST", TOKEN_ENDPOINT, form={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": code, "tx_code": "1234"}, headers=headers)
    return (tok if s == 200 and isinstance(tok, dict) else None), tok


def bearer(tok):
    return {"Authorization": (tok.get("token_type", "Bearer")) + " " + tok["access_token"]}


def issue_new(tok, configuration_id, proofs, dpop_key=None):
    headers = bearer(tok)
    if dpop_key:
        headers["DPoP"] = dpop(dpop_key, "POST", NEW_META["credential_endpoint"], tok["access_token"])
    return call("POST", "/oid4vci/credential", {"credential_configuration_id": configuration_id, "proofs": proofs}, headers)


def nonce(path="/oid4vci/nonce"):
    s, _, n = call("POST", path)
    return n.get("c_nonce") if isinstance(n, dict) else None


def wait_for(description, predicate, seconds=75):
    for _ in range(seconds // 5):
        if predicate():
            return True
        time.sleep(5)
    return predicate()


def v2_config(body):
    s, _, existing = call("GET", "/v2/credential-configurations/" + body["id"])
    if s == 200:
        return True, existing
    s, _, created = call("POST", "/v2/credential-configurations", body)
    return s == 201, created


def template(name, replacements=None):
    text = (TEMPLATES / name).read_text()
    for old, new in (replacements or {}).items():
        text = text.replace(old, new)
    return text


# ------------------------------------------------------------------------------------------------ 1. discovery
s, _, LEGACY_META = call("GET", "/.well-known/openid-credential-issuer")
check("compatibility metadata", s == 200 and CONFIG in LEGACY_META.get("credential_configurations_supported", {}), LEGACY_META.get("credential_issuer") if isinstance(LEGACY_META, dict) else LEGACY_META)
s, _, NEW_META = call("GET", "/oid4vci/.well-known/openid-credential-issuer")
check("new-surface metadata", s == 200 and NEW_META.get("credential_issuer", "").endswith("/oid4vci") and "nonce_endpoint" in NEW_META and "notification_endpoint" in NEW_META,
      {k: NEW_META.get(k) for k in ("credential_issuer", "nonce_endpoint", "batch_credential_issuance")} if isinstance(NEW_META, dict) else NEW_META)
s, _, AS_META = call("GET", "/.well-known/oauth-authorization-server")
TOKEN_ENDPOINT = AS_META.get("token_endpoint") if isinstance(AS_META, dict) else None
AS_ISSUER = AS_META.get("issuer") if isinstance(AS_META, dict) else None
check("authorization server metadata (PAR, attestation, DPoP advertised)", s == 200 and TOKEN_ENDPOINT and AS_META.get("pushed_authorization_request_endpoint")
      and "attest_jwt_client_auth" in AS_META.get("token_endpoint_auth_methods_supported", []) and AS_META.get("dpop_signing_alg_values_supported"),
      {k: AS_META.get(k) for k in ("issuer", "pushed_authorization_request_endpoint", "token_endpoint_auth_methods_supported", "dpop_signing_alg_values_supported")} if isinstance(AS_META, dict) else AS_META)
s, _, DID = call("GET", "/.well-known/did.json")
ISSUER_DID = DID.get("id") if isinstance(DID, dict) else None
check("did.json", s == 200 and ISSUER_DID and DID.get("verificationMethod"), ISSUER_DID)
if not (TOKEN_ENDPOINT and isinstance(NEW_META, dict) and ISSUER_DID):
    print("discovery failed; stopping")
    sys.exit(1)
NEW_ISSUER = NEW_META["credential_issuer"]
LEGACY_ISSUER = LEGACY_META["credential_issuer"]

# ------------------------------------------------------------------------------------------------ 2. configurations for the run (v2 API)
FARMER = call("GET", "/v2/credential-configurations/" + CONFIG)[2]
farmer_template = FARMER.get("template", {}).get("content") if isinstance(FARMER, dict) else None
check("v2 get of the farmer configuration", isinstance(FARMER, dict) and bool(farmer_template), {k: FARMER.get(k) for k in ("format", "issuanceStrategy", "configVersion")} if isinstance(FARMER, dict) else FARMER)
CONTEXT_V1 = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
ED_SIGNING = {"alias": "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg": "EdDSA", "cryptosuite": "Ed25519Signature2020", "didUrl": ISSUER_DID}
DISPLAY = lambda name: {"display": [{"name": name, "locale": "en"}], "order": ["fullName"]}
CLAIMS = {"fullName": {"display": [{"name": "Full name", "locale": "en"}]}}
SDJWT_ID, MDL_ID, ATTESTED_ID, SUPPLIED_ID = "WorkflowSdJwtCredential", "WorkflowMdlCredential", "WorkflowAttestedCredential", "WorkflowSuppliedCredential"

ok, out = v2_config({"id": SDJWT_ID, "scope": "wf_sdjwt", "format": "dc+sd-jwt",
                     "formatConfig": {"vct": SDJWT_ID, "sdClaims": ["$.fullName"], "sdJwtClaims": CLAIMS},
                     "signing": {"provider": "x509-file", "alias": "sdjwt-es256", "alg": "ES256", "x5c": "without-anchor"},
                     "status": {"mechanism": "TokenStatusList", "purposes": ["revocation"]},
                     "template": {"content": template("golden-sdjwt.vm", {"${city}": "${villageOrTown}"})}, "display": DISPLAY(SDJWT_ID)})
check("v2 create: SD-JWT VC under the dev CA with a Token Status List", ok, out if not ok else "")
ok, out = v2_config({"id": MDL_ID, "scope": "wf_mdl", "format": "mso_mdoc",
                     "formatConfig": {"doctype": "org.iso.18013.5.1.mDL", "mdocClaims": {"org.iso.18013.5.1": {"family_name": CLAIMS["fullName"]}}},
                     "signing": {"provider": "x509-file", "alias": "mdoc-es256", "alg": "ES256", "x5c": "without-anchor"},
                     "template": {"content": template("golden-mdoc.vm", {"${city}": "${villageOrTown}"})}, "display": DISPLAY(MDL_ID)})
check("v2 create: mDoc under the dev CA", ok, out if not ok else "")
ok, out = v2_config({"id": ATTESTED_ID, "scope": "wf_attested", "format": "ldp_vc",
                     "formatConfig": {"context": CONTEXT_V1, "types": ["VerifiableCredential", ATTESTED_ID], "claims": CLAIMS},
                     "signing": ED_SIGNING, "template": {"content": farmer_template or template("golden-ldp.vm")}, "display": DISPLAY(ATTESTED_ID),
                     "protocol": {"cryptographicBindingMethodsSupported": ["did:jwk", "did:key"], "proofTypesSupported": {
                         "jwt": {"proof_signing_alg_values_supported": ["ES256"], "key_attestations_required": {"key_storage": ["iso_18045_high", "iso_18045_moderate"]}},
                         "attestation": {"proof_signing_alg_values_supported": ["ES256"]}}}})
check("v2 create: configuration requiring key attestations", ok, out if not ok else "")
CONTEXT_V2 = ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/suites/ed25519-2020/v1"]  # Bitstring status is attached to VC 2.0 documents
ok, out = v2_config({"id": SUPPLIED_ID, "scope": "wf_supplied", "format": "ldp_vc", "issuanceStrategy": "SUPPLIED",
                     "formatConfig": {"context": CONTEXT_V2, "types": ["VerifiableCredential", SUPPLIED_ID], "claims": CLAIMS},
                     "signing": ED_SIGNING, "status": {"mechanism": "BitstringStatusList", "purposes": ["revocation"]}, "display": DISPLAY(SUPPLIED_ID)})
check("v2 create: supplied-credential configuration for VC-API with Bitstring status", ok, out if not ok else "")
s, _, NEW_META = call("GET", "/oid4vci/.well-known/openid-credential-issuer")
check("metadata advertises the new configurations with key_attestations_required", all(c in NEW_META.get("credential_configurations_supported", {}) for c in (SDJWT_ID, MDL_ID, ATTESTED_ID, SUPPLIED_ID))
      and NEW_META["credential_configurations_supported"].get(ATTESTED_ID, {}).get("proof_types_supported", {}).get("jwt", {}).get("key_attestations_required"),
      sorted(NEW_META.get("credential_configurations_supported", {}).keys()))

# ------------------------------------------------------------------------------------------------ 3. pre-authorized code flow, three surfaces
tok, detail = offer_and_token(CONFIG)
check("pre-authorized code flow: token", tok is not None and jwt.decode(tok["access_token"], options={"verify_signature": False}).get("sub") == SUBJECT, detail if tok is None else {k: tok.get(k) for k in ("token_type", "expires_in")})
if tok is None:
    print("no token; stopping")
    sys.exit(1)
s, _, cred = call("POST", "/issuance/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(LEGACY_ISSUER, nonce("/nonce"))]}}, bearer(tok))
legacy_vc = (cred.get("credentials") or [{}])[0].get("credential") if isinstance(cred, dict) else None
check("compatibility surface: ldp_vc for the CSV subject", s == 200 and isinstance(legacy_vc, dict) and "proof" in legacy_vc and legacy_vc.get("credentialSubject", {}).get("fullName") == "Gorge Cooper",
      {"status": s, "subject": (legacy_vc or {}).get("credentialSubject") if isinstance(legacy_vc, dict) else cred})
s, h, _ = call("POST", "/issuance/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(LEGACY_ISSUER, nonce("/nonce"))]}}, bearer(tok))
check("compatibility surface carries Deprecation and Link headers", s == 200 and "deprecation" in {k.lower() for k in h} and "link" in {k.lower() for k in h}, {k: v for k, v in h.items() if k.lower() in ("deprecation", "sunset", "link")})
definition = LEGACY_META["credential_configurations_supported"][CONFIG].get("credential_definition", {})
s, _, d13 = call("POST", "/issuance/credential", {"format": "ldp_vc", "credential_definition": {"@context": definition.get("@context"), "type": definition.get("type")},
                                                   "proof": {"proof_type": "jwt", "jwt": proof(LEGACY_ISSUER, nonce("/nonce"))}}, bearer(tok))
check("draft-13 surface: 0.14.0 body answers a credential", s == 200 and isinstance(d13, dict) and isinstance(d13.get("credential"), dict) and "proof" in d13["credential"], {"status": s, "keys": list(d13.keys()) if isinstance(d13, dict) else d13})
s, _, cred2 = issue_new(tok, CONFIG, {"jwt": [proof(NEW_ISSUER, nonce())]})
new_vc = (cred2.get("credentials") or [{}])[0].get("credential") if isinstance(cred2, dict) else None
notification_id = cred2.get("notification_id") if isinstance(cred2, dict) else None
check("new surface: ldp_vc with notification_id", s == 200 and isinstance(new_vc, dict) and "proof" in new_vc and notification_id, {"status": s, "body": cred2 if s != 200 else notification_id})
vm = (new_vc or {}).get("proof", {}).get("verificationMethod") if isinstance(new_vc, dict) else None
check("did.json lists the proof's verification method", vm in [m.get("id") for m in DID.get("verificationMethod", [])], vm)
s, _, _ = call("POST", "/oid4vci/notification", {"notification_id": notification_id, "event": "credential_accepted"}, bearer(tok))
check("notification accepted", s == 204, s)
n = nonce()
s, _, batch = issue_new(tok, CONFIG, {"jwt": [proof(NEW_ISSUER, n), proof(NEW_ISSUER, n)]})
check("batch: two proofs, two credentials, two holders", s == 200 and isinstance(batch, dict) and len(batch.get("credentials", [])) == 2
      and batch["credentials"][0]["credential"]["credentialSubject"]["id"] != batch["credentials"][1]["credential"]["credentialSubject"]["id"], {"status": s, "count": len(batch.get("credentials", [])) if isinstance(batch, dict) else batch})
s, _, replay = issue_new(tok, CONFIG, {"jwt": [proof(NEW_ISSUER, n)]})
check("nonce replay refused", s == 400 and isinstance(replay, dict) and replay.get("error") == "invalid_nonce", replay)
s, _, unauth = call("POST", "/oid4vci/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(NEW_ISSUER, nonce())]}})
check("new surface without a token", s == 401, s)

# ------------------------------------------------------------------------------------------------ 4. authorization code flow: PAR, PKCE, client attestation, DPoP
instance_key = new_key()
verifier = secrets.token_urlsafe(48)
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = secrets.token_urlsafe(8)
par_form = {"client_id": "wallet", "response_type": "code", "redirect_uri": "https://wallet.example/cb", "scope": FARMER.get("scope", "sample_vc_ldp") if isinstance(FARMER, dict) else "",
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
attested_headers = {} if ATTESTER is None else {"OAuth-Client-Attestation": client_attestation("wallet", instance_key), "OAuth-Client-Attestation-PoP": client_attestation_pop("wallet", instance_key, AS_ISSUER)}
s, _, par = call("POST", "/oauth/par", form=par_form, headers=attested_headers)
request_uri = par.get("request_uri") if isinstance(par, dict) else None
check("PAR" + (" with client attestation" if attested_headers else ""), s == 201 and request_uri and request_uri.startswith("urn:ietf:params:oauth:request_uri:"), par)
if ATTESTER is not None:
    rogue = new_key()
    s, _, bad = call("POST", "/oauth/par", form=par_form, headers={"OAuth-Client-Attestation": client_attestation("wallet", instance_key, attester=rogue), "OAuth-Client-Attestation-PoP": client_attestation_pop("wallet", instance_key, AS_ISSUER)})
    check("PAR with an attestation from an unknown attester is refused", s == 401 and isinstance(bad, dict) and bad.get("error") == "invalid_client", {"status": s, "body": bad})
s, h, _ = call("GET", "/oauth/authorize?" + urllib.parse.urlencode({"client_id": "wallet", "request_uri": request_uri or ""}))
location = h.get("Location") or h.get("location") or ""
q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
code = q.get("code", [None])[0]
check("authorize redirects with code, state and iss", s in (302, 303) and code and q.get("state") == [state] and q.get("iss") == [AS_ISSUER], {"status": s, "location": location[:160]})
dpop_key = new_key()
token_headers = {} if ATTESTER is None else {"OAuth-Client-Attestation": client_attestation("wallet", instance_key), "OAuth-Client-Attestation-PoP": client_attestation_pop("wallet", instance_key, AS_ISSUER)}
token_headers["DPoP"] = dpop(dpop_key, "POST", TOKEN_ENDPOINT)
s, _, ac_tok = call("POST", TOKEN_ENDPOINT, form={"grant_type": "authorization_code", "code": code or "", "redirect_uri": "https://wallet.example/cb", "client_id": "wallet", "code_verifier": verifier}, headers=token_headers)
ac_claims = jwt.decode(ac_tok["access_token"], options={"verify_signature": False}) if isinstance(ac_tok, dict) and ac_tok.get("access_token") else {}
check("token: authorization code + PKCE, DPoP-bound (cnf.jkt), fixed subject", s == 200 and isinstance(ac_tok, dict) and ac_tok.get("token_type") == "DPoP"
      and ac_claims.get("cnf", {}).get("jkt") == thumbprint(public_jwk(dpop_key)) and ac_claims.get("sub") == SUBJECT,
      {k: ac_tok.get(k) for k in ("token_type", "error", "error_description")} if isinstance(ac_tok, dict) else ac_tok)
if isinstance(ac_tok, dict) and ac_tok.get("access_token"):
    s, _, dp = issue_new(ac_tok, CONFIG, {"jwt": [proof(NEW_ISSUER, nonce())]}, dpop_key=dpop_key)
    check("credential with the DPoP-bound token and a DPoP proof", s == 200 and isinstance(dp, dict) and dp.get("credentials"), {"status": s, "body": dp if s != 200 else "issued"})
    s, _, nodp = call("POST", "/oid4vci/credential", {"credential_configuration_id": CONFIG, "proofs": {"jwt": [proof(NEW_ISSUER, nonce())]}}, {"Authorization": "Bearer " + ac_tok["access_token"]})
    check("DPoP-bound token presented as Bearer is refused", s == 401, {"status": s, "body": nodp})
    s, _, wrongkey = issue_new(ac_tok, CONFIG, {"jwt": [proof(NEW_ISSUER, nonce())]}, dpop_key=new_key())
    check("DPoP proof from another key is refused", s == 401, {"status": s, "body": wrongkey})

# ------------------------------------------------------------------------------------------------ 5. key attestations
if ATTESTER is None:
    check("key attestations (needs the attester key: 4th argument)", False, "skipped")
else:
    atok, detail = offer_and_token(ATTESTED_ID)
    check("pre-authorized token for the attested configuration", atok is not None, detail if atok is None else "")
    if atok:
        n = nonce()
        s, _, plain = issue_new(atok, ATTESTED_ID, {"jwt": [proof(NEW_ISSUER, n)]})
        check("jwt proof without the required key attestation is refused", s == 400 and isinstance(plain, dict) and plain.get("error") == "invalid_proof", plain)
        holder, sibling = new_key(), new_key()
        n = nonce()
        s, _, att = issue_new(atok, ATTESTED_ID, {"jwt": [proof(NEW_ISSUER, n, holder, {"key_attestation": key_attestation([holder, sibling], n)})]})
        check("jwt proof with a key attestation: one credential per attested key", s == 200 and isinstance(att, dict) and len(att.get("credentials", [])) == 2, {"status": s, "body": att if s != 200 else len(att["credentials"])})
        n = nonce()
        s, _, weak = issue_new(atok, ATTESTED_ID, {"jwt": [proof(NEW_ISSUER, n, holder, {"key_attestation": key_attestation([holder], n, key_storage=("iso_18045_basic",))})]})
        check("key storage below the accepted level is refused", s == 400 and isinstance(weak, dict) and weak.get("error") == "invalid_proof", weak)
        n = nonce()
        s, _, att2 = issue_new(atok, ATTESTED_ID, {"attestation": [key_attestation([new_key(), new_key(), new_key()], n, exp=False)]})
        check("attestation proof type: three attested keys, three credentials", s == 200 and isinstance(att2, dict) and len(att2.get("credentials", [])) == 3, {"status": s, "body": att2 if s != 200 else len(att2["credentials"])})
        s, _, nonce_less = issue_new(atok, ATTESTED_ID, {"attestation": [key_attestation([new_key()], None)]})
        check("attestation proof without the c_nonce is refused", s == 400 and isinstance(nonce_less, dict) and nonce_less.get("error") == "invalid_nonce", nonce_less)

# ------------------------------------------------------------------------------------------------ 6. SD-JWT VC under the dev CA with a Token Status List
stok, detail = offer_and_token(SDJWT_ID)
check("pre-authorized token for the SD-JWT configuration", stok is not None, detail if stok is None else "")
if stok:
    s, _, sd = issue_new(stok, SDJWT_ID, {"jwt": [proof(NEW_ISSUER, nonce())]})
    compact = (sd.get("credentials") or [{}])[0].get("credential") if isinstance(sd, dict) else None
    ok = s == 200 and isinstance(compact, str) and "~" in compact
    header, payload = jwt_parts(compact.split("~")[0]) if ok else ({}, {})
    status_list = payload.get("status", {}).get("status_list", {})
    check("SD-JWT VC issued: typ, x5c leaf only, cnf, disclosures", ok and header.get("typ") == "dc+sd-jwt" and len(header.get("x5c", [])) == 1 and "cnf" in payload and payload.get("vct") == SDJWT_ID and compact.count("~") >= 2,
          {"status": s, "typ": header.get("typ"), "x5c": len(header.get("x5c", [])), "disclosures": compact.count("~") - 1 if ok else sd})
    check("SD-JWT VC carries status.status_list {idx, uri}", isinstance(status_list.get("idx"), int) and isinstance(status_list.get("uri"), str) and "/credentials/token-status-list/" in status_list.get("uri", ""), status_list)
    if status_list.get("uri"):
        s, h, list_jwt = call("GET", status_list["uri"])
        lh, lp = jwt_parts(list_jwt) if isinstance(list_jwt, str) and list_jwt.count(".") == 2 else ({}, {})
        check("Token Status List served as statuslist+jwt, bit clear", s == 200 and lh.get("typ") == "statuslist+jwt" and lp.get("sub") == status_list["uri"] and lp.get("status_list", {}).get("bits") == 1
              and token_status_bit(lp["status_list"]["lst"], status_list["idx"]) == 0, {"status": s, "content-type": h.get("Content-Type"), "typ": lh.get("typ")})
        list_id = status_list["uri"].rsplit("/", 1)[-1]
        s, _, upd = call("POST", "/credentials/status", {"credentialStatus": {"id": list_id, "type": "TokenStatusList", "statusPurpose": "revocation", "statusListIndex": status_list["idx"], "statusListCredential": list_id}, "status": True})
        check("revocation recorded for the SD-JWT entry", s == 200, {"status": s, "body": upd})
        flipped = wait_for("token status bit", lambda: token_status_bit(jwt_parts(call("GET", status_list["uri"])[2])[1]["status_list"]["lst"], status_list["idx"]) == 1)
        check("Token Status List re-signed by the batch job with the bit set", flipped, "waited for the 10 s batch")

# ------------------------------------------------------------------------------------------------ 7. mDoc under the dev CA
mtok, detail = offer_and_token(MDL_ID)
check("pre-authorized token for the mDoc configuration", mtok is not None, detail if mtok is None else "")
if mtok:
    s, _, md = issue_new(mtok, MDL_ID, {"jwt": [proof(NEW_ISSUER, nonce())]})
    encoded = (md.get("credentials") or [{}])[0].get("credential") if isinstance(md, dict) else None
    decoded = None
    if s == 200 and isinstance(encoded, str):
        try:
            import cbor2
            decoded = cbor2.loads(b64url_decode(encoded))
        except Exception as e:  # noqa: BLE001
            decoded = {"error": str(e)}
    ok = isinstance(decoded, dict) and "issuerAuth" in decoded and "nameSpaces" in decoded and "org.iso.18013.5.1" in decoded.get("nameSpaces", {})
    check("mDoc issued: IssuerSigned with nameSpaces and issuerAuth (COSE_Sign1 under the dev CA)", ok, {"status": s, "keys": list(decoded.keys()) if isinstance(decoded, dict) else md})
    if ok:
        issuer_auth = decoded["issuerAuth"]
        protected = cbor2.loads(issuer_auth[0]) if isinstance(issuer_auth, list) else {}
        unprotected = issuer_auth[1] if isinstance(issuer_auth, list) else {}
        check("issuerAuth: ES256 (-7) and an x5chain (33) with the leaf", protected.get(1) == -7 and 33 in unprotected, {"protected": protected, "unprotected_keys": list(unprotected.keys()) if isinstance(unprotected, dict) else unprotected})

# ------------------------------------------------------------------------------------------------ 8. VC-API: issue, refusals, status through the ledger
basic = {"Authorization": "Basic " + base64.b64encode(b"coordinator:s3cret").decode()}
supplied = {"@context": CONTEXT_V2, "id": "urn:uuid:" + secrets.token_hex(8), "type": ["VerifiableCredential", SUPPLIED_ID], "issuer": ISSUER_DID,
            "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "credentialSubject": {"id": "did:example:holder", "fullName": "Supplied Farmer"}}
s, _, vc = call("POST", "/vc-api/credentials/issue", {"credential": supplied}, basic)
issued = vc.get("verifiableCredential") if isinstance(vc, dict) else None
check("VC-API issue: 201 with the signed credential (Ed25519Signature2020, verification method in did.json)", s == 201 and isinstance(issued, dict) and issued.get("proof", {}).get("type") == "Ed25519Signature2020"
      and issued["proof"].get("verificationMethod") in [m.get("id") for m in DID.get("verificationMethod", [])] and issued.get("id") == supplied["id"],
      {"status": s, "body": vc if s != 201 else issued.get("proof", {}).get("verificationMethod")})
check("VC-API issue: credentialStatus attached (Bitstring)", isinstance(issued, dict) and isinstance(issued.get("credentialStatus"), dict) and issued["credentialStatus"].get("statusPurpose") == "revocation", (issued or {}).get("credentialStatus") if isinstance(issued, dict) else "")
s, h, no = call("POST", "/vc-api/credentials/issue", {"credential": supplied})
check("VC-API without a client: 401 with WWW-Authenticate", s == 401 and any(k.lower() == "www-authenticate" for k in h), {"status": s, "body": no})
s, _, other = call("POST", "/vc-api/credentials/issue", {"credential": supplied}, {"Authorization": "Basic " + base64.b64encode(b"other:other-secret").decode()})
check("VC-API client without the configuration: 403 problem details", s == 403 and isinstance(other, dict) and other.get("title") == "FORBIDDEN", other)
wrong = dict(supplied, issuer="did:web:someone-else.example")
s, _, mism = call("POST", "/vc-api/credentials/issue", {"credential": wrong}, basic)
check("VC-API issuer mismatch: 400", s == 400 and isinstance(mism, dict) and mism.get("title") == "ISSUER_MISMATCH", mism)
if isinstance(issued, dict) and isinstance(issued.get("credentialStatus"), dict):
    cs = issued["credentialStatus"]
    list_url, index = cs.get("statusListCredential"), int(cs.get("statusListIndex"))
    s, _, before = call("GET", "/credentials/status-list/" + list_url.rsplit("/", 1)[-1])
    check("Bitstring status list served, bit clear", s == 200 and isinstance(before, dict) and bitstring_bit(before["credentialSubject"]["encodedList"], index) == 0, {"status": s, "list": list_url})
    s, _, upd = call("POST", "/vc-api/credentials/status", {"credentialId": issued["id"], "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation"}, "status": True}, basic)
    check("VC-API status update by credential id (ledger lookup): 200", s == 200, {"status": s, "body": upd})
    flipped = wait_for("bitstring bit", lambda: bitstring_bit(call("GET", "/credentials/status-list/" + list_url.rsplit("/", 1)[-1])[2]["credentialSubject"]["encodedList"], index) == 1)
    check("Bitstring list re-signed by the batch job with the bit set", flipped, "waited for the 10 s batch")
    s, _, unknown = call("POST", "/vc-api/credentials/status", {"credentialId": "urn:uuid:unknown", "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation"}, "status": True}, basic)
    check("VC-API status for an unknown credential: 404", s == 404, {"status": s, "body": unknown})

# ------------------------------------------------------------------------------------------------ 9. configuration API round trip
s, _, prev = call("POST", "/v2/credential-configurations/" + CONFIG + "/preview", {"claims": {"fullName": "Preview Person", "dateOfBirth": "2000-01-01"}})
check("v2 preview renders the farmer template", s == 200 and isinstance(prev, dict) and "credential" in prev, {"status": s, "body": prev if s != 200 else "rendered"})

failed = [r for r in results if not r[1]]
print("\n%d checks, %d failed" % (len(results), len(failed)))
for name, ok, detail in failed:
    print("  FAILED:", name)
sys.exit(1 if failed else 0)
