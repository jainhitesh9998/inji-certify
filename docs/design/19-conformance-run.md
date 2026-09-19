# 19. Running the OpenID Foundation issuer conformance suite against Certify

What to deploy, configure and hand to the suite ("OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test an Issuer") now that gap items 1 to 6 of `17-conformance-gaps.md` are merged. The suite acts as a HAIP wallet from `35.196.44.185` against a public HTTPS issuer, drives the authorization code flow with PAR, PKCE, client attestation and DPoP, and verifies SD-JWT VC or mDoc credentials and their status lists against trust anchors the tester uploads.

## 1. Host

- A public HTTPS host that terminates TLS and forwards to the service. The Credential Issuer Identifier is `https://<host>/v1/certify/oid4vci` (the new surface appends `/oid4vci` to `mosip.certify.identifier`, which stays `https://<host>/v1/certify`); the authorization server issuer is `https://<host>/v1/certify` (`/.well-known/oauth-authorization-server`).
- Every path the suite calls must be reachable without a network allow-list: `/oid4vci/.well-known/openid-credential-issuer`, `/.well-known/oauth-authorization-server`, `/oauth/par`, `/oauth/authorize`, `/oauth/token`, `/oid4vci/nonce`, `/oid4vci/credential`, `/oid4vci/notification`, `/credentials/token-status-list/{id}`, `/.well-known/did.json` and `/.well-known/jwks.json` (the token verification keys).
- The compose stack is enough for the run (`docker-compose/docker-compose-injistack`, `docker-compose.rebuild.yaml`, `config/certify-rebuild.properties`) behind any reverse proxy that sets `X-Forwarded-Proto: https`; production shape is `15-deployment.md`.

## 2. Properties for the run

Add to `certify-rebuild.properties` (or the environment):

```properties
# the wallet the suite registers: the callback it prints for the plan alias
certify.as.clients.oidf.redirect-uris=https://www.certification.openid.net/test/a/<alias>/callback
# the suite needs a code back without a user: approve every request for one configured subject
certify.as.authorization.subject-mode=fixed
certify.as.authorization.fixed-subject=<a subject the data provider resolves, e.g. a CSV row id>
# HAIP: client attestation is mandatory; the suite's attestation signing key from the plan configuration
certify.as.client-attestation.required=true
certify.as.client-attestation.attesters.oidf.jwks={"keys":[<the suite's client attestation JWK>]}
# the PKI the credentials and status lists are signed under: x509-file in dev mode generates a CA and the listed
# leaves in a PKCS#12 at start (a test run); production points path/password at an operator-supplied keystore
certify.keyprovider.x509-file.enabled=true
certify.keyprovider.x509-file.dev-mode=true
certify.keyprovider.x509-file.path=/home/mosip/keys/conformance.p12
certify.keyprovider.x509-file.password=<keystore password>
certify.keyprovider.x509-file.keys[0].alias=sdjwt-es256
certify.keyprovider.x509-file.keys[0].algorithm=ES256
certify.keyprovider.x509-file.keys[0].subject=CN=Certify Conformance SD-JWT
certify.keyprovider.x509-file.keys[1].alias=mdoc-es256
certify.keyprovider.x509-file.keys[1].algorithm=ES256
certify.keyprovider.x509-file.keys[1].subject=CN=Certify Conformance mDoc
# Token Status List signing key (a leaf under the same CA)
certify.status.token-status-list.key-ref=x509-file:sdjwt-es256
# only when the plan enables its key attestation tests
certify.protocol.oid4vci-v1.key-attestation.attesters.oidf.jwks={"keys":[<the suite's key attestation JWK>]}
# or, when the plan signs key attestations under a certificate chain
# certify.protocol.oid4vci-v1.key-attestation.attesters.oidf.trust-anchor=-----BEGIN CERTIFICATE-----...
```

DPoP needs no setting: a `DPoP` header at the token endpoint binds the token. PAR is advertised as required as soon as a client is registered. Deprecated compatibility paths stay on and do not interfere.

## 3. The credential configuration

Create the HAIP credential through the v2 API (`docs/design/VALIDATE.md` 5b). SD-JWT VC under the dev CA, anchor-free chain, Token Status List, attested keys optional:

```json
{
  "id": "HAIPIdentityCredential",
  "scope": "haip_identity",
  "format": "dc+sd-jwt",
  "formatConfig": {"vct": "urn:eudi:pid:1", "sdClaims": ["$.given_name", "$.family_name", "$.birthdate"]},
  "signing": {"provider": "x509-file", "alias": "sdjwt-es256", "alg": "ES256", "x5c": "without-anchor"},
  "status": {"mechanism": "TokenStatusList", "purposes": ["revocation"]},
  "template": {"content": "<the SD-JWT payload template>"},
  "display": {"display": [{"name": "Identity", "locale": "en"}]},
  "protocol": {
    "cryptographicBindingMethodsSupported": ["jwk"],
    "proofTypesSupported": {
      "jwt": {"proof_signing_alg_values_supported": ["ES256"]},
      "attestation": {"proof_signing_alg_values_supported": ["ES256"]}
    }
  }
}
```

Add `"key_attestations_required": {"key_storage": ["iso_18045_high", "iso_18045_moderate"]}` under `jwt` only for the plan's key attestation variant; the metadata then advertises it and plain proofs are refused. For mDoc use `"format": "mso_mdoc"`, `"formatConfig": {"doctype": "org.iso.18013.5.1.mDL", ...}` and a `mdoc-es256` alias signed by the same dev CA.

## 4. What to upload to the plan

| Plan field | Where it comes from |
| --- | --- |
| Issuer metadata URL | `https://<host>/v1/certify/oid4vci/.well-known/openid-credential-issuer` |
| Credential configuration id and scope | the id and scope above |
| Trust anchor for the credential's `x5c` | `keytool -exportcert -rfc -keystore /home/mosip/keys/conformance.p12 -storepass <pw> -alias dev-ca` (the CA the dev mode generated, alias `certify.keyprovider.x509-file.ca-alias`; the issued chain carries the leaf only, so the suite chains it to this anchor) |
| Trust anchor for the status list JWT | the same certificate when `certify.status.token-status-list.key-ref` is a key under the dev CA |
| Redirect URI | the plan prints it; it must match `certify.as.clients.oidf.redirect-uris` exactly |
| Client id | `oidf` (the key under `certify.as.clients`) |

## 5. Dry run before the plan

1. `docs/design/tools/smoke.py https://<host>/v1/certify HAIPIdentityCredential` proves offer, token, nonce, credential and notification on the new surface.
2. `AuthorizationCodeFlowTest`, `ClientAttestationTest`, `DpopBoundTokenTest`, `PkiSdJwtIssuanceTest`, `StatusListPostgresTest.tokenStatusListForSdJwt` and `KeyAttestationTest` are the in-process equivalents of the suite's steps.
3. Verify one issued SD-JWT VC with an independent verifier against the exported anchor before starting the plan (`VALIDATE.md` 7).

## 6. Reading a failure

The suite names the step; the matching error on Certify's side is in the JSON log (`error` and `error_description` of the response, and the validator's message): `invalid_client` at PAR or token is the client attestation (attester JWKS, `aud`, `jti` replay, `iat` age); `invalid_dpop_proof` the DPoP header; `invalid_proof` or `invalid_nonce` the holder proof or key attestation; `certificate_chain_invalid` the signing chain against `CertificateChainPolicy`. Every response on the new surface follows the specification's error names (`IssuanceGoldenTest.oid4vciErrorsFollowTheSpec`).
