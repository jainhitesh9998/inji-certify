# Validating the rebuild: pre-authorized code flow from a wallet

The acceptance test for every merge into `design/extensibility` is unchanged behaviour on the wire. This page is
the manual counterpart: build the image from the branch, run the injistack with it, and download a credential
into a wallet through the pre-authorized code flow. Automated coverage of the same flow lives in
`certify-service/src/test/java/io/mosip/certify/golden/IssuanceGoldenTest.java` (nonce, holder proof, `ldp_vc`,
`dc+sd-jwt`, Data Integrity, RSA; every credential verified by an independent library).

## 1. Build the service

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
mvn -B -ntp -Dgpg.skip=true -DskipTests install          # add -s .mvn/settings-local.xml if JitPack hangs
```

The image is built by the compose override in step 4 from `certify-service/Dockerfile` (`inji-certify:rebuild`).

## 2. Plugin jars

The published `injistackdev/inji-certify-with-plugins:develop` image only adds the plugin jars on top of the
service image. Take them from there instead of resolving snapshot artifacts:

```bash
cd docker-compose/docker-compose-injistack
mkdir -p loader_path/certify data/CERTIFY_PKCS12
id=$(docker create injistackdev/inji-certify-with-plugins:develop)
docker cp "$id":/home/inji/additional_jars/. loader_path/certify/   # the published image runs as user inji
docker rm "$id"
ls loader_path/certify   # mock-certify-plugin-*.jar and friends
```

## 3. Issuer identity

The farmer use case signs `ldp_vc` with `did:web`. Set the DID to the hostname the wallet will resolve:

- `config/certify-csvdp-farmer.properties`: `mosip.certify.data-provider-plugin.did-url=did:web:<host>`; for
  Inji Web inside the same compose network `did:web:certify-nginx` works, for a phone wallet use the public
  hostname of an `ngrok http 8091` tunnel.
- `docker-compose.yaml`, service `certify`: `mosip_certify_domain_url` must be the URL the wallet uses to reach
  Certify (`http://certify-nginx:80` for Inji Web, the ngrok URL for a phone).

The `rebuild` profile (`config/certify-rebuild.properties`, mounted by the override) makes Certify its own
authorization server, which is what the pre-authorized code flow needs.

## 4. Run

```bash
docker network inspect mosip_network >/dev/null 2>&1 || docker network create mosip_network   # the compose file expects it
docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml up -d --build
docker compose logs -f certify | grep -m1 'INJI Certify -- Started'
curl -s http://localhost:8090/v1/certify/.well-known/openid-credential-issuer | jq '.credential_configurations_supported | keys'
curl -s http://localhost:8090/v1/certify/.well-known/oauth-authorization-server | jq '.token_endpoint, .grant_types_supported'
```

Expected: `["FarmerCredential", ...]` and a token endpoint under Certify's own URL with
`urn:ietf:params:oauth:grant-type:pre-authorized_code` in the grant types.

## 5. Create a credential offer

`/pre-authorized-data` is unauthenticated in the stack configuration (`mosip.certify.security.ignore-auth-urls`).
Claim keys must be among the configuration's `claims` metadata (last path segment); anything else is refused with
`unknown_claims`, and note the refusal comes back as HTTP 200 with an `errors` array (legacy envelope, logged as a
finding). With Certify as its own authorization server there are two ways to name the identity data. An offer with a
`subject` puts that value in the access token's `sub`, exactly as an eSignet token would carry the individual id, so
the farmer profile's CSV plugin resolves the row (`2154189532` is Gorge Cooper in `farmer_identity_data.csv`) and
every template field is filled:
```bash
curl -s http://localhost:8090/v1/certify/pre-authorized-data \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"FarmerCredential","subject":"2154189532","expires_in":600,"tx_code":"1234"}'
```
An offer with `claims` instead makes the claims the identity data; that needs
`mosip.certify.integration.data-provider-plugin=PreAuthDataProviderPlugin` (the CSV plugin cannot resolve a JSON
`sub`), and template fields the offer does not carry render as their literal placeholder (`${state}`):
```bash
curl -s http://localhost:8090/v1/certify/pre-authorized-data \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"FarmerCredential","claims":{"fullName":"Gorge Cooper","phone":"9876543210","dateOfBirth":"1990-05-25","gender":"Male"},"expires_in":600,"tx_code":"1234"}'
```

The response is `{"credential_offer_uri":"openid-credential-offer://?credential_offer_uri=..."}`. Show it as a QR
(`qrencode -t ansiutf8 '<uri>'`) or paste it into the wallet. The same three steps run in-JVM in
`IssuanceGoldenTest.preAuthorizedCodeFlowGoldenAndAccessTokenVerification`, which also verifies the access token
against `jwks.json`.

## 5b. Configure through the v2 API

The same configuration can be written in the rebuilt model; `sampleClaims` makes the service render the template
before it saves the row, and `preview` renders a saved one without signing:

```bash
curl -s -X POST http://localhost:8090/v1/certify/v2/credential-configurations -H 'Content-Type: application/json' -d '{
  "id": "FarmerCredentialV2", "scope": "farmer_vc_ldp", "format": "ldp_vc",
  "formatConfig": {"context": ["https://www.w3.org/2018/credentials/v1"], "types": ["VerifiableCredential", "FarmerCredential"],
                   "claims": {"fullName": {"display": [{"name": "Full name", "locale": "en"}], "mandatory": true}}},
  "signing": {"alias": "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg": "EdDSA", "cryptosuite": "Ed25519Signature2020", "didUrl": "did:web:localhost:certify"},
  "template": {"content": "<the Velocity template as text>"},
  "display": {"display": [{"name": "Farmer credential", "locale": "en"}], "order": ["fullName"]},
  "sampleClaims": {"fullName": "Sample Person"}
}'
curl -s -X POST http://localhost:8090/v1/certify/v2/credential-configurations/FarmerCredentialV2/preview \
  -H 'Content-Type: application/json' -d '{"claims": {"fullName": "Preview Person"}}'
```

## 6. Download with a wallet

- Inji Web from the same compose (`inji-web` service) or the Inji mobile wallet: scan or open the offer, enter
  the transaction code `1234`, accept. The wallet performs `GET /credential-offer-data/{id}`, `POST /oauth/token`
  (grant `pre-authorized_code`), `POST /nonce`, `POST /issuance/credential` with a JWT proof.
- To watch the calls: `docker compose logs -f certify | grep -E 'oauth/token|/nonce|issuance/credential'`.

Without a wallet the first two steps can be driven by hand:

```bash
offer=$(curl -s "<credential_offer_uri from step 5>")
code=$(echo "$offer" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]')
curl -s http://localhost:8090/v1/certify/oauth/token -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=$code&tx_code=1234"
curl -s -X POST http://localhost:8090/v1/certify/nonce -i | grep -i 'c_nonce\|^HTTP'
```

The credential request itself needs a holder-signed proof, which is what the wallet contributes; the golden test
builds one in-process if you want to see the exact shape.

## 6b. The new surface

The rebuilt core serves `ldp_vc`, `dc+sd-jwt` and `mso_mdoc` at `POST /v1/certify/oid4vci/credential`, discovered
through `GET /v1/certify/oid4vci/.well-known/openid-credential-issuer` (its own `credential_issuer`, ending in
`/oid4vci`) with `POST /v1/certify/oid4vci/nonce`. A wallet whose issuer entry points at that metadata completes the
same pre-authorized flow on the new surface (the token comes from the same `/oauth/token`; the proof's `aud` must be
the new `credential_issuer`). The wallet flow above still uses the compatibility path `/issuance/credential`.

The credential response on this surface carries a `notification_id`; a wallet that implements the OpenID4VCI 1.0
notification endpoint reports back to `POST /v1/certify/oid4vci/notification` and the matching
`issuance_transaction` row (`select state from issuance_transaction`) moves from `ISSUED` to `NOTIFIED`. By hand:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8090/v1/certify/oid4vci/notification \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"notification_id":"<id from the credential response>","event":"credential_accepted"}'   # 204
```

## 6c. Draft-13 wallets and the compatibility path through the core

A wallet that still speaks OpenID4VCI draft 13 (release 0.14.0) posts the 0.14.0 body to the same
`POST /v1/certify/issuance/credential` (`format` plus `credential_definition`, `vct` or `doctype`, one `proof`) or to
`/v1/certify/issuance/vd12/credential` and `/v1/certify/issuance/vd11/credential`; it discovers the issuer through
`GET /v1/certify/.well-known/openid-credential-issuer?version=latest|vd12|vd11` or the `/v1/certify/issuance/.well-known/`
aliases. A wrong or missing nonce is answered with `invalid_proof` carrying the `c_nonce` to use next, as 0.14.0 did.
Every draft-13 answer carries `Deprecation` and `Link` headers and counts in `certify.deprecated.calls`;
`certify.protocol.oid4vci-d13.enabled=false` removes the adapter, `mosip.certify.deprecated.<endpoint>.enabled=false`
turns one endpoint into `410 Gone`.

The 1.0 body on `/issuance/credential` is still served by the legacy issuance service unless
`certify.protocol.oid4vci-v1.compat-core.enabled=true` (DataProvider plugin mode), which routes it through the new
core; the golden tests run both modes, so the wallet flow above is the same either way.

## 6d. Scripted smoke run

`docs/design/tools/smoke.py` walks the whole flow without a wallet: metadata on both surfaces, offer, token, nonce,
`POST /issuance/credential`, `POST /oid4vci/credential` with `notification_id`, the notification endpoint, a
replayed nonce (refused), the request without a token (401), `did.json` listing the proof's verification method,
and the v2 configuration API (list, get, preview). It needs Python 3 with `pyjwt` and `cryptography`:

```bash
python3 -m venv .venv && .venv/bin/pip install pyjwt cryptography
.venv/bin/python docs/design/tools/smoke.py http://localhost:8090/v1/certify FarmerCredential
```

The stack's `mosip_certify_domain_url` decides the identifiers the script must use as proof audiences; with the
compose default (`http://certify-nginx:80`) run it from inside the network or start the stack with the URL the
script reaches, for example an override file setting `mosip_certify_domain_url=http://localhost:8090` on the
`certify` service. On 2026-09-19 the run passed every check except the deprecation header on
`/issuance/credential`, which waits for the owner's decision (P1-11f).

## 6e. Every workflow in one run

`docs/design/tools/workflows.py` drives every issuance workflow against a running stack and prints one `PASS`/`FAIL`
line per step (52 steps on 2026-09-19): discovery on all surfaces; the pre-authorized code flow on the compatibility,
draft-13 and `/oid4vci` surfaces with notification, batch and nonce replay; the authorization code flow of Certify's
own AS with PAR, PKCE, client attestation and a DPoP-bound token (and the refusals of a replayed attestation PoP, a
Bearer presentation of a DPoP token and a foreign DPoP key); key attestations on `jwt` proofs and the `attestation`
proof type; SD-JWT VC under the x509-file dev CA with a Token Status List and its revocation by the batch job; mDoc;
VC-API issuance, its refusals and a status update resolved through the ledger; the v2 configuration API.

The stack needs a `workflows` profile next to `rebuild` (the driver creates the extra configurations itself):

```properties
certify.as.clients.wallet.redirect-uris=https://wallet.example/cb
certify.as.authorization.subject-mode=fixed
certify.as.authorization.fixed-subject=2154189532
certify.as.client-attestation.attesters.test.jwks={"keys":[<the attester's public JWK, kid wallet-provider-1>]}
certify.protocol.oid4vci-v1.key-attestation.attesters.test.jwks={"keys":[<the same JWK>]}
certify.protocol.vc-api.enabled=true
certify.protocol.vc-api.clients.coordinator.secret=s3cret
certify.protocol.vc-api.clients.other.secret=other-secret
certify.protocol.vc-api.clients.other.credential-configurations=SomeOtherConfiguration
certify.keyprovider.x509-file.enabled=true
certify.keyprovider.x509-file.dev-mode=true
certify.keyprovider.x509-file.path=/tmp/workflows-pki.p12
certify.keyprovider.x509-file.password=pki-test
certify.keyprovider.x509-file.keys[0].alias=sdjwt-es256
certify.keyprovider.x509-file.keys[0].algorithm=ES256
certify.keyprovider.x509-file.keys[1].alias=mdoc-es256
certify.keyprovider.x509-file.keys[1].algorithm=ES256
certify.status.token-status-list.key-ref=x509-file:sdjwt-es256
mosip.certify.batch.status-list-update.cron-expression=*/10 * * * * *
mosip.certify.batch.status-list-update.lock-at-least-for=5s
```

Mount it as `/home/mosip/config/certify-workflows.properties`, set `active_profile_env=default, csvdp-farmer, rebuild, workflows`,
and point `mosip_certify_domain_url` at the host the run uses (a Cloudflare tunnel in front of port 8090 works; the
driver pins IPv4 and sets a user agent because Cloudflare stalls Python's defaults). Then:

```bash
.venv/bin/pip install pyjwt cryptography cbor2
.venv/bin/python docs/design/tools/workflows.py https://<host>/v1/certify FarmerCredential 2154189532 attester.pem
```

`attester.pem` is the private key of the JWK in the two `attesters` properties. The run of 2026-09-19 found four
defects that the unit suite could not see (F-02 to F-05 in `docs/design/wp/PROGRESS.md`); all are fixed.

## 7. Verify the credential independently

The wallet shows the credential; to check it with a third-party verifier, paste the `ldp_vc` JSON into any
Ed25519Signature2020-capable verifier (e.g. the `did:web` document at
`http://<host>/.well-known/did.json` resolves the verification method) or run the golden test, which verifies
with danubetech's verifier and Nimbus. A credential that renders in the wallet but fails an independent verifier
is a bug of the highest priority (`CLAUDE.md`, non-negotiables).

## What "unchanged" means per merge

`docs/design/wp/PROGRESS.md` records, per work package, the golden and full-suite status. Anything that changes a
golden before Phase 3 is a regression unless the decision log says otherwise.
