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
docker cp "$id":/home/mosip/additional_jars/. loader_path/certify/
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
finding). For `FarmerCredential` the seed lists `fullName`, `phone`, `dateOfBirth`, ... — the mock CSV plugin then
resolves the row it serves:

```bash
curl -s http://localhost:8090/v1/certify/pre-authorized-data \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"FarmerCredential","claims":{"fullName":"Gorge Cooper"},"expires_in":600,"tx_code":"1234"}'
```

The response is `{"credential_offer_uri":"openid-credential-offer://?credential_offer_uri=..."}`. Show it as a QR
(`qrencode -t ansiutf8 '<uri>'`) or paste it into the wallet. The same three steps run in-JVM in
`IssuanceGoldenTest.preAuthorizedCodeFlowGoldenAndAccessTokenVerification`, which also verifies the access token
against `jwks.json`.

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

`POST /v1/certify/oid4vci/credential` (same request body, same access token) issues `ldp_vc` through the rebuilt core;
the wallet flow above still uses the compatibility path `/issuance/credential`. Issuer metadata and the nonce endpoint
under `/oid4vci` arrive with the next slices, so a wallet cannot discover the new surface yet.

## 7. Verify the credential independently

The wallet shows the credential; to check it with a third-party verifier, paste the `ldp_vc` JSON into any
Ed25519Signature2020-capable verifier (e.g. the `did:web` document at
`http://<host>/.well-known/did.json` resolves the verification method) or run the golden test, which verifies
with danubetech's verifier and Nimbus. A credential that renders in the wallet but fails an independent verifier
is a bug of the highest priority (`CLAUDE.md`, non-negotiables).

## What "unchanged" means per merge

`docs/design/wp/PROGRESS.md` records, per work package, the golden and full-suite status. Anything that changes a
golden before Phase 3 is a regression unless the decision log says otherwise.
