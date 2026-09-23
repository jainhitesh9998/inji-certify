# Changes in the extensibility rebuild (unreleased, `design/extensibility`)

## Draft-13 endpoints restored and deprecated

The OpenID4VCI draft-13 credential endpoints of release 0.14.0 are served again by the `oid4vci-d13` adapter (on by default, `certify.protocol.oid4vci-d13.enabled`): the 0.14.0 body on `POST /issuance/credential`, `POST /issuance/vd12/credential` and `POST /issuance/vd11/credential`. They are deprecated from this release: every answer carries `Deprecation` and `Link` headers, calls are counted in `certify.deprecated.calls{endpoint=oid4vci-d13-credential|oid4vci-d13-versioned-credential}`, and `mosip.certify.deprecated.<endpoint>.enabled=false` answers `410 Gone`. Replacement: `POST /oid4vci/credential` (OpenID4VCI 1.0). Removal no earlier than two minor releases after this one.

## Notification endpoint on the new surface

`POST /oid4vci/credential` answers with a `notification_id` and the issuer metadata under `/oid4vci` advertises `notification_endpoint`: wallets report `credential_accepted`, `credential_failure` or `credential_deleted` to `POST /oid4vci/notification` (OpenID4VCI 1.0 section 10) with the access token of the issuance. Every issuance through the new surface is recorded in the `issuance_transaction` table created by the 1.1.0 migration and purged after `certify.protocol.oid4vci-v1.notification.retention` (default one day). The compatibility endpoints are unchanged.

## v2 configuration API

`POST`, `GET`, `PUT` and `DELETE /v2/credential-configurations` take and return the configuration model the rebuilt core reads (`formatConfig`, `signing`, `template`, `issuanceStrategy`, `status`, `display`, `protocol`), version templates in `credential_template`, and dry-run a body that carries `sampleClaims` through the template engine and formatter before saving it (`400 template_render_failed` otherwise). `POST /v2/credential-configurations/{id}/preview` renders a saved configuration against given claims without signing. Rows written through v2 carry every v1 column too, so `/credential-configurations` (v1), the compatibility endpoints and the issuer metadata see them unchanged. The v1 API is unchanged and not yet deprecated.

## Single-use nonces and batch issuance on the new surface

A `c_nonce` from `POST /oid4vci/nonce` now authorises one credential request: after the credentials are issued the nonce is dropped, and a replayed proof answers `400 invalid_nonce` (`certify.protocol.oid4vci-v1.nonce.single-use=false` restores the previous behaviour). The issuer metadata under `/oid4vci` advertises `batch_credential_issuance.batch_size` (`certify.protocol.oid4vci-v1.batch.size`, default 10); a request whose `proofs` exceed it answers `400 invalid_credential_request`. The compatibility endpoints and the draft-13 endpoints are unchanged.

## Path-based tenants

`certify.tenancy.resolver=path` serves each configured tenant under `{domain}{servletPath}/t/{tenant}/oid4vci/...` with `.../t/{tenant}/oid4vci` as its Credential Issuer Identifier, next to the host resolver. Unconfigured path tenants answer as the default tenant. A tenant may also set `certify.tenancy.tenants.<id>.display` and `.authorization-servers` for its metadata document; token validation still uses the deployment's authorization server.

## Tenant DID documents

With `certify.tenancy` enabled, a tenant configured with `issuer-did` issues under that DID (the proof's `verificationMethod` is `<tenant did>#<kid>`) and `GET /.well-known/did.json` on the tenant's host publishes the deployment's keys under the tenant's DID, so a verifier resolves the tenant's credentials from the tenant's own document. Single-tenant deployments are unchanged.

## Compatibility credential endpoint deprecated

`POST /issuance/credential` with the 1.0.0-beta.1 body (`credential_configuration_id`, `proofs`) keeps working and is deprecated from this release: every answer carries `Deprecation` and `Link` headers, calls are counted in `certify.deprecated.calls{endpoint=oid4vci-v1-compat-credential}`, and `mosip.certify.deprecated.oid4vci-v1-compat-credential.enabled=false` answers `410 Gone`. Replacement: `POST /oid4vci/credential` (OpenID4VCI 1.0, advertised by `GET /oid4vci/.well-known/openid-credential-issuer`). `POST /nonce` stays. Removal no earlier than two minor releases after this one, never in a patch.

## Pre-authorized offers may name a subject

`POST /pre-authorized-data` accepts an optional `subject` next to `claims`: the identifier the data provider resolves (for the CSV plugin, the row id). It becomes the access token's `sub`, so plugins that look the record up by `sub` work in the pre-authorized code flow without eSignet. Offers with `claims` behave as before.

## Token Status List

A configuration whose `status.mechanism` is `TokenStatusList` gives its SD-JWT VC payload or mDoc MSO a `status.status_list` entry (draft-ietf-oauth-status-list); the lists are signed JWTs (`typ statuslist+jwt`) under `certify.status.token-status-list.key-ref`, served at `GET /credentials/token-status-list/{id}` as `application/statuslist+jwt`, and re-signed by the status-list batch job on revocation. Bitstring Status List for `ldp_vc` is unchanged.

## X.509 chains for SD-JWT VC and mDoc

The `x509-file` provider's dev mode now signs generated keys with a dev CA (`certify.keyprovider.x509-file.ca-alias`, default `dev-ca`) instead of self-signing them, a configuration may choose how much of the chain its SD-JWT `x5c` and mDoc `x5chain` carry (`signing.x5c` in the v2 configuration API: `full`, `leaf`, `without-anchor`, `none`), and the chain is checked (validity, links) before an SD-JWT VC or mDoc is signed. Configurations without the setting are unchanged.

## DPoP-bound access tokens

`POST /oauth/token` accepts a `DPoP` proof (RFC 9449) on every grant and then issues a sender-constrained token (`cnf.jkt`, `token_type: DPoP`) that the credential endpoints already enforce; the authorization server metadata advertises `dpop_signing_alg_values_supported`. Without a proof the token is a Bearer token, as before.

## Attestation-based client authentication

With attesters configured under `certify.as.client-attestation.attesters.<id>.jwks`, `POST /oauth/par` and `POST /oauth/token` validate the `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers (draft-ietf-oauth-attestation-based-client-auth) and the authorization server metadata advertises `token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"]`; `certify.as.client-attestation.required=true` refuses unauthenticated calls, as HAIP requires. Without attesters nothing changes.

## Authorization code flow in Certify's own authorization server

Once a client is registered under `certify.as.clients.<client-id>.redirect-uris`, the authorization server metadata advertises `authorization_endpoint`, `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests`, and wallets run the authorization code flow with pushed requests and PKCE (`S256`) against `POST /oauth/par`, `GET /oauth/authorize` and `POST /oauth/token`. The subject of an authorization comes from `certify.as.authorization.subject-mode`: `none` (default) refuses, `fixed` approves every request for `certify.as.authorization.fixed-subject` without user interaction, which is meant for conformance runs and demos only. Deployments without registered clients see no change.

## Holder keys as `did:key` with RSA

A proof whose `kid` is an RSA `did:key` (multicodec `0x1205`) was decoded by 1.0.0-beta.1 but never verified: the resolver built the key without its `kid`, so signature verification found no matching key and the request failed with `invalid_proof`. It verifies now on both surfaces. Every other holder key form (`jwk` header with P-256, Ed25519 or RSA; `kid` as `did:jwk` or `did:key` with Ed25519, P-256 or secp256k1) is unchanged and covered by `HolderDidMethodsTest`; see `docs/design/18-compatibility-validation.md`.

## Key attestations on the new surface

`POST /oid4vci/credential` validates a `key_attestation` JOSE header on `jwt` proofs and accepts the `attestation` proof type (OpenID4VCI 1.0 Appendix D and F): the attestation must be typed `key-attestation+jwt`, signed by an attester configured under `certify.protocol.oid4vci-v1.key-attestation.attesters.<id>` (`jwks`, or `trust-anchor` for an `x5c` chain), unexpired, and carry the proof key in `attested_keys`; a configuration that lists `key_attestations_required` under `proof_types_supported.jwt` refuses proofs without one and checks the accepted `key_storage` and `user_authentication` values. One credential is issued per attested key, within `batch_size`. Compatibility surfaces are unchanged (`attestation` proofs answer `unsupported_proof_type` there, as any unknown type did).

## `did:web` holder keys, and `did:key` in the advertised default

A proof whose `kid` is a `did:web` DID URL is resolved by fetching the DID document over HTTPS when `certify.protocol.oid4vci-v1.did-web-holders.enabled=true` (`timeout` per fetch, default 5 s); the verification method named by the `kid` supplies the key as `publicKeyJwk` or `publicKeyMultibase`, and the credential is bound to the `kid`. Off by default, so nothing changes for deployments that do not set it. The local profile's `cryptographic-binding-methods-supported` default now lists `did:jwk` and `did:key` for `ldp_vc` and `dc+sd-jwt`, the methods the issuer resolves without configuration (the compose profile already did); a deployment that enables `did:web` holders adds `did:web` to its own default or per configuration.

## P-256 keys with a leading zero byte

The DID document encoded the P-256 `publicKeyMultibase` from a minimal-length X coordinate, so for about one key in 256 (an X starting with a zero byte) `did.json` published a wrong point and no verifier could check credentials signed with that key; the `did:key` holder resolver built JWK coordinates the same way, changing the thumbprint of such holder keys. Both are fixed-width now. A deployment whose P-256 signing key is affected publishes the right key after upgrading, without a key change.

## VC-API issuer endpoints

With `certify.protocol.vc-api.enabled=true`, `POST /vc-api/credentials/issue` (W3C VCALM, the CCG VC-API) takes `{credential, options}` from a client registered under `certify.protocol.vc-api.clients.<id>` (HTTP Basic with the client id and `secret`; `credential-configurations` optionally limits what it may issue), signs the body with the `ldp_vc` configuration of `issuanceStrategy: SUPPLIED` whose `@context` and `type` match, and answers `201 {verifiableCredential}`; refusals are `application/problem+json`. `POST /vc-api/credentials/status` updates a status list entry named in the request or found through the ledger by `credentialId`. Today's `POST /credentials/status` is unchanged; nothing is served under `/vc-api` unless enabled.

## Four defects found by the workflow run

The v1 and v2 configuration APIs evicted the `issuerMetadataCache` through `@CacheEvict`, which fails with "Cannot find cache" on a deployment whose `mosip.certify.cache.names` does not list that name (every deployment upgrading with its own list); the eviction is programmatic and tolerant now, and the name is still worth adding to the list so metadata is cached. The service jar lacked `certify-keyprovider-jca`, which the x509-file provider needs, because the service declared it with test scope; enabling `certify.keyprovider.x509-file` failed at startup with `ClassNotFoundException`. The compose stack's `certify_init.sql` created `status_list_credential.capacity` where the DDL and the entity say `capacity_in_kb` (renamed in 0.13.0), so status lists failed on a fresh compose stack. And once a Token Status List existed, a Bitstring credential issued afterwards was given an index on that JWT list because the Bitstring lookup ignored the list type; the lookup is type-aware now. All four fixed.

## Offer page

With `certify.offer-page.enabled=true`, `{servletPath}/offer/` serves a page that creates a pre-authorized credential offer for a chosen configuration and subject, shows the `openid-credential-offer://` deep link as a QR code for a wallet, and can run the pre-authorized code flow itself (token, `c_nonce`, a proof signed in the browser, the credential). Off by default.

## Metadata location for the `/oid4vci` surface

OpenID4VCI 1.0 (section 12.2.2) forms the metadata URL of a Credential Issuer Identifier with a path by inserting `/.well-known/openid-credential-issuer` between host and path, so the new surface's document must also be reachable at `https://<host>/.well-known/openid-credential-issuer/v1/certify/oid4vci` (and `.../v1/certify/t/<tenant>/oid4vci` for path tenants). Certify keeps serving it under the servlet path; the compose stack's nginx maps the inserted form, and a deployment's proxy must do the same (`docs/design/15-deployment.md`).
# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm



```
moved client.zip to build time dependency in dockerfile - addition of new hsm-client zip can be done by adding it to volume mount in docker-compose or helm charts with same structure as [client.zip](https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip)

---

# Changes in release 0.12.0

## Restructure of credential_template table

Step-by-Step Migration guide for upgrade from 0.11.0 to 0.12.0 is available at [Migration Guide](./Migration_Guide_0.11.0_To_0.12.0.md)