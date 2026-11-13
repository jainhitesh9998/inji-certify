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

## Offers on the `/oid4vci` surface

`POST /pre-authorized-data` accepts an optional `issuer` (`oid4vci` or `legacy`, case-insensitive, blank means absent; absent, `certify.protocol.oid4vci-v1.offers.default-issuer`, `legacy` unless set) and an optional `offer_by_value`. An `oid4vci` offer names the `/oid4vci` identifier in `credential_issuer`, and the access token its code is exchanged for is addressed to that surface's credential endpoint, so the wallet can redeem it at `POST /oid4vci/credential` without the deployment adding an audience. `offer_by_value: true` returns the offer document as `credential_offer` next to the `openid-credential-offer://` deep link (which then carries the offer, URL-encoded per RFC 3986, instead of a pointer). The `/oid4vci` metadata document now publishes the issuer `display`, and both metadata documents publish `mso_mdoc` signing algorithms from one COSE map. The offer page gains a surface selector, defaults to `/oid4vci` for `mso_mdoc`, returns offers by value, and decodes and shows an `mso_mdoc` credential's IssuerSigned elements and portrait. Behaviour without `issuer`, `offer_by_value` and an `mso_mdoc` configuration is unchanged.

Tenant binding is a property of the `/oid4vci` surface only. A `legacy` offer is tenant-agnostic, exactly as before: its code is redeemed wherever a token is requested and it mints the deployment's configured audience. An `oid4vci` offer created under a non-default tenant (path tenants, `certify.tenancy.resolver=path`) names that tenant's identifier and addresses its token to that tenant's credential endpoint, and a token bound to one tenant is accepted only at that tenant's surface. Two limits are worth stating plainly: `/pre-authorized-data` and `/oauth/token` are served on the deployment's own paths only — the authorization server metadata publishes one token endpoint — so completing an offer created for a non-default tenant needs tenant-aware authorization-server and offer endpoints, which Certify does not provide yet; and a tenant that configures no `issuer-identifier` shares the default `/oid4vci` identifier, and therefore its audience.

`/.well-known/oauth-authorization-server` grows `pre-authorized_grant_anonymous_access_supported` (OID4VCI 1.0 section 12.3) only when the deployment opts in: `certify.as.pre-authorized-grant.advertise-anonymous-access=true`, client attestation is not required, and `grant_types_supported` lists the pre-authorized code grant. The default is off, so an unchanged deployment's authorization server metadata is byte-identical to before.

## Compatibility metadata: `mso_mdoc` signing algorithms

Two changes are visible on the compatibility surface's `/.well-known/openid-credential-issuer`. An `mso_mdoc` configuration whose signing algorithm has no COSE identifier no longer fails the whole metadata document: the value is dropped with a warning (previously an `IllegalArgumentException` answered the request with an error), so the document still advertises everything else, and the configuration is better fixed by choosing ES256, ES384, ES512 or EdDSA. And an ES384 or ES512 configuration now publishes the COSE identifiers -35 and -36, where it previously failed the document for lack of a mapping. ES256, EdDSA, ES256K and RS256 rows are byte-identical to before.

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

## Proof `iss` in the pre-authorized code flow

A `jwt` proof presented with a token from the anonymous pre-authorized code flow may carry `iss` equal to the holder's own DID (the `did:jwk` of the proof key, or its `kid` without the fragment), which Inji Wallet sends to issuers with a nonce endpoint; OpenID4VCI 1.0 asks wallets to omit `iss` there, and the value names nothing the signature does not prove. A client_id, when known, must still match `iss`; any other value is still refused. The compose stack's seeded `FarmerCredential` now advertises EdDSA next to RS256, PS256 and ES256, as the deployment default does, so Inji Wallet's Ed25519 proofs are accepted there.

## mDoc output from the refactored formatter follows ISO/IEC 18013-5

The refactored `mso_mdoc` formatter (`certify-format-mdoc`, decision D1 of `docs/design/20-mdl-issuer.md`) serves `/oid4vci`, the draft-13 endpoints (`/issuance/credential` with the 0.14.0 body, `/issuance/vd12/credential`, `/issuance/vd11/credential`) and, only when `certify.protocol.oid4vci-v1.compat-core.enabled=true`, the compatibility endpoint `POST /issuance/credential`. Credentials from those paths change on the wire as listed below. With `compat-core` off (the default), `POST /issuance/credential` still runs the legacy `utils.MDocProcessor`, and its mDoc output is unchanged (the `legacy-develop` golden).

- `validityInfo` timestamps are `tdate` (`#6.0`) strings with whole seconds only (`2026-11-13T10:15:30Z`), never fractional seconds (9.1.2.4).
- `digestID`s are random distinct unsigned integers in `0..2^31-1` per namespace; the template's `digestID` values are ignored (9.1.2.5). Verifiers must look items up by the identifier they carry, not by position.
- The IssuerAuth `x5chain` carries the document signer certificate and its intermediates, never the self-signed IACA (HAIP); a configuration whose key has no certificate chain, or with `signing.x5c` `none` (also refused at save on the v2 API), or `leaf` with intermediates, now fails with `certificate_chain_invalid` instead of issuing an mDoc without `x5chain`.
- Element values are typed by ISO/IEC 18013-5 Table 5 for namespace `org.iso.18013.5.1` (`portrait` and the biometric templates are `bstr` from base64, `birth_date` `#6.1004`, `issue_date`/`expiry_date` `full-date` or `tdate`, `driving_privileges` an array of maps, `age_over_NN` `bool`, `sex`/`height`/`weight` `uint`) and by `formatConfig.elementTypes` elsewhere; untyped namespaces keep the `YYYY-MM-DD` heuristic, but only inside element values (identifiers, namespace names and `docType` stay text), and integers beyond 64 bits stay CBOR integers (bignums) instead of text.
- The MSO's default validity is 90 days (`certify.format.mdoc.mso-validity`, a `Duration`, at least one minute) instead of two years, capped at the document signer certificate's `notAfter` and at an mDL's `expiry_date`. When `mso-validity` is not set, `certify.format.mdoc.validity-period-years` and then the 1.0.0-beta.1 key `mosip.certify.mdoc.validity-period-years` apply, in that order; likewise `certify.format.mdoc.digest-algorithm` falls back to `mosip.certify.mdoc.digest-algorithm`, then `SHA-256`. The formatter logs once at startup which key decided each value. A deployment that set neither validity key gets 90 days on these paths where the legacy service gave two years. An mDL whose `expiry_date` has passed, or is today, is refused.
- For the `org.iso.18013.5.1.mDL` doctype the document is validated before signing (`mdoc_data_model_invalid`): every mandatory Table 5 element, `issuing_country` equal to the document signer certificate's country, `un_distinguishing_sign` 1-3 upper-case letters, and a JPEG-only `portrait` (complete, at most 1 MiB and 4096x4096 pixels, decodable without errors); JPEG 2000 portraits are no longer accepted.
- The device key is taken from the proof's `did:jwk`, `did:key` or JWK as P-256/P-384/P-521 (EC2) or Ed25519 (OKP) without an `alg` label; a holder key the MSO cannot carry (another curve, EC coordinates shorter than the field width, a point off the curve, an Ed25519 key that is not a valid point) is answered `400 invalid_proof` instead of `500`.

Changes on those paths that can make a configuration that issued before now fail (check them before switching on `compat-core` or moving wallets to `/oid4vci` or draft-13):

- The template's `docType` must equal the configuration's `doctype`; a mismatch is a template error instead of an mDoc whose MSO names another document type (G7).
- The configured `digestAlgorithm` is now actually used to compute the digests (G5): a deployment that set `SHA-384` or `SHA-512` previously issued SHA-256 digests labelled with that algorithm, and now issues digests of that algorithm.
- Text-typed Table 5 elements refuse JSON numbers: a numeric `document_number` (or `family_name`, `issuing_authority`, ...) in the template is `mdoc_data_model_invalid`; quote it.
- `issuing_jurisdiction` must be an ISO 3166-2 subdivision of `issuing_country`; `nationality` and `resident_country` ISO 3166-1 alpha-2 codes; `sex` an ISO/IEC 5218 code (0, 1, 2 or 9); `issue_date` before `expiry_date`; `issue_date` and `birth_date` not after the issuance date.
- Startup fails unless `certify.format.mdoc.mso-version` is `1.0` and the configured validity is positive (`mso-validity` at least one minute, either `validity-period-years` above zero).
- A "complete JPEG" `portrait` ends with its EOI marker (`FF D9`) as the last two bytes, so padding or metadata appended after EOI is refused; and it must decode with the JDK JPEG reader, which reads YCbCr and greyscale JPEGs only, so a CMYK or YCCK portrait is refused.
- A signing key whose certificate is self-signed (a plain dev key with no CA) is refused with `certificate_chain_invalid`: an ISO/IEC 18013-5 Annex B document signer is issued by an IACA. Keymanager keys (signed by the keymanager root) and `x509-file` dev keys (signed by the dev CA) are not affected.

## Annex B keys in the `x509-file` provider

The `x509-file` provider can generate an ISO/IEC 18013-5 Annex B IACA and Document Signers in dev mode (`certify.keyprovider.x509-file.iaca`, `keys[].profile: mdoc-dsc`), import a Document Signer key and `[DSC, IACA]` chain from PEM files (`pem-keys`), and rotate keys as `alias@version` entries; the gauge `certify.signing.key.expires_in_days{keyRef}` and a WARN 30 days ahead report every current signing certificate, keymanager's included (`docs/design/20-mdl-issuer.md` M-05). Configurations without these settings are unchanged, with one exception: a Document Signer (a certificate carrying the mDL extended key usage `1.0.18013.5.1.2`) held as a single unversioned entry in an existing keystore no longer resolves once it has expired or before it is valid, because every verifier rejects an mDL signed outside its Document Signer's validity; a plain key with a single entry still resolves whatever its dates, as before.

## mDoc Document Signer policy and IACA publication

An issuer can name the ISO/IEC 18013-5 IACAs its mDoc Document Signers chain to (`certify.pki.trust-anchors.mdoc-iaca[].{id, certificate, crl}`, PEM or DER; the `x509-file` provider's IACAs are added automatically), and can publish them (`docs/design/20-mdl-issuer.md` M-06 and M-08). Nothing changes for a deployment that configures neither: no IACA means the policy below is not enforced (the service logs that once at startup), mDocs are signed exactly as before, keymanager chains stay the certificate alone, and nothing is published.

- **Once at least one IACA is configured, or the `x509-file` provider holds one, every `mso_mdoc` signature on every surface (`/oid4vci`, the draft-13 endpoints, the compatibility endpoint through the core) is checked against them and refused with `certificate_chain_invalid` naming the rule** when the Document Signer was issued by none of them (`DSC_NO_TRUSTED_IACA`; this is the case for keymanager's own certificates, signed by its root), when the signing instant lies outside the DSC's validity (`DSC_NOT_YET_VALID`, `DSC_EXPIRED`) or the IACA's (`IACA_NOT_YET_VALID`, `IACA_EXPIRED`), when the DSC or the IACA breaks its Annex B profile (the `certify-pki` rule, such as `DS_EKU_MISSING`), or when the IACA's CRL lists the DSC (`DSC_REVOKED`). A deployment that adds an IACA while it still signs mDocs with keymanager keys must move those configurations to a DSC the IACA issued: the keymanager CSR flow (`/system-info/generate-csr`, the IACA signs it, `uploadCertificate`) or an `x509-file` key. The v2 configuration API's dry run and `POST /v2/credential-configurations/{id}/preview` run the same check and answer `400 template_render_failed` with the rule.
- A keymanager certificate that a configured IACA issued (the CSR flow) is returned with that IACA as `[DSC, IACA]`, so the policy can check it; the IssuerAuth still carries the DSC alone (`without-anchor`), and the JWKS lists the IACA after the DSC in that key's `x5c`.
- Startup fails when a configured IACA does not meet the Annex B IACA profile, when a configured CRL is not a valid CRL of its IACA, or when two anchors share an id. CRL files are re-read when they change (`certify.pki.trust-anchors.crl-refresh-interval`, default five minutes); a changed file that does not validate is logged and the previous CRL stays in use. In `x509-file` dev mode the service issues an empty CRL for the dev IACA, valid for `certify.pki.trust-anchors.dev-crl-validity` (seven days) and re-issued half way.
- `certify.pki.publication.enabled=true` serves, without authentication and read-only, `GET /mdoc/iaca` (a JSON list of `{id, subject, country, sha256, notBefore, notAfter, pem, der, crl}`, the downloads as references relative to the list's URL) and `GET /mdoc/iaca/{id}.pem` (`application/x-pem-file`), `.der` (`application/pkix-cert`) and `.crl` (`application/pkix-crl`, DER, cached until its nextUpdate and at most an hour; `404` when the IACA has no CRL). An IACA's id is `certify.pki.trust-anchors.mdoc-iaca[].id`, else the `<id>` of its own CRL distribution point `…/mdoc/iaca/<id>.crl`, else its subject key identifier in hex, so the distribution point to write into an IACA is `https://<host>/v1/certify/mdoc/iaca/<id>.crl`. The compose nginx passes `GET`/`HEAD` under `/v1/certify/mdoc/iaca` from the public host and refuses every other method.

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