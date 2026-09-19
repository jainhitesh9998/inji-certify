# P1-11 oid4vci-v1 adapter (first slice): POST /oid4vci/credential through the new core

Branch: `wp/p1-11-oid4vci-adapter` off `design/extensibility`. Phase 1. Size: L, delivered in slices. Depends on: P1-01, P1-02, P1-03, P1-05, P1-08, P1-09, P1-11a.

## Goal

The spec-clean surface exists and issues a credential end to end through `DefaultIssuanceService`: registry over `credential_config`, `TemplateEngine`, `DataProviderPlugin`, jwt proof adapter, `KeyProviderRegistry`, `ldp_vc` formatter. Today's paths are untouched.

## Scope (this slice, package `io.mosip.certify.oid4vci` inside certify-service until the P1-13 split)

- `POST {servletPath}/oid4vci/credential` (`Oid4vciCredentialController`): OpenID4VCI 1.0 request (`credential_configuration_id`, `proofs`), `IssuanceCommand` built from the request-scoped `AuthorizationContext`, the configuration's `proof_signing_alg_values_supported`, the issuer identifier as proof audience, and the cache-backed nonce check; response `{"credentials":[{"credential":...}]}` (202 with `transaction_id` for deferred results); errors as `{error, error_description}` with the core's spec-named codes (`invalid_credential_request`, `unsupported_credential_type`, `invalid_proof`, `invalid_nonce`, `invalid_scope`; 401 `invalid_token`; 500 `server_error`).
- Adapter-declared security (rule 9): a `SecurityFilterChain` for `/oid4vci/**` (permit, stateless, csrf off) plus the adapter's own token filters, subclasses of the service's `AccessTokenValidationFilter` (`!local`) and `LocalAccessTokenValidationFilter` (`local`) that apply to every `/oid4vci/` request; no URL list changes.
- `Oid4vciIssuanceConfiguration`: the `IssuanceService` bean over the registry, every `CredentialFormatter`/`TemplateEngine`/`ProofValidator` bean, the key providers, `DataProviderPluginDataSource` (token claims + `accessTokenHash` as identity details, as the legacy path passes them) and `CacheNonceCheck` (`POST /nonce` cache with expiry); validity from `mosip.certify.data-provider-plugin.vc-expiry-duration`.
- Both template engines resolve `_issuer` from the configuration's `didUrl` when the tenant has no issuer DID (legacy rows).

## Not in this slice

(all three formatters now serve the new surface: P1-05, P1-06, P1-07), issuer metadata and nonce endpoints under `/oid4vci`, deferred and notification endpoints, credential response encryption, status attachment and ledger/audit listeners (P1-10), the credential `id`/`credentialStatus` post-processing the legacy `VCFormatter` performs, deprecation headers on the old paths (P3), HAIP profile.

## Acceptance criteria

- [x] `IssuanceGoldenTest.oid4vciLdpVcIssuanceGoldenAndIndependentVerification`: an Ed25519Signature2020 `ldp_vc` issued through the new surface from the same configuration and proof as the legacy golden, verified with danubetech against `did.json`; golden recorded under `goldens/oid4vci-1.0/oid4vci`.
- [x] Spec error names on the new surface (`invalid_credential_request`, `invalid_nonce`).
- [x] Legacy goldens unchanged; ArchUnit unchanged.
- [x] Full `certify-service` suite green: 891 tests.

## Second slice (branch `wp/p1-11-oid4vci-discovery`): discovery

- `Oid4vciIssuer`: the new surface's Credential Issuer Identifier is `mosip.certify.identifier` + `/oid4vci` unless `certify.oid4vci.issuer-identifier` names it; metadata, endpoints, SD-JWT `iss` and the proof audience derive from it.
- `GET /oid4vci/.well-known/openid-credential-issuer`: the compatibility surface's configurations with this surface's `credential_issuer`, `credential_endpoint` and `nonce_endpoint`; `POST /oid4vci/nonce` on the shared c_nonce store (a nonce from either endpoint is valid on either surface). Both are public (the adapter's token filters exempt them).
- Proofs must carry the new identifier as `aud`: `JwtProofValidator` gained an audience-aware overload, the adapter passes `ProofPolicy.audience`, and a compatibility-surface proof is refused on the new surface (`invalid_proof`).
- Golden `v2/oid4vci/openid-credential-issuer`; the SD-JWT payload golden re-recorded with the new `iss`.
- Still open: the well-known document is served under the identifier's path (`{identifier}/.well-known/...`), the form Certify and its nginx mapping use today; OpenID4VCI 1.0 §11.2.2's path-insertion form (`/.well-known/openid-credential-issuer/v1/certify/oid4vci`) is a deployment mapping to add with the nginx configuration.
