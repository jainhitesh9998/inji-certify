# P2-05 Per-tenant issuer metadata on the new surface

Branch: `wp/p2-05-tenant-metadata` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-03.

## Goal

"A tenant-specific `credential_issuer` yields a tenant-specific `.well-known` document" (docs/design/05): `GET /oid4vci/.well-known/openid-credential-issuer` for a request resolved to a tenant other than `default` lists that tenant's configurations under the tenant's own issuer identifier, credential and nonce endpoints. The default tenant keeps the document develop builds, so the goldens stay untouched.

## Scope

- `TenantIssuerMetadata`: the document built from the core's view (`ConfigurationRegistry.all(tenant)`): each entry is the formatter's metadata fragment plus `scope`, `cryptographic_binding_methods_supported`, `credential_signing_alg_values_supported` (COSE identifiers for mDoc, as the default document has), `proof_types_supported` and `credential_metadata` (display and claims with `path`); authorization servers and issuer display are the deployment's for now.
- `Oid4vciDiscoveryController.issuerMetadata` picks the tenant from the request-scoped `AuthorizationContext` and the tenant's `/oid4vci` identifier through `TenantContexts` and `Oid4vciIssuer.derive`.
- The legacy document builder (`CredentialConfigurationServiceImpl.fetchCredentialIssuerMetadata`) and the draft-13 one keep only the default tenant's rows, so a tenant's configuration never appears in the deployment's documents.
- `TenancyIssuanceTest.theHostSelectsTheIssuerMetadataDocument`: the acme document and the untouched default one.

## Outside scope

Per-tenant issuer display and authorization servers (`certify.tenancy.tenants.<id>.*` overrides of `certify.issuer`), per-tenant `did.json` and `jwks.json`, the compatibility surface's document (default tenant only).

## Acceptance criteria

- [x] `TenancyIssuanceTest` green (issuance and metadata); `IssuanceGoldenTest` (metadata goldens) unchanged.
- [x] Full `certify-service` suite green (968 tests, 0 failures).
- [ ] CI green on the fork.
