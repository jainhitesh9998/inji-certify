# P2-11 Per-tenant issuer display and authorization servers

Branch: `wp/p2-11-tenant-issuer-display` off `design/extensibility`. Phase 2. Size: XS. Depends on: P2-05.

## Goal

docs/design/14-configuration.md lists `certify.tenancy.tenants.<id>.*` as overrides of the deployment's issuer settings; P2-05 left the tenant document with the deployment's `display` and `authorization_servers`. A tenant now names its own.

## Scope

- `TenancyProperties.Tenant` gains `display` (the issuer display list, `name`/`locale`/logo as in `mosip.certify.credential-config.issuer.display`) and `authorization-servers`; both optional, the deployment's values apply when absent.
- `TenantIssuerMetadata.document` uses them for the tenant's `/oid4vci` metadata document; the default document is untouched.
- `PathTenancyIssuanceTest` configures both for the `beta` tenant and checks the tenant and default documents; the host test keeps a tenant without overrides.

## Outside scope

Per-tenant token validation against the tenant's authorization server (the token filter still validates against the deployment's issuer and JWKS), per-tenant keys.

## Acceptance criteria

- [x] `PathTenancyIssuanceTest`, `PathTenantResolverTest`, `TenancyIssuanceTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (983 tests, 0 failures).
- [ ] CI green on the fork.
