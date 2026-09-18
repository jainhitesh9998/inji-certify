# P2-10 The path tenant resolver

Branch: `wp/p2-10-path-tenant-resolver` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-03, P2-05, P2-07.

## Goal

The second resolver docs/design/09 and 14 name: `certify.tenancy.resolver=path` serves a tenant under `{domain}{servletPath}/t/{tenant}/oid4vci/...` for deployments that cannot give every tenant a host name. P2-03 left it "waiting for path routing".

## Scope

- `PathTenantResolver`: the segment after `/t/` in the request path, recognised only for tenants configured under `certify.tenancy.tenants.<id>`; anything else is the default tenant (as the host resolver treats an unknown host). `TenancyConfiguration` selects it for `resolver=path`.
- `TenantContexts.forRequest`: a path-resolved tenant without its own `issuer-identifier` gets `{deployment identifier}/t/{tenant}`, so the adapter's `/oid4vci` suffix and every endpoint hang under it.
- The new-surface controllers (credential, discovery with nonce, notification) are mapped at both `/oid4vci` and `/t/{tenant}/oid4vci`; `Oid4vciSecurityConfiguration` matches `/t/*/oid4vci/**` too (the token filters already match any `/oid4vci/` path).
- Tests: `PathTenantResolverTest`; `PathTenancyIssuanceTest` (metadata, nonce, credential with the tenant's DID in issuer and verification method, notification under `/t/acme/oid4vci`; the default surface unchanged; an unknown path tenant answers the default document; acme's configuration invisible from the default surface).

## Outside scope

The RFC 8615 host-root form `/.well-known/openid-credential-issuer/t/{tenant}/oid4vci`, path-based DIDs (`did:web:host:t:acme`), path routing for the compatibility and draft-13 surfaces, the v2 configuration API under a tenant path (rows are placed by hand or by an operator with the tenant's host until then).

## Acceptance criteria

- [x] `PathTenantResolverTest`, `PathTenancyIssuanceTest`, `TenancyIssuanceTest`, `HostTenantResolverTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (983 tests, 0 failures).
- [ ] CI green on the fork.
