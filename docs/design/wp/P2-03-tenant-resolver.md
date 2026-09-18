# P2-03 TenantResolver: tenant-scoped lookups and a host resolver

Branch: `wp/p2-03-tenant-resolver` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-01, P2-02.

## Goal

The tenancy the design keeps ready (`docs/design/05-target-architecture.md`, `14-configuration.md` `certify.tenancy`): every request is resolved to a tenant once, the registry answers per tenant, and each adapter hands the core the tenant's own issuer identifier and DID. Off by default; a single-tenant deployment sees exactly what it saw before.

## Scope

- `TenancyProperties` (`certify.tenancy`): `enabled` (false), `resolver` (`fixed` or `host`), `tenants.<id>.hosts`, `issuer-identifier`, `issuer-did`, `key-namespace`.
- `TenancyConfiguration`: the `TenantResolver` bean of the deployment, `TenantResolver.fixed(default)` unless tenancy is enabled with the `host` resolver (`HostTenantResolver`: the request host, port dropped, mapped through `tenants.<id>.hosts`; unknown hosts are the default tenant). The `path` resolver (`/t/{tenant}` prefix) waits for path routing.
- `TenantResolutionFilter` (only when enabled, before the token filters): resolves the tenant into the request-scoped `AuthorizationContext`.
- `TenantContexts`: the `TenantContext` an adapter hands to the core, with the tenant's overrides over the adapter's defaults. `Oid4vciCredentialController` (a tenant identifier gets this surface's `/oid4vci` suffix), `CoreBackedVCIssuanceService` and `D13IssuanceHandler` use it for the command's tenant, the proof audience and the configuration lookup.
- `JpaConfigurationRegistry` looks configurations up per tenant through new tenant-scoped repository finders (`findByTenantIdAnd...`, `findByTenantId`); the configuration's `tenantId` comes from the row on both read paths.
- Tests: `HostTenantResolverTest` (resolver and `TenantContexts` overrides), `JpaConfigurationRegistryTest.lookupsAreScopedToTheTenant`, `TenancyIssuanceTest` (host resolver end to end on `/oid4vci/credential`: acme's row issues with acme's DID and audience, is invisible to the default tenant, and the default tenant keeps the deployment's values).

## Outside scope

Per-tenant issuer metadata documents and DID documents (the discovery controllers still publish the deployment's), per-tenant key aliases (`keyNamespace` is carried, not yet applied by the key providers), the `path` resolver, writing tenant rows through the config API.

## Acceptance criteria

- [x] `HostTenantResolverTest`, `JpaConfigurationRegistryTest` and `TenancyIssuanceTest` green.
- [x] Goldens (`IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest`, `StatusListPostgresTest`) and ArchUnit unchanged: single-tenant behaviour identical.
- [x] Full `certify-service` suite green (964 tests, 0 failures).
- [ ] CI green on the fork.

## Rules that apply

- Tenant-ready, single-tenant by default (rule 4); typed settings under `certify.tenancy` (rule 9).
- Decision recorded in `docs/design/12-risks-and-decisions.md`.
