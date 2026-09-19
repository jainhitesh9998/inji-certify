# P2-07 Tenant DID documents and verification methods

Branch: `wp/p2-07-tenant-did-document` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-03 (tenant resolver), P2-05 (per-tenant metadata).

## Goal

A credential issued in a tenant's context must verify from the tenant's own DID: today the template names the tenant's DID as `issuer` while the proof's `verificationMethod` still points at the deployment's DID (`SigningConfig.issuerDid` from the row's `did_url`), and `GET /.well-known/did.json` on the tenant's host answers the deployment's document. Rule 2 of `CLAUDE.md` (a complete, resolvable verification method) applies to tenants too.

## Scope

- Core: `DefaultIssuanceService.issueOne` signs with `configuration.signing().withIssuerDid(tenant.issuerDid())` when the request's `TenantContext` carries a DID that differs from the row's; requests without a tenant DID (every default-tenant request, every compatibility and draft-13 request: the adapters pass `null`) are untouched, so the goldens stay byte-identical.
- `WellKnownController.getDIDDocument`: a request resolved to a tenant with `certify.tenancy.tenants.<id>.issuer-did` gets `DIDDocumentUtil.generateDIDDocument(tenantDid)`: the same keys and verification methods, published under the tenant's DID (`id`, `assertionMethod`, `authentication`, `<did>#<kid>`); the default tenant keeps the deployment's document (`goldens/legacy-develop/did.json`). The dependencies are `ObjectProvider`s so the `@WebMvcTest` slice of the controller is unchanged.
- `TenancyIssuanceTest`: the acme credential's `proof.verificationMethod` starts with the acme DID, the acme host's `did.json` names that DID and lists that verification method, and the proof verifies with danubetech's Ed25519Signature2020 verifier against the key taken from the tenant's document; the default host's document is unchanged.

## Outside scope

Per-tenant keys (`keyNamespace` is carried, not applied), per-tenant `jwks.json` (identical keys today), the ledger's issuer column for tenant issuances (still the row's `did_url`), `did:web` path-based DIDs for the `path` resolver, the draft-13 `/issuance/.well-known/did.json`.

## Acceptance criteria

- [x] `TenancyIssuanceTest` green with the new assertions; `IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `StatusListPostgresTest`, `WellKnownControllerTest` green; no golden changed.
- [x] Full `certify-service` suite green (975 tests, 0 failures).
- [ ] CI green on the fork.
- [x] Decision logged: the tenant DID overrides the row's `did_url` at signing time; tenant DID documents share the deployment's keys.
