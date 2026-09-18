# P0-08 CredentialRegistry read path and metadata cache

Branch: `wp/p0-08-credential-registry` off `develop`. Phase 0 (guardrails). Size: M. Depends on: P0-01, P0-07.

## Goal

Stop rebuilding issuer metadata with `findAll()` on every credential request and give the core one lookup API for configurations.

## Scope

- `CredentialRegistry` interface in `certify-core` (`byId(tenant, id)`, `byScope(tenant, scope)`, `bySelector(tenant, format, selector)`, `all(tenant)`) with a JPA-backed implementation and a Spring cache `credentialRegistry` evicted on every config write.
- `fetchCredentialIssuerMetadata()` and `DIDDocumentUtil` read from the registry; `CertifyIssuanceServiceImpl` and `VCIssuanceServiceImpl` resolve the configuration through the registry instead of the metadata DTO.
- Metadata itself cached under the existing `issuerMetadataCache` name, evicted on config writes.

## Acceptance criteria

- [ ] Goldens unchanged.
- [ ] A credential request performs at most one `credential_config` read on a warm cache (assert with Hibernate statistics).

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
