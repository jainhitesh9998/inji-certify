# Risks, open questions and decisions needed

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

The two largest risks are shipping develop to a deployment whose wallets still speak draft 13, and changing signature bytes while wrapping keymanager; both are closed by Phase 0 artefacts that exist before any refactor starts.

| Risk | Impact | Mitigation |
| --- | --- | --- |
| A develop-based release reaches wallets that speak draft 13 | Issuance stops for those wallets | Confirm which wallet versions are in production before the first develop release; ship `oid4vci-d13` in P1 and default it on where such wallets exist |
| Signature bytes change while routing keymanager through the envelope builders | Verifiers with pinned expectations, cached `kid` values or `x5t` checks reject credentials | Golden signature vectors per path recorded in P0; ECDSA compared by verification; the keymanager provider calls keymanager's native envelope methods rather than `signRaw` |
| Extracting keymanager's wiring out of `CertifyServiceApplication` and `AppConfig` breaks its auto-configuration | Service fails to boot or keys are not found | The provider module reproduces the exact package list; an integration test boots only the provider against the keymanager tables |
| Golden tests miss behaviour a wallet relies on (error bodies, header casing) | Silent breakage in P1 | Record goldens from real Inji Wallet and mimoto traffic as well as hand-written cases; weekly wallet interop from P0 |
| Keymanager stays the only provider in practice and its DTOs leak back across the seam | The signing SPI becomes decorative | ArchUnit rule from P0; the `jca` provider in the test kit from P1; PKCS#11 in P5 |
| Tenant columns and index rebuilds on large `ledger` tables | Long migration lock on big deployments | Add `tenant_id` with a default and build indexes `CONCURRENTLY` in a separate migration step; rehearse on a production-sized dump |
| `verify-core` and keymanager tables in the `certify` schema drift with their own upgrades | Migration conflicts between three owners | Per-module Flyway locations from P0; verify tables owned by `certify-as` |
| HAIP's PAR and wallet attestation belong to the AS, which in production may be eSignet | P4 effort spent on `certify-as` that deployments will not use | Decide the target AS before P4; if eSignet, P4 ships the issuer half plus a written AS contract |
| Dual-write of config v1 and v2 drifts | Wrong metadata for some configurations | One write-through service; the migration-verifier test compares legacy and JSONB reads for every row |
| Plugin authors stay on `certify-integration-api` | Legacy adapters cannot be removed in 2.0.0 | Two-release guarantee, `certify-spi-testkit`, a mechanical mapping table in the migration guide |
| Presentation during issuance (IAE) is a draft extension that 1.0 may not carry | Core shaped around an unstable flow | Keep IAE in `certify-as` behind a feature flag; the core never depends on it |
| Re-layering turns into feature work | P1 slips and cannot be released | Rule: P1 ships zero behaviour change; new capability only from P3 |
| CI has no Docker for Testcontainers | Database tests cannot run per PR | Confirm the `kattu` workflows' runners; fall back to a PostgreSQL service container |
| A CLI run with the keymanager provider needs the keymanager database and HSM | Offline signing is not possible with keymanager keys | Documented; offline runs use the PKCS#11 or PKCS#12 provider |

Decisions needed from the team before P2:

- [x] Draft-13 wallets: decided 2026-09-18, `oid4vci-d13` is built in P1 and on by default, deprecated from day one.
- [x] Issuer surface: decided 2026-09-18, a new spec-clean surface under `{domain}{servletPath}/oid4vci` with today's paths kept as a deprecated compatibility surface.
- [x] Keymanager: decided 2026-09-18, kernel-keymanager stays the embedded default provider; other key managers plug in above it; no remote keymanager.
- [ ] Where do agent work packages land: PRs straight to `develop` behind the gates, an integration branch, or the fork only for now?
- [ ] Flyway run mode: Helm pre-upgrade Job plus startup in compose (recommended), startup everywhere, or baseline only for now? Is Docker available on the CI runners for Testcontainers?
- [ ] HAIP: is the embedded `certify-as` or eSignet the authorization server for PAR and wallet attestation?
- [ ] Which additional key provider comes first: a cloud KMS, Vault, or the file provider only for tests and the CLI?
- [ ] Tenant isolation to prepare for: shared schema with `tenant_id` (recommended default), schema per tenant, or database per tenant?
- [ ] Should the nonce endpoint be advertised by default on the compatibility surface too (`allow-c-nonce=true`)?
- [ ] Keep Velocity as the default engine and add `jsonmap`, or move the shipped samples to `jsonmap` and keep Velocity for compatibility only?
- [ ] Status for SD-JWT and mDoc: IETF Token Status List, or Bitstring referenced from a `status` claim?
- [ ] Do the `verify-core` tables stay in the `certify` schema with a `verify_` prefix, or move to their own schema?
- [ ] Is presentation during issuance a product commitment or an experiment?


## Decision log

Record every decision taken while building, newest first. A work package that needs a decision not listed here stops and asks.

| Date | Decision | Options considered | Chosen | By | Affects |
| --- | --- | --- | --- | --- | --- |
| 2026-09-18 | Draft-13 support: `oid4vci-d13` adapter built in P1, on by default, deprecated from day one | not supported; built but off; on by default | on by default | project owner | P0-02, P1-12, deprecation counters |
| 2026-09-18 | Protocol surface: new spec-clean OpenID4VCI 1.0 surface under `{domain}{servletPath}/oid4vci` with its own issuer identifier; today's paths kept as a deprecated compatibility surface over the same core | same path only; second issuer URL only; both | new surface plus deprecated old surface | project owner | `oid4vci-v1`, API compatibility, metadata, tenancy prefix |
| 2026-09-18 | Keymanager: MOSIP kernel-keymanager stays an embedded library and the default key provider; no HTTP or remote keymanager option; keymanager already covers HSM backends (PKCS#11, PKCS#12, offline), so Certify's `KeyProvider` SPI is for other key managers (cloud KMS, Vault, file, X.509 providers, other libraries) | embedded library; remote keymanager service | embedded, wrapped as `certify-keyprovider-keymanager` | project owner | signing, database, CLI |
| 2026-09-18 | PKI-based formats (mDoc/mDL, SD-JWT VC with `x5c`) get a separate `x509` provider family, a per-format `CertificateChainPolicy` and trust-anchor publication, usable without keymanager tables | keymanager CSR flow only; separate providers | separate providers plus policy | project owner | signing, mDoc, SD-JWT, database (`trust_anchor`) |
| 2026-09-18 | Multi-tenancy is off by default but the code is tenant-ready (`TenantContext`, defaulted `tenant_id` columns) | none; tenant-ready; full multi-tenant | tenant-ready | project owner | core, persistence, adapters |
| 2026-09-18 | Design baseline is `develop` (`a1cfd63`), not the 0.14.0 release | master; develop | develop | project owner | everything |
