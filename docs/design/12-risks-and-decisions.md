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

- [ ] Which wallet versions in production speak draft 13 today, and must the first develop-based release serve them (decides whether `oid4vci-d13` is on by default)?
- [ ] One `credential_issuer` serving both protocol versions on the same path, or a second issuer URL under `/oid4vci` for 1.0?
- [ ] HAIP: is the embedded `certify-as` or eSignet the authorization server for PAR and wallet attestation?
- [ ] Which additional key provider comes first: PKCS#11, a specific cloud KMS, or the file provider only for tests and the CLI?
- [ ] Tenant isolation to prepare for: shared schema with `tenant_id` (recommended default), schema per tenant, or database per tenant?
- [ ] Should the nonce endpoint be advertised by default in 1.0.0 (`allow-c-nonce=true`) as the spec expects?
- [ ] Keep Velocity as the default engine and add `jsonmap`, or move the shipped samples to `jsonmap` and keep Velocity for compatibility only?
- [ ] Status for SD-JWT and mDoc: IETF Token Status List, or Bitstring referenced from a `status` claim?
- [ ] Do the `verify-core` tables stay in the `certify` schema with a `verify_` prefix, or move to their own schema?
- [ ] Is presentation during issuance a product commitment or an experiment?


## Decision log

Record every decision taken while building, newest first. A work package that needs a decision not listed here stops and asks.

| Date | Decision | Options considered | Chosen | By | Affects |
| --- | --- | --- | --- | --- | --- |
| 2026-09-18 | Keymanager stays an embedded library and the default key provider; no HTTP or remote keymanager option | embedded library; remote keymanager service | embedded, wrapped as `certify-keyprovider-keymanager` | project owner | signing, database, CLI |
| 2026-09-18 | Multi-tenancy is off by default but the code is tenant-ready (`TenantContext`, defaulted `tenant_id` columns) | none; tenant-ready; full multi-tenant | tenant-ready | project owner | core, persistence, adapters |
| 2026-09-18 | Design baseline is `develop` (`a1cfd63`), not the 0.14.0 release | master; develop | develop | project owner | everything |
