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

Decisions taken on 2026-09-18 (details in the log below):

- [x] Draft-13 wallets: `oid4vci-d13` is built in P1 and on by default, deprecated from day one.
- [x] Issuer surface: a new spec-clean surface under `{domain}{servletPath}/oid4vci`; today's paths kept as a deprecated compatibility surface.
- [x] Keymanager: kernel-keymanager stays the embedded default provider; other key managers plug in above it; no remote keymanager.
- [x] Where work lands: branches on `jainhitesh9998/inji-certify` only, integration branch `design/extensibility`; no pull requests to `inji/inji-certify`.
- [x] Flyway and CI: Helm pre-upgrade Job in Kubernetes, startup migration in docker-compose; GitHub Actions on the fork runs the gates with Docker.
- [x] HAIP: both halves; Certify as a HAIP resource server behind any HAIP-capable authorization server, and `certify-as` implementing PAR, PKCE, DPoP-bound tokens and wallet attestation itself.
- [x] First non-keymanager provider: `x509-file` (PKCS#12 or PEM) with a dev mode that generates a key and a test chain at startup.
- [x] Tenant isolation: shared schema with a defaulted `tenant_id` column.
- [x] Templating: Velocity stays the default for existing whole-document templates; SD-JWT and mDoc use a standard claims mapping with format libraries building the envelope; a JSON mapping engine and a no-template path are provided; output validated by JSON Schema per format plus format-specific checks.
- [x] Status for SD-JWT and mDoc: IETF Token Status List; Bitstring stays for W3C credentials.
- [x] `verify-core` tables: stay in the `certify` schema unrenamed, created only by the `certify-as` Flyway location.
- [x] Presentation during issuance (IAE): a supported feature kept in `certify-as` behind a feature flag; the core never depends on it.

## Decision log

Record every decision taken while building, newest first. A work package that needs a decision not listed here stops and asks.

| Date | Decision | Options considered | Chosen | By | Affects |
| --- | --- | --- | --- | --- | --- |
| 2026-09-18 | Legacy LD suites and Data Integrity share danubetech canonicalization in `certify-service` for now; `certify-signing` contributes the proof encodings (`LdLegacyEnvelope`, `SignerByteSigner`) and gains `ld-signatures-java`/`data-integrity-java`; the full LD envelope builder moves with the `ldp_vc` formatter (P1-05) | full builder now; encodings now, builder with the formatter | encodings now | judgement | certify-signing, P1-05 |
| 2026-09-18 | Modules wire themselves into an application through Spring Boot auto-configuration (`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`), never through `@Import` on the application class or extra `scanBasePackages`; test slices then exclude them the standard way | scanBasePackages; @Import; auto-configuration | auto-configuration | judgement | every provider, formatter and adapter module; CLAUDE.md rule |
| 2026-09-18 | Keymanager keys are addressed as `keymanager:APPID/REFID[@keyId]` (empty reference id omitted); the optional version pins keymanager's key id (certificate thumbprint) so a configuration can hold a rotation back deliberately | separate fields; alias grammar | alias grammar | judgement | KeyRef, credential configuration signing block, CLI |
| 2026-09-18 | Algorithm choice within a key family (RS256 vs PS256 on one RSA key) is made by `SigningConfig.algorithm` and applied through `SigningKey.withAlgorithm` in `KeyProviderRegistry`; providers report a key's natural algorithm and refuse cross-family use | header policy carries alg; key carries alg | key copy with the configured alg | judgement | certify-signing, formatters, P1-03 |
| 2026-09-18 | Startup provisioning creates, besides the historical four signing keys, every alias the key-alias-mapper names for an algorithm keymanager can generate (RS256, PS256, ES256, ES256K, EdDSA); unsupported algorithms are logged and skipped | historical four only; mapper only; both | both | judgement | deployments with custom mappers, P1-02 |
| 2026-09-18 | The keymanager provider cannot be switched off until the direct signing call sites are gone (P1-13); the switch `mosip.certify.key-provider.keymanager.enabled` arrives with that WP rather than as a flag that breaks boot today | flag now; flag later | later | judgement | P1-13, configuration |
| 2026-09-18 | The new protocol-agnostic core module is `certify-issuance`, not `certify-core`: the existing `certify-core` artifact (DTOs, `ParsedAccessToken`, `CredentialRegistry`, Spring Web uses) keeps its name and coordinates so plugins built against it keep resolving; it shrinks over Phase 1 and becomes a compatibility shell | rename existing module and reuse `certify-core`; new name | new name `certify-issuance`; design docs read `certify-core` as this module | judgement | P1-*, plugin compatibility, ArchUnit |
| 2026-09-18 | Work lands on branches of `jainhitesh9998/inji-certify` only; integration branch `design/extensibility`; no PRs to upstream | upstream PRs; integration branch; fork only | fork only | project owner | automation, CI |
| 2026-09-18 | Flyway runs from a Helm pre-upgrade Job in Kubernetes and at startup in docker-compose; the application only validates at boot; CI is GitHub Actions on the fork with Docker for Testcontainers | Job; startup everywhere; manual | Job + compose startup | project owner (judgement delegated) | P0-04, P0-05, CI |
| 2026-09-18 | HAIP on both sides: resource-server behaviour works behind any HAIP-capable AS (eSignet is one of several), and `certify-as` implements PAR, PKCE, DPoP-bound access tokens and wallet attestation | issuer half only; both | both | project owner | P4, certify-as, certify-authz |
| 2026-09-18 | First non-keymanager provider is `x509-file` (PKCS#12 or PEM) with a dev mode generating a key and a test IACA-to-DSC chain at startup | KMS; Vault; file | file with dev mode | project owner | P3, tests, CLI |
| 2026-09-18 | Tenant isolation: shared schema with a defaulted `tenant_id` column; schema- or database-per-tenant stays reachable through Hibernate multi-tenancy later | shared schema; schema per tenant; database per tenant | shared schema | project owner | P2 migration, entities |
| 2026-09-18 | Templating: Velocity remains the default engine for existing whole-document (`FULL_DOCUMENT`) templates; SD-JWT and mDoc use a standard claims mapping (`CLAIMS_ONLY`) with the format libraries building the envelope; a `jsonmap` engine and a no-template build path exist; output validated by JSON Schema per format plus format checks (SD path validity, mDoc namespace shape) | Velocity only; replace Velocity; both | both, standard mapping for SD-JWT and mDoc | project owner (validation by judgement) | P1-08, P5 |
| 2026-09-18 | Status mechanism: IETF Token Status List for SD-JWT and mDoc; Bitstring Status List stays for W3C credentials | Bitstring everywhere; Token Status List | Token Status List for SD-JWT and mDoc | judgement | P5 StatusProvider |
| 2026-09-18 | `verify-core` tables stay in the `certify` schema unrenamed, created only by the `certify-as` Flyway location | rename with prefix; own schema; leave | leave, owned by certify-as | judgement | P0-04 |
| 2026-09-18 | Presentation during issuance (IAE) is a supported feature kept in `certify-as` behind a feature flag; the core does not depend on it | drop; experiment; supported | supported behind a flag | project owner | certify-as |
| 2026-09-18 | Draft-13 support: `oid4vci-d13` adapter built in P1, on by default, deprecated from day one | not supported; built but off; on by default | on by default | project owner | P0-02, P1-12, deprecation counters |
| 2026-09-18 | Protocol surface: new spec-clean OpenID4VCI 1.0 surface under `{domain}{servletPath}/oid4vci` with its own issuer identifier; today's paths kept as a deprecated compatibility surface over the same core | same path only; second issuer URL only; both | new surface plus deprecated old surface | project owner | `oid4vci-v1`, API compatibility, metadata, tenancy prefix |
| 2026-09-18 | Keymanager: MOSIP kernel-keymanager stays an embedded library and the default key provider; no HTTP or remote keymanager option; keymanager already covers HSM backends (PKCS#11, PKCS#12, offline), so Certify's `KeyProvider` SPI is for other key managers (cloud KMS, Vault, file, X.509 providers, other libraries) | embedded library; remote keymanager service | embedded, wrapped as `certify-keyprovider-keymanager` | project owner | signing, database, CLI |
| 2026-09-18 | PKI-based formats (mDoc/mDL, SD-JWT VC with `x5c`) get a separate `x509` provider family, a per-format `CertificateChainPolicy` and trust-anchor publication, usable without keymanager tables | keymanager CSR flow only; separate providers | separate providers plus policy | project owner | signing, mDoc, SD-JWT, database (`trust_anchor`) |
| 2026-09-18 | Multi-tenancy is off by default but the code is tenant-ready (`TenantContext`, defaulted `tenant_id` columns) | none; tenant-ready; full multi-tenant | tenant-ready | project owner | core, persistence, adapters |
| 2026-09-18 | Design baseline is `develop` (`a1cfd63`), not the 0.14.0 release | master; develop | develop | project owner | everything |
