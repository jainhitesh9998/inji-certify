# P1-10a Status list end to end on PostgreSQL

Branch: `wp/p1-10a-status-postgres` off `design/extensibility`. Phase 1. Size: S. Depends on: P0-05, P1-10.

## Goal

Prove the status-list feature on the database it needs. A VC 2.0 `ldp_vc` with a revocation purpose, issued through the new surface and through the compatibility surface, gets a Bitstring Status List entry; the list it points to is published and verifies with a library Certify did not write; a revocation flips the bit and the re-signed list verifies again; the ledger row is written. H2 cannot run `StatusListCredentialService.initializeAvailableIndices` (`generate_series`), so until now no test issued a credential with a real status entry (finding of P1-10).

## Scope

- `StatusListPostgresTest` (`io.mosip.certify.golden`): `@SpringBootTest` on a Testcontainers PostgreSQL 15 prepared the way a deployment prepares it: the Flyway chain (`FlywayDefaults` locations and baseline), then the keymanager policy rows of `db_scripts/inji_certify/dml/certify-key_policy_def.csv`; the service then starts with `spring.flyway.enabled=true` and finds nothing pending. Its own PKCS#12 keystore under `target/`. Skipped without Docker (`disabledWithoutDocker`); CI has Docker, so it runs there inside the normal `verify`.
- Tests: the Flyway chain is applied and validated by the service; new-surface issuance carries `credentialStatus` (shape, `id` = list URL + index, entry bit clear in the published list), the credential verifies with danubetech (`eddsa-rdfc-2022`), the status list credential from `/credentials/status-list/{id}` verifies with danubetech (`Ed25519Signature2020`) and its proof type survives JSON-LD expansion; the ledger row carries the status detail and the indexed plugin attribute; a revocation through `/credentials/status` plus the batch job's `updateStatusList` sets the bit, re-signs the list (verified again) and marks the transaction processed; the compatibility surface draws from the same list with its own index.
- Goldens recorded by this test: `v2/oid4vci/ldp_vc-status-response`, `v2/status-list/bitstring-status-list-credential`, `v1/issuance/ldp_vc-status-response`.
- Fix (spec correctness, non-negotiable 1): `StatusListCredentialService.generateStatusListCredential` adds the proof suite's JSON-LD context (`https://w3id.org/security/suites/ed25519-2020/v1` for `Ed25519Signature2020`) to the status list credential. The VC 2.0 context defines `DataIntegrityProof` only, so the proof `type` of every list generated so far expands to an undefined term; danubetech verified such lists only because signer and verifier drop the same triple, and strict verifiers reject them. Stored lists are unchanged; new lists carry the context. Decision recorded.
- `IssuanceGoldenTest.ldpConfig` made package-visible for reuse; its comment now points to the new test.

## Outside scope

- `Ed25519Signature2018` status lists (compose `certify-mock-mdl.properties`) have the same defect; the context loader serves no `ed25519-2018` context, so they are left as they are (finding).
- The update API takes the bare list id where the credential carries the list URL (finding; kept until 2.0.0).
- `key_policy_def` seed rows are not part of the Flyway chain: a Flyway-only database cannot start the keymanager (finding; decision needed on a DML migration).

## Acceptance criteria

- [x] `StatusListPostgresTest` green on PostgreSQL 15 (4 tests): Flyway chain, new-surface issuance with status and ledger, revocation, compatibility-surface parity.
- [x] Every credential and every status list in the test verified with danubetech; the status list's proof type survives expansion with the service's own context loader.
- [x] Three goldens recorded; the existing goldens, `IssuanceGoldenTest` (21) and `StatusListCredentialServiceTest` (17) unchanged and green.
- [x] Full `certify-service` suite green (902 tests, 0 failures; the PostgreSQL test executed, not skipped).
- [ ] CI green on the fork with the Testcontainers test executed, not skipped.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green; the status list context is a spec fix recorded in the decision log.
- No edits outside the files this WP names without a note in the PR.
- Read `CLAUDE.md`, then `docs/design/10-testing-and-conformance.md` and `docs/design/08-database.md`.
