# P0-01 Golden request/response tests for develop's HTTP surface

Branch: `wp/p0-01-golden-tests-v1` off `develop`. Phase 0 (guardrails). Size: M. Depends on: none.

## Goal

Record byte-exact request/response pairs for every endpoint on develop and replay them in a JUnit suite so later refactors cannot change wire behaviour unnoticed.

## Scope

- Run the service with profile `local` (TestBearer tokens) and the mock CSV data provider; record for: `POST /issuance/credential` (ldp_vc, dc+sd-jwt, mso_mdoc; valid, invalid proof, missing nonce, wrong scope), `POST /nonce`, all `/.well-known/*`, `/credential-configurations` CRUD, `/credentials/status`, `/credentials/status-list/{id}`, `/ledger-search`, `/rendering-template/{id}`, `/oauth/token` (pre-auth), `/pre-authorized-data`, `/credential-offer-data/{id}`.
- Store under `certify-service/src/test/resources/goldens/v1/<endpoint>/<case>.{request,response}.json` with a `normalize.json` per case listing volatile fields (timestamps, ids, nonces, signatures) and the rule for each (`ignore`, `regex`, `verify-signature`).
- A `GoldenReplayTest` (MockMvc, profile `test`) that replays every case and diffs after normalisation; a Gradle/Maven profile `-Pgoldens-record` that re-records.
- Do not change production code in this WP.

## Acceptance criteria

- [ ] `mvn -pl certify-service test -Dtest=GoldenReplayTest` passes on develop unchanged.
- [ ] Every controller mapping in `certify-service` has at least one golden case (a test asserts this by scanning `@RequestMapping` annotations).
- [ ] Re-recording on an unchanged build produces zero diff.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
