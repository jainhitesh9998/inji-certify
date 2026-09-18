# P0-02 Golden request/response tests for the 0.14.0 draft-13 surface

Branch: `wp/p0-02-golden-tests-d13` off `develop`. Phase 0 (guardrails). Size: M. Depends on: P0-01.

## Goal

Capture the draft-13 behaviour (release 0.14.0, commit `e54539a`) the `oid4vci-d13` adapter must reproduce in Phase 1.

## Scope

- Check out `e54539a` in a scratch clone, run it with the same mock data provider, record the same case matrix for `POST /issuance/credential` (draft-13 body with `format`/`credential_definition`/`vct`/`doctype`, single `proof`), `/issuance/vd11/credential`, `/issuance/vd12/credential`, `/.well-known/openid-credential-issuer?version=vd11|vd12|latest`, `/issuance/.well-known/*`, the `invalid_proof` error carrying `c_nonce`, and `acceptance_token`.
- Store under `certify-service/src/test/resources/goldens/d13/`; the replay test for this set is `@Disabled("enabled by WP1-10")` until the adapter exists.
- Document in `docs/design/wp/P0-02-notes.md` every behavioural difference found between 0.14.0 and develop for the same input.

## Acceptance criteria

- [ ] Golden files present for every listed endpoint and case.
- [ ] The notes file lists the draft-13 fields the adapter must restore.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
