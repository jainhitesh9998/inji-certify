# P0-02 Golden request/response tests for the 0.14.0 draft-13 surface

Branch: `wp/p0-02-golden-tests-d13` off `design/extensibility` (recorded 2026-09-19). Phase 0 (guardrails). Size: M. Depends on: P0-01.

## Goal

Capture the draft-13 behaviour (release 0.14.0, commit `e54539a`) the `oid4vci-d13` adapter must reproduce in Phase 1.

## Scope

- Recorded in process rather than against a running server: `docs/design/wp/p0-02-recorder/D13GoldenRecorder.java` runs inside a `git worktree` of `e54539a` (the real 0.14.0 service on H2 with the PKCS#12 keymanager, Velocity and the `local` profile's TestBearer filter, through MockMvc), with the same mock data, templates and configurations as develop's `IssuanceGoldenTest` and the shared `Goldens` normaliser. The README there gives the exact commands; a second run must record nothing.
- Cases (26 files under `certify-service/src/test/resources/goldens/d13/`): `POST /issuance/credential` with the draft-13 body for `ldp_vc`, `vc+sd-jwt` (header, payload, response shape) and `mso_mdoc` (response shape, CBOR summary); `/issuance/vd12/credential` and `/issuance/vd11/credential`; the `invalid_proof` error with `c_nonce`, unknown type, unsupported format, missing proof; `/.well-known/openid-credential-issuer` for `latest`, `vd12`, `vd11` and an unknown version, the `/issuance/.well-known/*` aliases, `did.json`, `jwks.json`, `oauth-authorization-server`; the pre-authorized code flow (offer, offer fetch, token response, access token claims and header).
- `D13GoldenSetTest` keeps the set complete, parseable and normalized; its replay method is `@Disabled` until P1-12 provides the adapter.
- `docs/design/wp/P0-02-notes.md` lists every behavioural difference found between 0.14.0 and develop for the same input, and the fields `oid4vci-d13` must restore.
- `Goldens.normalize` now sorts object arrays by their key-sorted form so that a recorded golden re-normalises to itself; the v1 `did.json` and `jwks.json` goldens were re-recorded (array order only, same entries).

## Acceptance criteria

- [x] Golden files present for every listed endpoint and case (26 files; recorder run twice, second run recorded nothing).
- [x] The notes file lists the draft-13 fields the adapter must restore (`P0-02-notes.md`).
- [x] Full `certify-service` suite green (904 tests; `D13GoldenSetTest` active, replay disabled until P1-12).

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
