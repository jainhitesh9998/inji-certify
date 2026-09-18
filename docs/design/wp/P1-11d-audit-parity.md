# P1-11d Audit parity on the core path

Branch: `wp/p1-11d-audit-parity` off `design/extensibility`. Phase 1. Size: XS. Depends on: P1-11c.

## Goal

The audit entries the legacy issuance services wrote per request also appear when the compatibility path runs through the core: `PROOF_VALIDATION` success once every proof passed and error when a proof or its nonce failed, next to the `VC_ISSUANCE` entries the `AuditListener` already wrote.

## Scope

- `AuditListener.onIssued` writes `PROOF_VALIDATION` success before `VC_ISSUANCE` success; `onFailed` writes `PROOF_VALIDATION` error for `invalid_proof` and `invalid_nonce`, `VC_ISSUANCE` error otherwise, each with the access token hash and the cause.
- `AuditListenerTest` covers both.

## Outside scope

`NONCE_VALIDATION`, which the legacy services wrote per proof with the nonce value: the core exposes no per-proof hook yet, so it is not written on the core path (documented in `AuditListener`).

## Acceptance criteria

- [x] `AuditListenerTest` green; `IssuanceGoldenCoreTest` and `IssuanceGoldenTest` unchanged.
- [x] Full `certify-service` suite green (967 tests, 0 failures).
- [ ] CI green on the fork.
