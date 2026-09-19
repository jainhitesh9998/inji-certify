# P3-03 Single-use nonces and batch issuance on the new surface

Branch: `wp/p3-03-single-use-nonce-batch` off `design/extensibility`. Phase 3. Size: S. Depends on: P1-11 (the `/oid4vci` surface), P3-02 (transactions).

## Goal

Two OpenID4VCI 1.0 behaviours the roadmap lists for Phase 3 (docs/design/11-roadmap.md: "single-use nonces", "`batch_credential_issuance`"): a `c_nonce` from `POST /oid4vci/nonce` authorises exactly one credential request, so a captured proof cannot be replayed until the nonce expires; and the issuer advertises how many proofs one request may carry and refuses more. The compatibility surfaces (today's paths, draft 13) keep their 0.14.0 and develop nonce rules and goldens.

## Scope

- `certify.protocol.oid4vci-v1.nonce.single-use` (default true) and `certify.protocol.oid4vci-v1.batch.size` (default 10) in `Oid4vciV1Properties`.
- `RecordingNonceCheck` wraps the request's `CacheNonceCheck` and remembers every nonce the proofs presented; once the core answers with issued credentials, `Oid4vciCredentialController` consumes them (`CacheNonceCheck.consume`, `VCICacheService.evictNonceTransaction`). All proofs of a batch share one nonce, so consumption waits for the whole request; a refused request leaves the nonce valid.
- `proofs` longer than `batch.size` answer `400 invalid_credential_request` before any proof is validated.
- `batch_credential_issuance: {batch_size}` in the default (`CredentialIssuerMetadataDTO`) and per-tenant (`TenantIssuerMetadata`) documents of the new surface when the size is above 1. The v2 metadata golden is re-recorded for the new field; v1 and d13 goldens are untouched.
- Test `Oid4vciNonceBatchTest` (batch size 2): replay refused with `invalid_nonce`; two proofs give two credentials for two holders and consume the nonce once; three proofs are refused and the nonce survives; the metadata carries the size.

## Outside scope

Single-use nonces on the draft-13 adapter and on the compatibility path (their nonces are bound to the access token and rotate as 0.14.0 and develop did), a durable `nonce` table (the cache is the shared store; Redis in deployments), response encryption, `credential_identifier`.

## Acceptance criteria

- [x] `Oid4vciNonceBatchTest` green; `IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `TenancyIssuanceTest` green; `goldens/legacy-develop` and `goldens/legacy-0.14.0` byte-identical.
- [x] Full `certify-service` suite green (975 tests, 0 failures).
- [ ] CI green on the fork.
- [x] Decision logged: consume on success only, batch size default, compatibility surfaces unchanged.
