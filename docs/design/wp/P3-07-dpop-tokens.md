# P3-07 DPoP-bound access tokens

Branch: `wp/p3-07-dpop-tokens` off `design/extensibility`. Phase 3 (`certify-as`). Size: XS. Depends on: P3-05.

## Goal

Item 3 of docs/design/17-conformance-gaps.md: HAIP requires sender-constrained access tokens (RFC 9449). The resource side already validates DPoP proofs and the `cnf.jkt` binding (develop); the authorization server side, issuing bound tokens, was missing.

## Scope

- `DpopProofValidator.validateForTokenEndpoint`: the token-endpoint case of RFC 9449 section 5 (header, signature, `htm`/`htu`, freshness, single-use `jti`), answering the key thumbprint.
- `POST /oauth/token`: a `DPoP` header on any grant binds the token (`cnf.jkt`) and answers `token_type: DPoP`; without the header the token stays a Bearer token, so today's wallets are unchanged. An invalid proof answers `invalid_dpop_proof`.
- `dpop_signing_alg_values_supported` in the AS metadata (RFC 9449 section 5.1) from the validator's allowed algorithms.
- `DpopBoundTokenTest`: bound token with the right thumbprint, Bearer without a proof, a wrong `htu` refused.

## Outside scope

DPoP nonces from the AS (`use_dpop_nonce`), `attest_jwt_client_auth_dpop`, refresh tokens.

## Acceptance criteria

- [x] `DpopBoundTokenTest`, `OAuthControllerTest`, `DpopProofValidatorTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (992 tests, 0 failures); CI pending.
