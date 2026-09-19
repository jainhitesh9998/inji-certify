# P3-06 Attestation-based client authentication

Branch: `wp/p3-06-client-attestation` off `design/extensibility`. Phase 3 (`certify-as`). Size: S. Depends on: P3-05.

## Goal

Item 2 of docs/design/17-conformance-gaps.md: HAIP requires client authentication at every OAuth endpoint and names attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth, HAIP Appendix E); the conformance suite configures an attester whose JWKS the issuer must trust.

## Scope

- `ClientAttestationValidator`: `OAuth-Client-Attestation` (`typ oauth-client-attestation+jwt`, signed by an attester configured under `certify.as.client-attestation.attesters.<id>.jwks`, `sub` = `client_id`, `exp`, `cnf.jwk`) and `OAuth-Client-Attestation-PoP` (`typ oauth-client-attestation-pop+jwt`, signed by the `cnf.jwk` key, `aud` = the AS issuer, single-use `jti`, `iat` within `pop-max-age` and `clock-skew`). Failures answer `invalid_client` (401 at PAR; the token endpoint's error envelope at `/oauth/token`).
- `required=true` refuses unauthenticated calls to `POST /oauth/par` and `POST /oauth/token` (the HAIP rule); `false` (default) validates the headers when presented, so today's wallets are unchanged.
- AS metadata advertises `token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"]` when an attester is configured.
- `ClientAttestationTest`: attested PAR and token succeed; missing attestation, an untrusted attester, a PoP by another key, a wrong audience, a `sub` that is not the client and a replayed `jti` are refused.

## Outside scope

The `use_attestation_challenge` mechanism (`OAuth-Client-Attestation-Challenge`), `attest_jwt_client_auth_dpop`, attesters given as `x5c` trust anchors, attestation at the resource server.

## Acceptance criteria

- [x] `ClientAttestationTest`, `AuthorizationCodeFlowTest`, `OAuthControllerTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (991 tests, 0 failures); CI pending.
