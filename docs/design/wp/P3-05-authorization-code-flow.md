# P3-05 The authorization code flow of Certify's own authorization server

Branch: `wp/p3-05-authorization-code` off `design/extensibility`. Phase 3 (`certify-as`). Size: M. Depends on: the presentation-during-issuance token path (`IarServiceImpl`), P3-04.

## Goal

Item 1 of docs/design/17-conformance-gaps.md: the OpenID Foundation issuer test drives the authorization code flow only. Certify's own AS gains `POST /oauth/par` (RFC 9126) and `GET /oauth/authorize` with PKCE `S256` (RFC 7636), `scope` or `authorization_details` (OpenID4VCI 1.0 section 5.1), the code delivered by redirect with `state` and `iss` (RFC 9207), and the existing `authorization_code` grant of `POST /oauth/token` exchanging it. The subject comes from `certify.as.authorization.subject-mode` (decision of 2026-09-19: `fixed` for conformance and demos; `none` by default).

## Scope

- `certify.as.clients.<client-id>.redirect-uris` registers clients; the flow and its metadata members (`authorization_endpoint`, `pushed_authorization_request_endpoint`, `require_pushed_authorization_requests`) exist only when a client is registered, so an unchanged deployment's AS document is unchanged.
- `AuthorizationCodeService`: validates the pushed request (registered client and redirect URI, `response_type=code`, PKCE `S256`, known scopes or `openid_credential` details naming known configurations), stores it in the pre-authorized code cache under a `request_uri` for `certify.as.par.expires-in`, and at the authorization endpoint consumes it (single use), establishes the subject and writes the code, challenge, scope and subject into `iar_session`, which the token endpoint already reads. The effective scope of an `authorization_details` request is the configurations' scope, so the credential endpoint's scope check passes.
- Errors are OAuth errors: `invalid_client` (401), `invalid_request`, `unsupported_response_type`, `invalid_scope` (400), `access_denied` by redirect when no subject can be established.
- `AuthorizationCodeFlowTest`: metadata, PAR, redirect with code, state and iss, single-use request_uri, token exchange with the fixed subject and scope, single-use code, `authorization_details`, every error.

## Outside scope (next slices)

Client attestation at PAR and token (item 2), DPoP-bound tokens (item 3), issuer-initiated offers with `issuer_state` and `authorization_details` with `credential_identifiers` in the token response, refresh tokens, the `iae` subject mode (presentation during issuance through the authorization endpoint).

## Acceptance criteria

- [x] `AuthorizationCodeFlowTest`, `OAuthControllerTest`, `IarServiceImplTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (990 tests, 0 failures); CI pending.
