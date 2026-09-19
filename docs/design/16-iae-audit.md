# 16. Presentation during issuance: audit against the current draft

Reviewed on 2026-09-19 at the owner's request. Certify's interactive authorization (`POST /oauth/iae`, `IarServiceImpl`, `IarVpRequestService`, `IarPresentationService`, `iar_session`) implements an earlier revision of the OpenID4VCI "interactive authorization endpoint" draft. The OpenID4VCI 1.1 editor's draft has since folded it into the OAuth 2.0 authorization challenge shape. OpenID4VCI 1.0 final does not contain the flow at all, which is why the design keeps it behind a flag in `certify-as` (docs/design/12, decision of 2026-09-18).

## What Certify does today

1. The wallet posts `response_type=code`, `client_id`, `code_challenge` (`S256` only), `authorization_details` (`type=openid_credential`, `credential_configuration_id`) and `interaction_types_supported` (must name `openid4vp_presentation`) to `POST /oauth/iae` as a form.
2. Certify answers HTTP 200 `{ "status": "require_interaction", "type": "openid4vp_presentation", "auth_session": ..., "openid4vp_request": { response_type, client_id, nonce, dcql_query, response_mode, response_uri } }`. The request is built by the embedded inji-verify library (`verify-core`) with the deployment's `dcqlQuery` (`vp_request_config.json`) and its verifier `client_id` (`mosip.certify.verify.service.verifier-client-id`); the nonce is the library's; `response_uri` is the IAE itself.
3. The wallet posts `auth_session` and `openid4vp_response` (a JSON object with `vp_token`) to the same endpoint. Certify hands the `vp_token` to `verify-core`, which checks the presentation (signatures, holder binding, nonce) against the stored request; on success Certify extracts the identity attributes named by `mosip.certify.iar.identity-data` (`uin`, `vid`) from the presented credential, stores them in the session and answers `{ "status": "ok", "code": ... }`; otherwise `{ "status": "error" }`.
4. `POST /oauth/token` with `grant_type=authorization_code`, `code`, `code_verifier` (PKCE verified, code single-use, expiry `mosip.certify.iar.authorization-code.expires-minutes`) returns the access token whose `sub` is the extracted identity, so the data-provider plugin resolves the record.
5. The AS metadata advertises `interactive_authorization_endpoint` and `require_interactive_authorization_request`.

The unit tests (`IarServiceImplTest`, `IarPresentationServiceTest`, `IarSessionServiceTest`, `IarVpRequestServiceTest`, `OAuthControllerTest`) cover validation, session handling, code lifetime and single use, PKCE and the token exchange with `verify-core` mocked; the cryptographic verification of the presentation is `verify-core`'s and is not exercised in this repository.

## Differences from the 1.1 editor's draft

| Topic | Certify today | 1.1 editor's draft | Effect |
| --- | --- | --- | --- |
| Interaction-required answer | HTTP 200, `status: require_interaction`, `type` | HTTP 403, `error: insufficient_authorization`, `interaction_type_required` | Wire format; a draft-current wallet would treat today's answer as success without a code |
| Interaction type identifiers | `openid4vp_presentation` | URNs `urn:openid:dcp:ia:openid4vp_presentation`, `urn:openid:dcp:ia:auth_via_web` | Wire format |
| Endpoint advertisement | `interactive_authorization_endpoint`, `require_interactive_authorization_request` | `authorization_challenge_endpoint` | Discovery |
| Presentation request `response_mode` | the library's (`direct_post`) | `ia_post` or `ia_post.jwt` | Wire format; `ia_post.jwt` needs encryption support |
| Holder binding audience | the verifier `client_id` from configuration | "the audience of each [presentation] MUST be properly bound to the Authorization Challenge Endpoint" | A presentation bound to the endpoint URL would fail today's check and vice versa |
| Completed answer | `status: ok`, `code` | `code` (no status member) | Minor |
| `redirect_uri` | not used | present in the draft's example | Minor |
| Identity extraction | requires `uin`/`vid` in the presented credential, else `invalid_vp` | not part of the protocol | Deployment policy; should be configurable per credential configuration rather than global |

The rest matches the draft: PKCE with `S256` only, `authorization_details` of type `openid_credential`, `auth_session` as the correlation handle, `openid4vp_response` as a JSON object carrying the OpenID4VP response, the nonce bound to the session by the library, single-use codes exchanged with `code_verifier`.

## Recommendation

Keep the current shape as the compatibility behaviour (the Inji wallet speaks it) and add the draft-current shape next to it in `certify-as`, selected by the request: a wallet that sends URN interaction types gets the 403 `insufficient_authorization` answer, `authorization_challenge_endpoint` is advertised next to the current member, the presentation request uses `ia_post` with the endpoint as audience, and the identity extraction becomes a per-configuration setting. Until the draft stabilises this stays behind `certify.as.iae.*` flags. Logged as a decision for the owner (docs/design/12).
