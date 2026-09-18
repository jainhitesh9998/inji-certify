# P1-12 oid4vci-d13 adapter (first slice): the 0.14.0 credential endpoints through the new core

Branch: `wp/p1-12-oid4vci-d13` off `design/extensibility`. Phase 1. Size: L, delivered in slices. Depends on: P0-02, P0-09, P1-06, P1-07, P1-11.

## Goal

Wallets that still speak OpenID4VCI draft 13 (release 0.14.0) get their credential endpoints back, byte for byte where they parse the bytes, served by `DefaultIssuanceService` and deprecated from day one (decision: draft-13 on by default). The goldens recorded from 0.14.0 in P0-02 are the definition of "back".

## Scope (this slice, package `io.mosip.certify.oid4vci.d13` inside certify-service until the P1-13 split)

- `POST /issuance/credential` with the 0.14.0 body (`format` plus `credential_definition{@context,type}` | `vct` | `doctype`, one `proof`), next to the 1.0 body on the same path. Dispatch on the body: `D13BodyBufferFilter` buffers the JSON of every `POST .../issuance/credential` and marks it draft-13 when it names a `format` and no `credential_configuration_id`; `D13RequestMappingHandlerMapping` attaches `D13BodyCondition` to the `@D13Body` handler, so Spring MVC ranks it above the compatibility controller for draft-13 bodies and drops it for 1.0 bodies. `VCIssuanceController` is untouched. Decision recorded.
- `POST /issuance/vd12/credential` and `/issuance/vd11/credential` (`D13VersionedPathsController`, `certify.protocol.oid4vci-d13.versioned-paths.enabled`): same body, the answer echoes `format`.
- `D13IssuanceHandler`: 0.14.0's lookup (token scopes, then format and context+type sets | vct | doctype, with 0.14.0's error codes and messages: `invalid_scope`, `invalid_credential_request` "No matching <format> credential configuration found for scope: <scope>", `unsupported_credential_format`), `IssuanceCommand` by configuration id with `ProtocolVersion.OID4VCI_D13`, the proof audience is today's issuer identifier, `{"credential": ...}` as the answer.
- `D13NonceCheck`: the token-bound `c_nonce` (cached under the token hash by the last `invalid_proof` answer) wins; otherwise the token's `c_nonce` claim until `iat + c_nonce_expires_in`; otherwise the shared nonce store, so `POST /nonce` nonces keep working. `D13ErrorAdvice` answers a nonce failure the 0.14.0 way: HTTP 400 `invalid_proof` with a fresh `c_nonce` and `c_nonce_expires_in` (`mosip.certify.cnonce-expire-seconds`), bound to the token and stored in the shared nonce store. Bean validation errors keep the service's advice (`invalid_proof` for a missing proof).
- 0.14.0 wire shapes: a `vc+sd-jwt` request gets `typ vc+sd-jwt` (`SdJwtFormatter.headerPolicy`, protocol parameter `requestedFormat`; `dc+sd-jwt` everywhere else); the mDoc is a Document `{docType, issuerSigned}` with `issuerAuth` under the COSE_Sign1 tag 18 (`D13Mdoc`), around the bare IssuerSigned the core signs. The MSO keeps the tag-24 wrapper and `validityInfo.signed` that ISO/IEC 18013-5 requires and 0.14.0 lacked (decision recorded).
- Deprecated from day one: `@DeprecatedEndpoint` on every handler (`oid4vci-d13-credential`, `oid4vci-d13-versioned-credential`; `since` 2026-09-19, replacement `/oid4vci/credential`): `Deprecation` and `Link` headers, `certify.deprecated.calls` counter, `mosip.certify.deprecated.<name>.enabled=false` kill switch, OpenAPI `deprecated`. Adapter kill switch: `certify.protocol.oid4vci-d13.enabled=false` removes every bean (`D13Properties`, typed).
- `D13GoldenReplayTest`: the P0-02 goldens replayed through MockMvc (`ldp_vc`, vd12, vd11, `vc+sd-jwt` header/payload/response, mDoc response and summary with the two deviations folded back, the four error answers, the fresh nonce from the error accepted next); every credential verified with danubetech, Nimbus or JCA; the 1.0 body on the same path still answered by the 1.0 controller without deprecation headers. Unit tests for the nonce rules, the body filter, the mDoc wrapper and the SD-JWT typ.

## Not in this slice

Versioned issuer metadata (`?version=latest|vd12|vd11`), the `/issuance/.well-known/*` aliases (slice 2), `c_nonce` in the token response of `certify-as`, `acceptance_token`, docs (`VALIDATE.md` draft-13 walk-through), the P1-13 move into `certify-protocol-oid4vci-d13`.

## Acceptance criteria

- [x] `D13GoldenReplayTest` green: every issuance and error golden of P0-02 reproduced (6 tests).
- [x] `IssuanceGoldenTest` (21) and the v1/v2 goldens unchanged; ArchUnit unchanged.
- [x] Unit tests: `D13NonceCheckTest`, `D13BodyBufferFilterTest`, `D13MdocTest`, `SdJwtHeaderPolicyTest`.
- [x] Full `certify-service` suite green (915 tests, 0 failures).
- [ ] CI green on the fork.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green; the draft-13 answers are new on develop and defined by the 0.14.0 goldens.
- No edits outside the files this WP names without a note in the PR. Outside scope: `JwsHeaderPolicy.withTyp` (certify-signing), `SdJwtFormatter.headerPolicy` (certify-format-sd-jwt), `IssuanceGoldenTest` config builders made package-visible.
- Decisions recorded in `docs/design/12-risks-and-decisions.md`.
