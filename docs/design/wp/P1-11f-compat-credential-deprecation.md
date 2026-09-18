# P1-11f Deprecation headers on the compatibility credential endpoint

Branch: `wp/p1-11f-compat-credential-deprecation` off `design/extensibility`. Phase 1 fix. Size: XS. Depends on: P0-05 (deprecation interceptor), P1-11.

## Goal

Found by the compose smoke run: `POST /issuance/credential` with the develop body answered without `Deprecation`, `Sunset` or `Link` headers, although docs/design/09-api-compatibility.md deprecates the compatibility credential endpoint from 1.1.0 and `CLAUDE.md` rule 6 requires headers, a counter, a kill switch, the OpenAPI flag and a release note for every deprecated surface. The draft-13 body on the same path already had them (P1-12).

## Scope

- `VCIssuanceController.getCredential` carries `@DeprecatedEndpoint(name = "oid4vci-v1-compat-credential", since = "2026-09-19", replacement = "/oid4vci/credential")`: the interceptor adds the headers, counts `certify.deprecated.calls{endpoint=oid4vci-v1-compat-credential}`, honours `mosip.certify.deprecated.oid4vci-v1-compat-credential.enabled=false` with `410 Gone`, and the OpenAPI document flags the operation. No sunset date yet (removal no earlier than two minor releases after 1.1.0, never in a patch).
- `VCIssuanceControllerTest.getVerifiableCredential_isDeprecatedWithHeaders` and `VCIssuanceControllerKillSwitchTest`.
- Release note in `docs/technical_docs/Releases.md`.

## Outside scope

`POST /nonce` (kept, docs/design/09), the legacy `.well-known` documents, the v1 configuration API (deprecated in 1.2.0 per the design).

## Status

On hold, ready on its branch. P1-12 asserted that the 1.0 handler is not deprecated "in this phase" (`D13GoldenReplayTest.compatibilitySurfaceOnTheSamePathIsUntouched`), following the decision that today's paths become the deprecated surface *over the same core*; the compat-core default flip is itself waiting for the owner. Merge this together with that flip, or earlier if the owner prefers headers from 1.1.0 as docs/design/09 says. The branch updates the draft-13 assertion accordingly.

## Acceptance criteria

- [ ] Both controller tests green; `IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest` green (bodies unchanged, headers added).
- [ ] Full `certify-service` suite green.
- [ ] The compose smoke run sees the headers on `/issuance/credential`.
- [ ] CI green on the fork.
