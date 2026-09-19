# P1-11c Compatibility path through the new core

Branch: `wp/p1-11c-compat-core` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-05, P1-06, P1-07, P1-08, P1-09, P1-10, P1-11.

## Goal

`POST /issuance/credential` with the OpenID4VCI 1.0 body, today served by `CertifyIssuanceServiceImpl`, served by `DefaultIssuanceService` with the same bytes on every path the v1 goldens cover: seven signing paths, SD-JWT, mDoc, claim-169 QR, Bitstring status, ledger, the pre-authorized flow and the error answers. This is the Phase 1 exit criterion "both `*IssuanceServiceImpl` deleted", taken in two steps: prove the core behind a flag (this WP), then flip the default and delete the legacy service.

## Scope

- `certify-spi`: `IssuanceListener.beforeRender(ClaimSet, CredentialConfiguration, IssuanceContext, HolderBinding)`, a default-identity hook the core applies before a template renders (`DefaultIssuanceService.render`).
- Listeners in `io.mosip.certify.oid4vci` (ordered): `LegacyTemplateParamsListener` (10) adds the model parameters the legacy issuance gave every Velocity template and the new engine did not (`templateName` in the legacy key form, `didUrl`, `_doctype`, `vct`/`cnf`/`iss`, `credentialId` when the id prefix is set, `_holderId`, `validFrom`/`validUntil`, `rootContext`, `envConfigs`); `RenderMethodDigestListener` (20) adds `renderingTemplateId` and `_renderMethodSVGdigest` for VC 2.0 templates when `mosip.certify.data-provider-plugin.rendering-template-id` is set; `Claim169QrListener` (30) renders the configuration's `qrSettings` through `VCFormatter.formatQRData`, maps them with PixelPass, signs the CWT through `Credential.signQRData` (same bytes) and hands `claim_169_values` to the template; `AuditListener` writes `VC_ISSUANCE` success or error through the `AuditPlugin`.
- `CoreBackedVCIssuanceService` (`io.mosip.certify.oid4vci.compat`, `@Primary`): the `VCIssuanceService` the compatibility controller uses when `certify.protocol.oid4vci-v1.compat-core.enabled=true` and the plugin mode is `DataProvider` (the VCIssuance mode has no `ExternalIssuer` adapter yet): the same command the new surface builds, today's issuer identifier as tenant identifier and proof audience, the shared nonce store, the 1.0 response shape, and the legacy exceptions, codes and messages so that the error goldens hold. `getDIDDocument` as before. `Oid4vciProperties` (typed, `certify.protocol.oid4vci-v1`) carries the flag, off by default.
- `KeymanagerKeyProviderConfiguration` exposes today's `key-alias-mapper` as the `legacyKeyAliasMapper` bean (same lookup, re-exposed) for the QR listener's algorithm-specific key choice.
- Tests: `IssuanceGoldenCoreTest` extends `IssuanceGoldenTest` with the flag on (all 21 goldens plus a check that the core-backed service is the active one); `StatusListPostgresCoreTest` extends `StatusListPostgresTest` with the flag on; unit tests for the legacy template parameters and the exception mapping.

## Outside scope

`JwsHeaderPolicy`-style module edits: none. `CredentialIdListener` unchanged. The legacy `CertifyIssuanceServiceImpl` stays until the flag's default flips (follow-up WP after CI has run both modes): `PROOF_VALIDATION` entries are written since P1-11d; `NONCE_VALIDATION` has no core hook yet and is not written on the core path; `VCIssuanceServiceImpl` (VCIssuance plugin mode) is covered since P1-15 (`LegacyExternalIssuer`).

## Acceptance criteria

- [x] `IssuanceGoldenCoreTest`: the 21 v1 goldens unchanged with the compatibility path served by the core (ldp_vc on Ed25519Signature2020/2018, RsaSignature2018, EcdsaSecp256k1/r1Signature2019, eddsa-rdfc-2022; dc+sd-jwt; mso_mdoc; claim-169 QR; jwks and did; pre-authorized flow; invalid nonce and unknown configuration errors); every credential verified independently as before.
- [x] `StatusListPostgresCoreTest`: status entry, list, revocation and ledger through the core on PostgreSQL.
- [x] `IssuanceGoldenTest`, `D13GoldenReplayTest`, ArchUnit unchanged; the flag off leaves the legacy service in place.
- [x] Full `certify-service` suite green (946 tests, 0 failures).
- [ ] CI green on the fork.

## Rules that apply

- Zero wire-byte change: the goldens are the proof, in both modes.
- No edits outside the files this WP names without a note in the PR. Outside scope edits: `certify-spi` (new default method), `certify-issuance` (hook call), `certify-keyprovider-keymanager` (bean).
- Decision recorded in `docs/design/12-risks-and-decisions.md`.
