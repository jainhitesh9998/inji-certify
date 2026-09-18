# P1-15 Legacy plugin adapters: VCIssuancePlugin as an ExternalIssuer

Branch: `wp/p1-15-legacy-plugin-adapters` off `design/extensibility`. Phase 1. Size: S. Depends on: P1-11c.

## Goal

The core serves both plugin modes. `DataProviderPlugin` already reaches the core as `DataProviderPluginDataSource`; this WP brings `VCIssuancePlugin` (plugin mode `VCIssuance`, the plugin builds and signs the credential) in as the `ExternalIssuer` the design names `LegacyExternalIssuer`, so that `certify.protocol.oid4vci-v1.compat-core.enabled` applies to every deployment and both `*IssuanceServiceImpl` can go.

## Scope

- `LegacyExternalIssuer` (`io.mosip.certify.oid4vci`, id `vci-plugin`): the calls and error codes of `VCIssuanceServiceImpl`: `ldp_vc` through `getVerifiableCredentialWithLinkedDataProof`, `mso_mdoc` through `getVerifiableCredential`, any other format refused as `unsupported_credential_format`; identity details are the token claims plus `accessTokenHash`; a `VCIExchangeException` keeps its code as message, an empty result is `vc_issuance_failed`. The plugin is resolved lazily, so the bean exists in both modes and the core picks the single `ExternalIssuer` for `EXTERNAL` configurations.
- `CoreBackedVCIssuanceService`: conditional on the flag alone (both plugin modes); `getDIDDocument` answers `unsupported_in_current_plugin_mode` in VCIssuance mode as the legacy service does.
- Goldens: `VcIssuancePluginGoldenTest` records the VCIssuance-mode answers of the legacy service for a mocked plugin under `goldens/v1/vci-plugin` (ldp_vc and mDoc responses, unsupported SD-JWT, plugin exception, empty plugin result, DID document refusal); `VcIssuancePluginGoldenCoreTest` replays them through the core.

## Outside scope

`AuditPlugin` adapters into the new SPI (the `AuditListener` already calls the plugin directly); the `PROOF_VALIDATION`/`NONCE_VALIDATION` audit entries of the legacy services (no core hook yet).

## Acceptance criteria

- [x] `VcIssuancePluginGoldenTest` (5) and `VcIssuancePluginGoldenCoreTest` (6) green: identical answers in both modes.
- [x] `IssuanceGoldenCoreTest` (22) and ArchUnit unchanged.
- [x] Full `certify-service` suite green (957 tests, 0 failures; `IssuanceGoldenTest` now compares issuer metadata for its own configurations only, since the golden tests share one H2).
- [ ] CI green on the fork.

## Rules that apply

- Zero wire-byte change: the new goldens are recorded from the legacy service first and replayed through the core.
- No edits outside the files this WP names without a note in the PR.
