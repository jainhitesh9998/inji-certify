# P1-11a ConfigurationRegistry over credential_config

Branch: `wp/p1-11a-configuration-registry` off `design/extensibility`. Phase 1. Size: S. Depends on: P1-01, P1-02.

## Goal

The new core reads today's `credential_config` rows as `CredentialConfiguration`s so the `/oid4vci` adapter (P1-11) and the CLI can issue from the same configuration operators already manage. Read-only; nothing about the table or the v1 configuration API changes.

## Scope

- `JpaConfigurationRegistry` (`io.mosip.certify.registry`, Spring bean) implementing `certify-issuance`'s `ConfigurationRegistry`:
  - `byId` = `credential_config_key_id`; `bySelector(format, key)`: `ldp_vc` → `context|credentialType` exactly as stored (the draft-13 lookup), `dc+sd-jwt`/`vc+sd-jwt` → vct, `mso_mdoc` → docType; `all`; only `active` rows; any tenant but `default` sees nothing (single tenant by default).
  - Mapping: `FormatConfig.Generic` carries the format-specific and metadata columns; `TemplateRef` = velocity, base64 template, FULL_DOCUMENT (NONE when the row has no template), params `didUrl`; `SigningConfig` = `keymanager:APPID/REFID`, the row's `signature_algo` (or the first `credential_signing_alg_values_supported`), cryptosuite, `didUrl` as issuer DID; strategy TEMPLATE in `DataProvider` plugin mode, EXTERNAL otherwise; `StatusConfig` = `BitstringStatusList` with the row's purposes; `DisplayConfig` from display, order and claims metadata.
- A row without any usable algorithm fails loudly (`IllegalStateException`) instead of issuing.

## Acceptance criteria

- [x] `JpaConfigurationRegistryTest` against a mocked repository: mapping of ldp_vc/SD-JWT/mDoc rows, selectors per format, inactive rows, other tenants, EXTERNAL mode, broken rows.
- [x] `IssuanceGoldenTest.configurationRegistryMapsTheGoldenConfigurations`: the registry maps the nine golden configurations from the real context.
- [x] Goldens and ArchUnit unchanged.
- [x] Full `certify-service` suite green: 889 tests.
