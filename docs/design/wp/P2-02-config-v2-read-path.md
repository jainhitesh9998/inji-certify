# P2-02 The v2 configuration model: read path and dual write

Branch: `wp/p2-02-config-v2-read-path` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-01.

## Goal

The rules of `docs/design/08-database.md` for an upgrade-safe model switch: the registry prefers the JSONB columns when `config_version >= 2` and falls back to the legacy columns otherwise; the v1 config API writes both shapes; the two read paths agree row by row.

## Scope

- `CredentialConfig` entity: the 1.1.0 columns (`tenant_id`, `format_config`, `signing_config`, `template_id`, `template_version`, `issuance_strategy`, `data_source_id`, `status_config`, `protocol_overrides`, `config_version`) with the database defaults mirrored in Java; the H2 test schema gains the same columns.
- `ConfigV2Columns.fill(row)`: the v2 columns derived from the legacy columns exactly as the migration backfills them; `CredentialConfigurationServiceImpl` calls it before every save (add and update), so every row the v1 API writes carries both shapes and `config_version = 2`.
- `JpaConfigurationRegistry`: `fromV2Columns` reads `format_config` (context, types, vct, doctype, sdClaims, claims, mdocClaims, sdJwtClaims), `signing_config` (provider and alias to a `KeyRef`, alg, cryptosuite, didUrl), `status_config`, `data_source_id`, `protocol_overrides` (keys that name a `ProtocolVersion`) and `tenant_id`; `issuance_strategy` is honoured when it names `EXTERNAL` or `SUPPLIED`, the backfilled default `TEMPLATE` still follows `mosip.certify.plugin-mode`; the template still comes from `vc_template` (no `credential_template` entity yet). The legacy branch is unchanged; both share the common tail.
- Tests: `ConfigV2ColumnsTest` (the fill matches the migration's shape, including a provider-prefixed key column); `JpaConfigurationRegistryTest.v2ColumnsReadExactlyAsTheLegacyColumns` (the two read paths give the same configuration for ldp_vc and SD-JWT rows; a v2 row may name its strategy and data source). Every golden test now runs on v2 rows, since the v1 API writes them, and stays green: the row-by-row comparison the design asks for, on every path.

## Outside scope

A `credential_template` entity and reading templates by `template_id`; the v2 config API (`/v2/credential-configurations`, `/preview`); `TenantResolver`.

## Acceptance criteria

- [x] `ConfigV2ColumnsTest` and the extended `JpaConfigurationRegistryTest` green.
- [x] `IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest` and `StatusListPostgresTest` unchanged (v2 rows on H2 and on PostgreSQL).
- [x] Full `certify-service` suite green (960 tests, 0 failures).
- [ ] CI green on the fork.

## Rules that apply

- Nothing renamed or dropped; the legacy columns stay the v1 API's contract until 2.0.0 (rule 3, rule 7).
- Decision recorded in `docs/design/12-risks-and-decisions.md` (P2-01 entry covers the strategy default).
