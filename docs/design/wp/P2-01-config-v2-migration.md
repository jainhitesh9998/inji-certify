# P2-01 Configuration model v2 and tenant columns: the 1.1.0 migration

Branch: `wp/p2-01-config-v2-migration` off `design/extensibility`. Phase 2. Size: M. Depends on: P0-04, P0-05, P3-01.

## Goal

The first Phase 2 step of `docs/design/08-database.md`: one additive Flyway migration that puts the domain model beside the legacy columns, versioned templates, the issuance transaction table, the ledger columns and the tenant discriminator in place, backfilled from today's rows, with a rollback script, rehearsed on a database created from `db_scripts` (what every deployment has). No code reads the new columns yet; the registry switches to JSONB in P2-02.

## Scope

- `db/migration/core/V1_1_0_000__config_v2_and_tenancy.sql`: `credential_config` gains `tenant_id`, `format_config`, `signing_config`, `template_id`, `template_version`, `issuance_strategy`, `data_source_id`, `status_config`, `protocol_overrides`, `config_version`; new `credential_template` (PK `(id, version)`, the tenant is a column, not part of the identity) and `issuance_transaction`; `ledger` gains `tenant_id`, `credential_config_id`, `format`, `protocol_version`, `transaction_id`; `status_list_credential`, `credential_status_transaction` and `iar_session` gain `tenant_id`; the unique indexes of `credential_config` and `ledger` are rebuilt once to lead with `tenant_id`.
- Backfill in the same migration: `format_config` (context, types, vct, doctype, sdClaims, claims, mdocClaims, sdJwtClaims, nulls stripped), `signing_config` (provider and alias from `key_manager_app_id`/`key_manager_ref_id`, a `provider:alias` column keeps its provider, alg, cryptosuite, didUrl), `status_config` (BitstringStatusList with the purposes), `config_version = 2`; `credential_template` rows decoded from the base64 `vc_template` (`velocity`, `FULL_DOCUMENT`, version 1, md5 checksum) with `template_id`/`template_version` set on the configuration. `issuance_strategy` stays at the default `TEMPLATE` (the plugin mode is a runtime property; the registry keeps deriving the strategy from it until the v2 API writes the column).
- `db_upgrade_script/inji_certify/sql/1.0.0_to_1.1.0_upgrade.sql` (points at Flyway) and `1.0.0_to_1.1.0_rollback.sql` (drops the additions, restores the 1.0.0 unique indexes, removes the history row).
- Tests on Testcontainers PostgreSQL: `FlywayMigrationTest` (empty database: five migrations, 17 tables; a `db_scripts` database: baseline then only 1.1.0; both roads the same schema); `ConfigV2MigrationTest` (three v1 rows backfilled and checked field by field, the template row, the tenant default, the rollback script applied and the migration applied again). `PostgresSupport` holds the shared helpers.

## Outside scope

Reading the JSONB columns (`config_version >= 2`) in `JpaConfigurationRegistry`, the JPA entities for `credential_template` and `issuance_transaction`, the v2 config API, the H2 test schema (unchanged until entities change), the `key_policy_def` seed rows (decision pending).

## Acceptance criteria

- [x] `FlywayMigrationTest` (3) and `ConfigV2MigrationTest` (1) green on PostgreSQL 15.
- [x] `StatusListPostgresTest` green: the service starts on a database carrying the 1.1.0 migration.
- [x] Full `certify-service` suite green (958 tests, 0 failures).
- [ ] CI green on the fork (Docker available, the Testcontainers tests run).

## Rules that apply

- Every database change is additive, shipped as a Flyway migration with a rollback script, backfilled in the same migration and rehearsed on a develop-shaped database (`CLAUDE.md` rule 3); `tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'` on every new tenant-scoped table, no entity embeds the tenant in its identity (rule 4).
- Decision recorded in `docs/design/12-risks-and-decisions.md`.
