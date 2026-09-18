# P2-09 Upgrade rehearsal from a 0.14.0 database

Branch: `wp/p2-09-upgrade-from-0.14.0` off `design/extensibility`. Phase 2 exit criterion. Size: S. Depends on: P2-01.

## Goal

docs/design/11-roadmap.md asks for "upgrade and rollback rehearsed on 0.14.0 and develop dumps"; `FlywayMigrationTest` covers the develop shape (`db_scripts`). This rehearses the road a release 0.14.0 deployment takes (`CLAUDE.md` non-negotiable 3): the 0.14.0 schema with rows in its shape, the operator's `0.14.0_to_1.0.0_upgrade.sql`, then the rebuild's Flyway baseline and 1.1.0 migration, the 1.1.0 rollback script and the migration again.

## Scope

- The 0.14.0 DDL of `e54539a` vendored under `certify-service/src/test/resources/db/v0.14.0` (12 tables plus its `ddl.sql` order).
- `PostgresSupport.applyDdlScripts(database, dir, count)`, `applySqlFile`, `execute`: the helper runs any release's DDL and any upgrade or rollback script.
- `UpgradeFrom014Test` (Testcontainers PostgreSQL): an `ldp_vc` row with a template blob and a `logo.url` display, and a `vc+sd-jwt` row, written in the 0.14.0 shape; after the 1.0.0 script `credential_subject` is `claims`, the format is `dc+sd-jwt` and the logo carries `uri`; after Flyway (baseline plus one migration) every row is `config_version` 2 with `format_config`, `signing_config`, `template_id` and a decoded `credential_template` row; tables, columns and indexes of a fresh Flyway schema are all present (extra columns of the upgraded road are printed as a finding, not asserted); the rollback script drops the 1.1.0 additions with the rows intact, and the migration applies again.

## Acceptance criteria

- [x] `UpgradeFrom014Test`, `FlywayMigrationTest`, `ConfigV2MigrationTest` green on PostgreSQL (the upgraded 0.14.0 database has no column difference from a fresh schema).
- [x] Full `certify-service` suite green (980 tests, 0 failures).
- [ ] CI green on the fork (Docker available there).
