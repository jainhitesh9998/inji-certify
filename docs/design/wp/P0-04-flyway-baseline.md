# P0-04 Flyway with per-module locations and a 1.0.0 baseline

Branch: `wp/p0-04-flyway-baseline` off `develop`. Phase 0 (guardrails). Size: M. Depends on: none.

## Goal

Put schema versioning under Flyway without changing a single table, so later migrations are ordered, idempotent and runnable from a Kubernetes Job.

## Scope

- Add `flyway-core` and `flyway-database-postgresql` to `certify-service`; set `spring.flyway.baseline-on-migrate=true`, `baseline-version=1.0.0.000`, `validate-on-migrate=true`.
- Locations: `classpath:db/migration/core`, `db/migration/keymanager`, `db/migration/verify`, `db/migration/as`; generate `V1_0_0_000__baseline.sql` per location from `db_scripts/inji_certify/ddl/*.sql` (core: credential_config, rendering_template, status_list_*, ledger, credential_status_transaction, shedlock; keymanager: key_alias, key_policy_def, key_store, ca_cert_store; verify: the three verify tables; as: iar_session).
- A `spring.flyway.enabled` switch; docker-compose runs `migrate` in an init container; add a Helm pre-upgrade Job manifest under `helm/`; `db_upgrade_script/README` explains both paths and that the SQL files are the same.
- Keep `db_upgrade_script/inji_certify` publishing per-release SQL exports (script that concatenates the Flyway files for a version range).

## Acceptance criteria

- [ ] A fresh Postgres gets the same schema from Flyway as from `db_scripts` (schema diff test via Testcontainers, WP P0-05).
- [ ] An existing develop database is baselined with no DDL executed (`flyway_schema_history` has one baseline row).
- [ ] `spring.jpa.hibernate.ddl-auto` stays `none`.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
