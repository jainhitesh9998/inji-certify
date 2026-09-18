# Database scripts

Two ways to create or upgrade the `inji_certify` database, backed by the same SQL:

- **Flyway (recommended, since 1.0.0).** `certify-service` bundles per-module baseline migrations under
  `src/main/resources/db/migration/{core,keymanager,verify,as}` (generated from `inji_certify/ddl` by
  `generate_flyway_baseline.sh`). A fresh database gets the schema from them; a database created with the
  psql scripts is baselined at version `1.0.0.003` and left untouched (`spring.flyway.baseline-on-migrate`
  defaults to `true`, see `io.mosip.certify.db.FlywayDefaults`). Later schema changes ship as new versioned
  migrations in the same folders. Run them before a rollout with
  `java -Dloader.main=io.mosip.certify.tools.MigrateOnly -jar certify-service.jar` (the Helm chart's
  pre-upgrade Job does this when `dbMigration.enabled` is true), or let the service apply them at startup
  (docker-compose). Rollback scripts for every migration stay under `../db_upgrade_script`.
- **psql scripts (`inji_certify/`).** `db.sql`, `ddl.sql`, `dml.sql` as before, for operators who provision the
  database by hand. Keep `ddl/` and the Flyway baselines in sync by re-running `generate_flyway_baseline.sh`
  only for the baseline; after 1.0.0 the psql DDL is a snapshot and Flyway is the source of truth.

Tests: `certify-service/src/test/java/io/mosip/certify/db/FlywayMigrationTest.java` (Testcontainers PostgreSQL)
proves that both roads produce the same columns, indexes and constraints, and that an existing database is
baselined without running any migration.
