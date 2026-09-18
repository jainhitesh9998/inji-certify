# P0-05 Testcontainers PostgreSQL for repository and migration tests

Branch: `wp/p0-05-testcontainers-postgres` off `develop`. Phase 0 (guardrails). Size: S. Depends on: P0-04.

## Goal

Replace H2 for anything that touches JSONB, arrays, enums or migrations so tests exercise the real schema.

## Scope

- Add `org.testcontainers:postgresql` and a shared `PostgresTestContainer` base; keep H2 only for pure-service unit tests that do not hit repositories.
- Move `repository/*Test` and add `FlywayMigrationTest` (applies the chain to a fresh database, then to a develop-schema dump under `src/test/resources/db-dumps/develop.sql`).
- CI: confirm Docker on the `kattu` runners; fall back to a `services: postgres` container in the workflow if not.

## Acceptance criteria

- [ ] Repository tests pass against PostgreSQL 15 in CI.
- [ ] The schema-diff assertion from P0-04 runs here.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
