# Database

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

Develop has 15 tables in one `certify` schema with three owners (Certify, the embedded keymanager library, the embedded `verify-core` library), hand-run psql upgrades, and most runtime state in caches. The recommendation: Flyway with per-module migration locations, a hybrid JSONB configuration model, durable Postgres rows for transactions and offers with cache only for nonces and DPoP replay, and a core schema that boots with zero keymanager or verify tables so any key manager can be plugged in.

| Table | Owner | Written by | Read by | Notes |
| --- | --- | --- | --- | --- |
| `credential_config` | Certify | config API | every credential request (`findAll()`), `did.json` (`findAll()`) | Union of formats; comma-string `context` and `credential_type`; three partial unique indexes; `plugin_configurations` never read |
| `rendering_template` | Certify | DML, manual | Velocity digest, `/rendering-template/{id}` | Global property picks the template |
| `status_list_credential`, `status_list_available_indices`, `credential_status_transaction` | Certify | issuance, `/credentials/status`, `StatusListUpdateBatchJob` | `/credentials/status-list/{id}` | `credential_status_enum` type; FK with cascade |
| `ledger` | Certify | issuance | `/ledger-search` | JSONB `indexed_attributes` and `credential_status_details` with GIN indexes; unbounded growth |
| `iar_session` | Certify (AS) | `/oauth/iae`, `/oauth/token` | same | PKCE, authorization code, identity data as text |
| `shedlock` | Certify | batch job | batch job | Distributed lock, already in place |
| `key_alias`, `key_policy_def`, `key_store`, `ca_cert_store` | keymanager library | `AppConfig.initKeys`, `/system-info/*` | every signature | Created by Certify's DDL, mapped by keymanager's JPA entities that `AppConfig` scans (`@EnableJpaRepositories("io.mosip.kernel.keymanagerservice.repository")`) |
| `authorization_request_details`, `vc_submission`, `vp_submission` | `verify-core` library | IAE flow | IAE flow | Added by `0.14.0_to_1.0.0_upgrade.sql` into the `certify` schema |

State that lives only in caches (`simple` per instance, or Redis): `vcissuance`, `nonce`, `preAuthCodeCache`, `credentialOfferCache`, `preAuthCacheTxn`, `dpopJti`, plus read caches `credentialConfig`, `jwks`, `certificatedatacache`, `renderTemplate`, `userinfo`. With `spring.cache.type=simple` a second replica cannot see a nonce, an offer or a used DPoP `jti` minted by the first; `DpopProofValidator.warnOnNonDistributedCache` already says so for one of them.

Migration mechanics today: `upgrade.sh` terminates every other backend on the database (`:24`), then runs `sql/${CURRENT}_to_${UPGRADE}_upgrade.sql` with `ON_ERROR_STOP` (`:30-33`); rollback pairs exist for every step; `spring.jpa.hibernate.ddl-auto=none`; no version table in the database, so nothing stops a script running twice or out of order. Tests run on H2 (`jdbc:h2:mem:mosip_esignet` in `application-test.properties`) while production is Postgres-only (JSONB, `TEXT[]`, an `ENUM` type, GIN and partial indexes), so schema behaviour is not what the tests exercise.

Option set 1, migration tooling:

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Keep hand-run psql scripts | No new dependency; operations know it | No version tracking, no idempotency, terminate-backends step, cannot run as a Kubernetes init step without wrapping | Keep only as an exported artefact |
| Flyway (community) | Spring Boot native; `flyway_schema_history`; `baselineOnMigrate` adopts existing databases; plain SQL files; per-module `locations`; runs at boot or from a CLI or init Job | No undo in the community edition (keep rollback scripts by convention); one location per vendor | Recommended |
| Liquibase | Undo support; vendor-neutral changelogs | Heavier; the team writes plain SQL; vendor neutrality is not needed for a Postgres-only schema | Not needed |
| Hibernate `ddl-auto=update` | Zero effort | Non-deterministic, no data migrations, no indexes or comments, unsafe in production | No |

Decided 2026-09-18: Flyway `migrate` in a Helm pre-install or pre-upgrade Job and an init container in docker-compose, with the application running only `validate` at boot (`spring.flyway.enabled=true`, `validate-on-migrate`), so a replica never races another on DDL. Baseline at `1.0.0` (`V1_0_0_000__baseline.sql` generated from today's `ddl.sql`, `baselineOnMigrate=true`), and one location per module: `db/migration/core`, `db/migration/as`, `db/migration/keymanager`, `db/migration/verify`, assembled from the modules present on the classpath. The same SQL files stay under `db_upgrade_script` for anyone who must run psql by hand.

Option set 2, where `credential_config` goes:

| Criterion | A: keep the row, add JSONB `format_config`, `signing_config`, `status_config` (hybrid) | B: common table plus one table per format (`ldp_vc_config`, `sd_jwt_config`, `mdoc_config`) | C: one document table `credential_config(id, version, document JSONB)` with generated columns for indexes |
| --- | --- | --- | --- |
| Cost of a new format | New JSON shape, no DDL | New table, FK, repository, mapper | None |
| Uniqueness per format | Generated `selector_key` column plus one unique index | Native per table | Generated column plus unique index |
| Lookup by id, scope, format | Same as today | Joins | Indexed generated columns |
| Validation | In the formatter's `parseConfig` | Split between DDL and code | In the formatter's `parseConfig` |
| Compatibility with the v1 config API | Dual-write during transition | Requires a view or rewrite | Requires a view or rewrite |
| Postgres-only features | JSONB (already used) | None new | JSONB, generated columns (Postgres 12+) |
| Verdict | Now: additive, reversible, keeps the v1 API alive | No | At sunset, if the team accepts JSON as the source of truth |

Option set 3, runtime state:

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Cache only (today) | Fast; TTL is native | Per-instance unless Redis; transactions vanish on restart; deferred issuance and notifications impossible; DPoP replay protection needs Redis anyway | Not for anything that must survive a restart |
| Postgres tables with `expires_at` and a ShedLock cleanup job | Durable; transactional with `ledger`; no extra infrastructure; single-use via `DELETE ... RETURNING` | Write load on hot paths; needs the cleanup job (the scheduler already exists) | For `issuance_transaction`, `credential_offer`, `pre_authorized_code` |
| Redis for short-lived, high-write items | Right tool for nonces and replay ids | One more mandatory component for multi-replica deployments | For `nonce` and `dpopJti`, with a Postgres `nonce` table as the fallback when Redis is absent |

Keymanager tables, and the provision for any key manager. Keymanager is an embedded library and remains one; today `CertifyServiceApplication` scans 15 `io.mosip.kernel.*` packages, `AppConfig` registers keymanager's repositories and entities, Certify's own DDL creates its four tables in the `certify` schema, and `AppConfig.initKeys` populates them at boot. The same library, tables and properties continue to be the default; what changes is that they are owned by the keymanager provider module, so a deployment that picks another provider does not need them.

| Key manager | Tables in Certify's database | Bootstrap | Trust material for mDoc and SD-JWT chains |
| --- | --- | --- | --- |
| Embedded MOSIP kernel-keymanager (default; every existing deployment; HSM via its own `PKCS11`, `PKCS12` or offline keystore) | `key_alias`, `key_policy_def`, `key_store`, `ca_cert_store`, unchanged, owned by `certify-keyprovider-keymanager` and created by its Flyway location, which is active by default | `KeymanagerKeyProvider.ensureKeys`, the same keys `AppConfig.initKeys` creates today; rotation by `key_policy_def` as today | `ca_cert_store` via `/system-info/upload-ca-certificate`, unchanged |
| Any other key manager (cloud KMS SDK, Vault, JCA file, another key-management library, PKCS#11 without keymanager; opt-in modules) | None of the keymanager tables | Keys created by the operator, or by `ensureKeys` where the provider supports it | A small Certify-owned `trust_anchor` table (`id`, `purpose`, `pem`, `not_after`) or provider configuration |

The rule that follows: the core schema must boot and pass its tests with zero keymanager and zero verify tables; `ddl.sql` splits into `core`, `keymanager`, `as` and `verify` files; `kernel-keymanager-service` moves from `certify-service/pom.xml` into the provider module, whose auto-configuration owns the `io.mosip.kernel` component scan, `@EnableJpaRepositories` and `@EntityScan`; `/system-info/*` becomes the keymanager provider's admin endpoints and disappears when another provider is active.

Verify tables (decided 2026-09-18: they stay in the `certify` schema unrenamed) follow the same ownership rule: `authorization_request_details`, `vc_submission` and `vp_submission` are created by `certify-as`'s Flyway location only when that module is deployed; in the same schema they carry a `verify_` prefix for readability, or live in their own `verify` schema if `verify-core` supports a configurable schema.

Changes per table, all additive until the sunset release:

| Table | Change | Why |
| --- | --- | --- |
| `credential_config` | Add `format_config JSONB`, `signing_config JSONB`, `template_id VARCHAR(128)`, `template_version INT`, `issuance_strategy VARCHAR(16) DEFAULT 'TEMPLATE'`, `data_source_id VARCHAR(128)`, `status_config JSONB`, `protocol_overrides JSONB`, `config_version SMALLINT DEFAULT 1`; backfill in the same migration | Holds the domain model; legacy columns stay for the partial unique indexes until sunset |
| `credential_template` (new) | `id`, `engine`, `mode`, `version`, `content TEXT`, `checksum`, `cr_dtimes`; backfill by decoding `vc_template` from base64 | Versioned, shareable templates; ends the base64 blob |
| `issuance_transaction` (new) | `id UUID`, `access_token_hash`, `credential_config_id`, `protocol_version`, `state` (PENDING, ISSUED, DEFERRED, FAILED, NOTIFIED), `holder_bindings JSONB`, `notification_id`, `credential_ids TEXT[]`, `cr_dtimes`, `expires_at`, index on `expires_at` | Replaces the cache-only `vcissuance` entry; enables deferred, batch and notification |
| `credential_offer`, `pre_authorized_code` (new, owned by `certify-as`) | `offer_id`, `payload JSONB`, `code_hash`, `tx_code_hash`, `expires_at`, `used_at` | Offers and codes survive restarts and replicas |
| `nonce` (new, optional fallback) | `value` PK, `client_id`, `issued_at`, `expires_at`; consumed with `DELETE ... RETURNING` | Single-use nonces without Redis |
| `trust_anchor` (new, optional) | `id`, `purpose`, `pem`, `not_after` | Chains for non-keymanager providers |
| `ledger` | Add `credential_config_id`, `format`, `protocol_version`, `transaction_id`; consider monthly partitioning by `issuance_date` above roughly 10 million rows | Search and revocation by configuration; growth control |
| `status_list_credential` | Add `mechanism VARCHAR(64) DEFAULT 'BitstringStatusList'`, `format VARCHAR(32)`; `vc_document` holds the serialized artefact for either mechanism | Token Status List beside Bitstring |
| `credential_config` (sunset) | Drop `context`, `credential_type`, `doctype`, `sd_jwt_vct`, `sd_claim`, `claims`, `mso_mdoc_claims`, `sd_jwt_claims`, `vc_template`, `did_url`, `key_manager_app_id`, `key_manager_ref_id`, `signature_algo`, `signature_crypto_suite`, `plugin_configurations`; replace the three partial indexes with one unique index on `(credential_format, selector_key)` | The DB half of the format switch goes away |
| Keymanager and verify tables | No schema change; ownership and Flyway location move as above | Optional per deployment |

Tenant-ready columns (decided 2026-09-18: shared schema with a discriminator column). The 1.1.0 migration also adds `tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'` to `credential_config`, `credential_template`, `ledger`, `status_list_credential`, `credential_status_transaction`, `issuance_transaction`, `iar_session`, `credential_offer`, `pre_authorized_code` and `trust_anchor`, and rewrites the unique indexes to lead with `tenant_id`, in the same migration as the JSONB columns so indexes are rebuilt once. A single-tenant deployment never sets the column. Isolation options for later, in increasing cost: discriminator column (this migration, with Hibernate's `@TenantId` filter), schema per tenant (a Flyway `schemas` list and Hibernate `SCHEMA` multi-tenancy, the same migrations applied per schema), database per tenant (a `MultiTenantConnectionProvider` routing by tenant). The keymanager tables are not tenant-scoped; tenant keys are told apart by `KeyRef` alias namespaces (an `appId` per tenant) or by a second provider.

Backfill for `credential_config`, in the same migration as the new columns:

```sql
UPDATE certify.credential_config SET
  format_config = jsonb_strip_nulls(jsonb_build_object(
    'context', string_to_array(context, ','), 'types', string_to_array(credential_type, ','),
    'vct', sd_jwt_vct, 'doctype', doctype,
    'sdClaims', string_to_array(sd_claim, ','), 'claims', claims,
    'mdocClaims', mso_mdoc_claims, 'sdJwtClaims', sd_jwt_claims)),
  signing_config = jsonb_build_object('provider', 'keymanager',
    'alias', key_manager_app_id || '/' || COALESCE(key_manager_ref_id, ''),
    'alg', signature_algo, 'cryptosuite', signature_crypto_suite, 'didUrl', did_url),
  status_config = CASE WHEN credential_status_purpose IS NULL THEN NULL
    ELSE jsonb_build_object('mechanism', 'BitstringStatusList', 'purposes', to_jsonb(credential_status_purpose)) END,
  config_version = 2
WHERE config_version = 1;

INSERT INTO certify.credential_template (id, engine, mode, version, content, checksum, cr_dtimes)
SELECT config_id, 'velocity', 'FULL_DOCUMENT', 1,
       convert_from(decode(vc_template, 'base64'), 'UTF8'), md5(vc_template), now()
FROM certify.credential_config WHERE vc_template IS NOT NULL;
UPDATE certify.credential_config SET template_id = config_id, template_version = 1 WHERE vc_template IS NOT NULL;
```

Rules that keep an upgrade safe: the read path prefers JSONB when `config_version >= 2` and falls back to legacy columns otherwise; the v1 config API writes both shapes; the v2 config API writes JSONB and derives the legacy columns until sunset; a migration-verifier test compares the two read paths row by row; each Flyway version ships with a rollback script; nothing is renamed before the sunset release; the test suite runs against Postgres (Testcontainers) instead of H2 from Phase 0.

| Release | Migration | Additive | Rollback |
| --- | --- | --- | --- |
| 1.0.0 | Flyway baseline from today's `ddl.sql`; locations split by module; no schema change | yes | none needed |
| 1.1.0 | `credential_config` JSONB columns and backfill; `credential_template`; `issuance_transaction`; `ledger` columns | yes | drop the added columns and tables |
| 1.2.0 | `credential_offer`, `pre_authorized_code`, `nonce`, `trust_anchor`; `status_list_credential.mechanism` | yes | drop |
| 2.0.0 | Drop legacy `credential_config` columns; new selector index; keymanager and verify tables optional | no | reverse backfill after a backup |
