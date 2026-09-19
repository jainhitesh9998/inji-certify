# 15. Deployment of the rebuilt service

What ships, how it is configured, how a running deployment moves to it, and what is still open. Written on 2026-09-19 against `design/extensibility`; the shipping artefacts are the same ones develop ships today, which is the point of non-negotiable 3 in `CLAUDE.md`.

## What ships

| Artefact | Built from | Contents | Notes |
| --- | --- | --- | --- |
| `inji-certify` image | `certify-service/Dockerfile` (`eclipse-temurin:21-jre`, `configure_start.sh`, `java -jar -Dloader.path=<additional_jars>`) | The `certify-service` fat jar. Every rebuild module (`certify-spi`, `certify-issuance`, `certify-signing`, the formatters, template engines, key providers, `certify-authz`) is a Maven dependency of `certify-service`, so it is inside this one jar; there is no second deployable until P1-13 splits the modules, and even then they stay libraries inside the same jar | `push-trigger.yml` builds and pushes it through `mosip/kattu` on every push to the release branches; `manual-docker-build.yml` for ad hoc tags |
| `inji-certify-with-plugins` image | `certify-service-with-plugins/Dockerfile` (`FROM injistackdev/inji-certify:<tag>`, copies the plugin jars into `additional_jars`) | The service image plus the MOSIP identity, mock (CSV), Postgres data-provider and Sunbird plugin jars | The image the helm chart and the compose stack use; a deployment with its own plugin jars uses the base image and mounts them into `additional_jars` |
| Helm chart `helm/inji-certify` | `chart-lint-publish.yml` | Deployment, config maps from the Spring Cloud Config server, DB and HSM secrets, `softhsm` share | `deploy/inji-certify/install.sh` wraps it for the MOSIP cluster layout |
| `certify-cli` jar | `certify-cli` module | Key generation, JWS and COSE signing from a PKCS#12 keystore | An operator tool, not deployed |
| SQL | `db_scripts/` (fresh installs today), `db_upgrade_script/inji_certify/sql/*_upgrade.sql` and `*_rollback.sql`, Flyway migrations inside the jar under `db/migration/{core,keymanager,verify,as}` | See below |

Nothing in the rebuild adds a process, a port or a container. The new surface (`/oid4vci/...`), the v2 configuration API, tenancy, transactions, the notification endpoint and the key providers are all inside the same Spring Boot application on port 8090.

## Configuration

Deployments keep their property source (Spring Cloud Config server via `spring_config_url`/`spring_config_label`, or mounted files under `SPRING_CONFIG_LOCATION` as the compose stack does) and their profiles (`default`, a use-case profile such as `csvdp-farmer`, plus `rebuild` in the compose stack). Every existing `mosip.certify.*` key keeps its meaning. The rebuild adds typed `certify.*` keys, all with defaults, so an unchanged property file starts the new build:

| Key | Default | What it does |
| --- | --- | --- |
| `certify.protocol.oid4vci-d13.enabled` | `true` | The draft-13 compatibility adapter (0.14.0 body on `/issuance/credential`, `/vd11`, `/vd12`) |
| `certify.protocol.oid4vci-v1.compat-core.enabled` | `false` | Routes today's `/issuance/credential` through the new core (owner decision pending on flipping it) |
| `certify.protocol.oid4vci-v1.notification.retention` / `.purge-interval` | `P1D` / `PT1H` | Issuance transaction retention and purge |
| `certify.protocol.oid4vci-v1.nonce.single-use` | `true` | A nonce-endpoint nonce is consumed by the request it authorised |
| `certify.protocol.oid4vci-v1.batch.size` | `10` | Largest `proofs` array; advertised as `batch_credential_issuance.batch_size` |
| `certify.oid4vci.issuer-identifier` | derived: `mosip.certify.identifier` + `server.servlet.path` + `/oid4vci` | The new surface's Credential Issuer Identifier |
| `certify.tenancy.enabled`, `.resolver` (`fixed`/`host`/`path`), `.tenants.<id>.*` | `false`, `fixed` | Tenancy; single tenant `default` unless enabled |
| `certify.keyprovider.x509-file.*` | off | PKCS#12 key provider next to keymanager |
| `mosip.certify.deprecated.<endpoint>.enabled` | `true` | Kill switches of the deprecated endpoints (`410 Gone` when `false`) |

Security lists (`mosip.certify.security.ignore-auth-urls`, `ignore-csrf-urls`, `mosip.certify.authn.filter-urls`) need no new entries: the new surface declares its own security chain and token filter, and `/v2/credential-configurations` sits under the existing `**/credential-configurations/**` patterns. The token filter still validates against `mosip.certify.authn.issuer-uri` and `jwk-set-uri`, whether that is eSignet or Certify's own authorization server (the `rebuild` profile in the compose stack).

The issuer identity is unchanged: `mosip.certify.identifier` and `mosip.certify.domain.url` for the legacy document, the derived `/oid4vci` identifier for the new one, `mosip.certify.data-provider-plugin.did-url` for the DID. Set them to the URL wallets reach (behind nginx: the public host name; the compose default `http://certify-nginx:80` is internal).

Keys: keymanager stays the default provider with the same `key_policy_def`, keystore (`CERTIFY_PKCS12` mount or the HSM client that `configure_start.sh` installs when `install_hsm_client=true`), aliases and rotation; `kid` values and signature bytes are unchanged. The `x509-file` provider is opt-in for deployments with their own PKI.

## Database

`spring.jpa.hibernate.ddl-auto` stays `none`. On startup Flyway runs with `baselineOnMigrate=true` and baseline version `1.0.0.003`:

- A database created by `db_scripts` (every deployment today) is adopted as the baseline and only `V1_1_0_000__config_v2_and_tenancy` runs: additive JSONB columns, `credential_template`, `issuance_transaction`, ledger and `tenant_id` columns, unique indexes led by `tenant_id`, and a backfill that sets `config_version = 2` on every row. Rehearsed on PostgreSQL from the develop DDL (`FlywayMigrationTest`) and from a 0.14.0 database (`UpgradeFrom014Test`).
- An empty database gets the full schema from the baseline migrations. It still lacks the `key_policy_def` seed rows keymanager needs at first start; today `init_db.sh` seeds them (owner decision pending on a Flyway DML migration).
- Rollback: `db_upgrade_script/inji_certify/sql/1.0.0_to_1.1.0_rollback.sql` drops the 1.1.0 additions with the rows intact and removes the Flyway history row, so the previous image starts again.

## Moving a running deployment

1. **From 1.0.0-beta.1 (develop):** deploy the new image with the same properties, keystore and database. Flyway applies 1.1.0 on the first start; nothing else changes. Endpoints, plugins, `kid` values and signature bytes are the same (the v1 and d13 goldens are the proof). New in the logs: `Deprecation` headers and the `certify.deprecated.calls` counter on the deprecated endpoints.
2. **From 0.14.0:** run `db_upgrade_script/inji_certify/sql/0.14.0_to_1.0.0_upgrade.sql` as before, then deploy as in step 1. `UpgradeFrom014Test` rehearses exactly this road and ends in the same schema as a fresh install.
3. **Back:** stop, run the 1.1.0 rollback script, start the previous image.

## Validation before shipping

`docs/design/VALIDATE.md` is the runbook: build the image from the checkout (`docker-compose.rebuild.yaml`), the pre-authorized code flow with a wallet or with `docs/design/tools/smoke.py`, and the independent verification of the issued credential. CI (`rebuild-ci.yml`) runs the full suite with Docker, so the PostgreSQL migration and status-list tests are part of every gate.

## Open before a production release

- The image tag and namespace for the rebuild (`inji-certify:rebuild` is the compose stack's local name; the published images keep their names and gain the new version).
- The Spring Cloud Config repository needs the new `certify.*` keys only where a deployment changes a default.
- The OpenID Foundation conformance run for the new surface (Phase 3) and independent mDoc and SD-JWT verifiers in the test suite.
- The owner decisions listed in the review document: compat-core flip, `key_policy_def` seed, `c_nonce` for draft-13 wallets, the remaining compatibility endpoints' deprecation headers.
