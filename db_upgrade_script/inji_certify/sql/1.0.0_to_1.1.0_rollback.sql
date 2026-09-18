-- Rollback of V1_1_0_000__config_v2_and_tenancy: drops what 1.1.0 added and restores the 1.0.0 unique indexes.
-- The legacy columns were never changed, so no data is lost; take a backup before running regardless.
SET search_path TO certify;

DROP INDEX IF EXISTS uq_ledger_tenant_credential_id;
ALTER TABLE ledger ADD CONSTRAINT uq_ledger_tracked_credential_id UNIQUE (credential_id);
ALTER TABLE ledger
    DROP COLUMN IF EXISTS transaction_id,
    DROP COLUMN IF EXISTS protocol_version,
    DROP COLUMN IF EXISTS format,
    DROP COLUMN IF EXISTS credential_config_id,
    DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_credential_config_doctype_unique;
DROP INDEX IF EXISTS idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS uq_credential_config_tenant_key;
ALTER TABLE credential_config ADD CONSTRAINT credential_config_credential_config_key_id_key UNIQUE (credential_config_key_id);
CREATE UNIQUE INDEX idx_credential_config_type_context_unique
    ON credential_config(credential_type, context, credential_format)
    WHERE credential_type IS NOT NULL AND credential_type <> '' AND context IS NOT NULL AND context <> '';
CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
    ON credential_config(sd_jwt_vct, credential_format)
    WHERE sd_jwt_vct IS NOT NULL and sd_jwt_vct <> '';
CREATE UNIQUE INDEX idx_credential_config_doctype_unique
    ON credential_config(doctype, credential_format)
    WHERE doctype IS NOT NULL and doctype <> '';
ALTER TABLE credential_config
    DROP COLUMN IF EXISTS config_version,
    DROP COLUMN IF EXISTS protocol_overrides,
    DROP COLUMN IF EXISTS status_config,
    DROP COLUMN IF EXISTS data_source_id,
    DROP COLUMN IF EXISTS issuance_strategy,
    DROP COLUMN IF EXISTS template_version,
    DROP COLUMN IF EXISTS template_id,
    DROP COLUMN IF EXISTS signing_config,
    DROP COLUMN IF EXISTS format_config,
    DROP COLUMN IF EXISTS tenant_id;

DROP TABLE IF EXISTS issuance_transaction;
DROP TABLE IF EXISTS credential_template;
ALTER TABLE status_list_credential DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE credential_status_transaction DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE iar_session DROP COLUMN IF EXISTS tenant_id;

DELETE FROM flyway_schema_history WHERE version = '1.1.0.000';
