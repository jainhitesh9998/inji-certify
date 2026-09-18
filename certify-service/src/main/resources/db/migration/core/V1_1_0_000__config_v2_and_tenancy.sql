-- 1.1.0: configuration model v2 beside the legacy columns, credential_template, issuance_transaction, ledger columns
-- and the tenant discriminator (docs/design/08-database.md). Additive: nothing is renamed or dropped; the legacy
-- columns keep serving the v1 config API and the compatibility read path. Rollback:
-- db_upgrade_script/inji_certify/sql/1.0.0_to_1.1.0_rollback.sql

-- ---- credential_config: the domain model ---------------------------------------------------------------
ALTER TABLE credential_config
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    ADD COLUMN IF NOT EXISTS format_config JSONB,
    ADD COLUMN IF NOT EXISTS signing_config JSONB,
    ADD COLUMN IF NOT EXISTS template_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS template_version INT,
    ADD COLUMN IF NOT EXISTS issuance_strategy VARCHAR(16) NOT NULL DEFAULT 'TEMPLATE',
    ADD COLUMN IF NOT EXISTS data_source_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS status_config JSONB,
    ADD COLUMN IF NOT EXISTS protocol_overrides JSONB,
    ADD COLUMN IF NOT EXISTS config_version SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN credential_config.format_config IS 'v2 model: format-specific selector and claims (context, types, vct, doctype, sdClaims, claims, mdocClaims, sdJwtClaims)';
COMMENT ON COLUMN credential_config.signing_config IS 'v2 model: provider, alias, alg, cryptosuite, didUrl';
COMMENT ON COLUMN credential_config.config_version IS '1 = legacy columns are the source of truth, 2 = the JSONB columns are';

-- ---- credential_template: versioned templates, decoded from the base64 blob ------------------------------
CREATE TABLE IF NOT EXISTS credential_template (
    id VARCHAR(128) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    engine VARCHAR(32) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    content TEXT NOT NULL,
    checksum VARCHAR(64),
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_credential_template PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS idx_credential_template_tenant ON credential_template(tenant_id);

-- ---- issuance_transaction: replaces the cache-only vcissuance entry; deferred, batch and notification ------
CREATE TABLE IF NOT EXISTS issuance_transaction (
    id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    access_token_hash VARCHAR(255),
    credential_config_id VARCHAR(2048),
    protocol_version VARCHAR(32),
    state VARCHAR(16) NOT NULL,
    holder_bindings JSONB,
    notification_id VARCHAR(128),
    credential_ids TEXT[],
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    CONSTRAINT pk_issuance_transaction PRIMARY KEY (id),
    CONSTRAINT chk_issuance_transaction_state CHECK (state IN ('PENDING', 'ISSUED', 'DEFERRED', 'FAILED', 'NOTIFIED'))
);
CREATE INDEX IF NOT EXISTS idx_issuance_transaction_expires_at ON issuance_transaction(expires_at);
CREATE INDEX IF NOT EXISTS idx_issuance_transaction_token ON issuance_transaction(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_issuance_transaction_notification ON issuance_transaction(notification_id);

-- ---- ledger: search and revocation by configuration ----------------------------------------------------
ALTER TABLE ledger
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    ADD COLUMN IF NOT EXISTS credential_config_id VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS format VARCHAR(32),
    ADD COLUMN IF NOT EXISTS protocol_version VARCHAR(32),
    ADD COLUMN IF NOT EXISTS transaction_id UUID;
CREATE INDEX IF NOT EXISTS idx_ledger_credential_config_id ON ledger(credential_config_id);

-- ---- tenant discriminator on the other tenant-scoped tables ----------------------------------------------
ALTER TABLE status_list_credential ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';
ALTER TABLE credential_status_transaction ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';
ALTER TABLE iar_session ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';

-- ---- unique indexes lead with tenant_id, rebuilt once ------------------------------------------------------
ALTER TABLE credential_config DROP CONSTRAINT IF EXISTS credential_config_credential_config_key_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_config_tenant_key ON credential_config(tenant_id, credential_config_key_id);
DROP INDEX IF EXISTS idx_credential_config_type_context_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_config_type_context_unique
    ON credential_config(tenant_id, credential_type, context, credential_format)
    WHERE credential_type IS NOT NULL AND credential_type <> '' AND context IS NOT NULL AND context <> '';
DROP INDEX IF EXISTS idx_credential_config_sd_jwt_vct_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_config_sd_jwt_vct_unique
    ON credential_config(tenant_id, sd_jwt_vct, credential_format)
    WHERE sd_jwt_vct IS NOT NULL AND sd_jwt_vct <> '';
DROP INDEX IF EXISTS idx_credential_config_doctype_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_config_doctype_unique
    ON credential_config(tenant_id, doctype, credential_format)
    WHERE doctype IS NOT NULL AND doctype <> '';
ALTER TABLE ledger DROP CONSTRAINT IF EXISTS uq_ledger_tracked_credential_id;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_tenant_credential_id ON ledger(tenant_id, credential_id);

-- ---- backfill: every existing row gets its v2 model from the legacy columns ------------------------------
UPDATE credential_config SET
    format_config = jsonb_strip_nulls(jsonb_build_object(
        'context', CASE WHEN context IS NULL OR context = '' THEN NULL ELSE to_jsonb(string_to_array(context, ',')) END,
        'types', CASE WHEN credential_type IS NULL OR credential_type = '' THEN NULL ELSE to_jsonb(string_to_array(credential_type, ',')) END,
        'vct', sd_jwt_vct,
        'doctype', doctype,
        'sdClaims', CASE WHEN sd_claim IS NULL OR sd_claim = '' THEN NULL ELSE to_jsonb(string_to_array(sd_claim, ',')) END,
        'claims', claims,
        'mdocClaims', mso_mdoc_claims,
        'sdJwtClaims', sd_jwt_claims)),
    signing_config = jsonb_strip_nulls(jsonb_build_object(
        'provider', CASE WHEN key_manager_app_id LIKE '%:%' THEN split_part(key_manager_app_id, ':', 1) ELSE 'keymanager' END,
        'alias', CASE WHEN key_manager_app_id LIKE '%:%' THEN substr(key_manager_app_id, position(':' IN key_manager_app_id) + 1)
                      ELSE key_manager_app_id || '/' || COALESCE(key_manager_ref_id, '') END,
        'alg', signature_algo,
        'cryptosuite', signature_crypto_suite,
        'didUrl', did_url)),
    status_config = CASE WHEN credential_status_purpose IS NULL OR cardinality(credential_status_purpose) = 0 THEN NULL
        ELSE jsonb_build_object('mechanism', 'BitstringStatusList', 'purposes', to_jsonb(credential_status_purpose)) END,
    config_version = 2
WHERE config_version = 1;

INSERT INTO credential_template (id, version, tenant_id, engine, mode, content, checksum, cr_dtimes)
SELECT config_id, 1, tenant_id, 'velocity', 'FULL_DOCUMENT', convert_from(decode(vc_template, 'base64'), 'UTF8'), md5(vc_template), NOW()
FROM credential_config
WHERE vc_template IS NOT NULL AND vc_template <> '' AND template_id IS NULL
ON CONFLICT (id, version) DO NOTHING;

UPDATE credential_config SET template_id = config_id, template_version = 1
WHERE vc_template IS NOT NULL AND vc_template <> '' AND template_id IS NULL;
