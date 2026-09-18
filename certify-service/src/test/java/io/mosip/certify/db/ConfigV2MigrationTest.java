package io.mosip.certify.db;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The 1.1.0 migration on a database a deployment has today: rows written by the v1 config API are backfilled into the
 * v2 JSONB model row by row (the migration verifier of docs/design/08-database.md), the template blob becomes a
 * credential_template row, tenant columns default to {@code default}, the rollback script returns to the 1.0.0
 * schema with the legacy rows intact, and a second migrate applies cleanly again.
 */
@Testcontainers(disabledWithoutDocker = true)
class ConfigV2MigrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final String TEMPLATE = "{\"@context\": [\"https://www.w3.org/2018/credentials/v1\"], \"issuer\": \"${_issuer}\"}";

    static PostgresSupport support() {
        return new PostgresSupport(POSTGRES);
    }

    @Test
    void legacyRowsAreBackfilledIntoTheV2ModelAndRolledBack() throws Exception {
        PostgresSupport db = support();
        String database = db.freshDatabase("config_v2");
        db.applyDdlScripts(database);
        String vcTemplate = Base64.getEncoder().encodeToString(TEMPLATE.getBytes(StandardCharsets.UTF_8));
        try (Connection c = db.dataSource(database).getConnection(); Statement s = c.createStatement()) {
            s.execute("SET search_path TO certify");
            s.execute(insert("ldp-1", "LdpCredential", "ldp_vc", "'" + vcTemplate + "'", "'https://www.w3.org/2018/credentials/v1'",
                    "'VerifiableCredential,FarmerCredential'", "NULL", "NULL", "'CERTIFY_VC_SIGN_ED25519'", "'ED25519_SIGN'", "'EdDSA'", "'Ed25519Signature2020'",
                    "NULL", "'{\"fullName\": {\"display\": [{\"name\": \"Full name\", \"locale\": \"en\"}]}}'", "ARRAY['revocation']"));
            s.execute(insert("sd-1", "SdJwtCredential", "dc+sd-jwt", "'" + vcTemplate + "'", "NULL", "NULL", "'FarmerCredential'", "NULL",
                    "'CERTIFY_VC_SIGN_EC_R1'", "'EC_SECP256R1_SIGN'", "'ES256'", "NULL", "'$.fullName,$.address.city'", "NULL", "NULL"));
            s.execute(insert("mdoc-1", "MdlCredential", "mso_mdoc", "NULL", "NULL", "NULL", "NULL", "'org.iso.18013.5.1.mDL'",
                    "'x509-file:mdl-signer@2'", "NULL", "'ES256'", "'ES256'", "NULL", "NULL", "NULL"));
        }

        assertEquals(1, db.flyway(database).migrate().migrationsExecuted, "baseline, then the 1.1.0 migration");

        JsonNode ldpFormat = json(db, database, "SELECT format_config::text FROM certify.credential_config WHERE config_id = 'ldp-1'");
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), MAPPER.convertValue(ldpFormat.get("context"), List.class));
        assertEquals(List.of("VerifiableCredential", "FarmerCredential"), MAPPER.convertValue(ldpFormat.get("types"), List.class));
        assertEquals("Full name", ldpFormat.get("claims").get("fullName").get("display").get(0).get("name").asText());
        assertFalse(ldpFormat.has("vct") || ldpFormat.has("doctype"), "nulls are stripped: " + ldpFormat);
        JsonNode ldpSigning = json(db, database, "SELECT signing_config::text FROM certify.credential_config WHERE config_id = 'ldp-1'");
        assertEquals("keymanager", ldpSigning.get("provider").asText());
        assertEquals("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", ldpSigning.get("alias").asText());
        assertEquals("EdDSA", ldpSigning.get("alg").asText());
        assertEquals("Ed25519Signature2020", ldpSigning.get("cryptosuite").asText());
        assertEquals("did:web:issuer", ldpSigning.get("didUrl").asText());
        JsonNode ldpStatus = json(db, database, "SELECT status_config::text FROM certify.credential_config WHERE config_id = 'ldp-1'");
        assertEquals("BitstringStatusList", ldpStatus.get("mechanism").asText());
        assertEquals("revocation", ldpStatus.get("purposes").get(0).asText());

        JsonNode sdFormat = json(db, database, "SELECT format_config::text FROM certify.credential_config WHERE config_id = 'sd-1'");
        assertEquals("FarmerCredential", sdFormat.get("vct").asText());
        assertEquals(List.of("$.fullName", "$.address.city"), MAPPER.convertValue(sdFormat.get("sdClaims"), List.class));
        assertEquals("NULL", scalar(db, database, "SELECT COALESCE(status_config::text, 'NULL') FROM certify.credential_config WHERE config_id = 'sd-1'"));

        JsonNode mdocSigning = json(db, database, "SELECT signing_config::text FROM certify.credential_config WHERE config_id = 'mdoc-1'");
        assertEquals("x509-file", mdocSigning.get("provider").asText(), "a provider-prefixed key column keeps its provider");
        assertEquals("mdl-signer@2", mdocSigning.get("alias").asText());
        assertEquals("org.iso.18013.5.1.mDL", json(db, database, "SELECT format_config::text FROM certify.credential_config WHERE config_id = 'mdoc-1'").get("doctype").asText());

        assertEquals("2,2,2", scalar(db, database, "SELECT string_agg(config_version::text, ',' ORDER BY config_id) FROM certify.credential_config"));
        assertEquals("default", scalar(db, database, "SELECT DISTINCT tenant_id FROM certify.credential_config"));
        assertEquals("TEMPLATE", scalar(db, database, "SELECT DISTINCT issuance_strategy FROM certify.credential_config"));
        assertEquals("2", scalar(db, database, "SELECT count(*)::text FROM certify.credential_template"));
        assertEquals(TEMPLATE, scalar(db, database, "SELECT content FROM certify.credential_template WHERE id = 'ldp-1'"));
        assertEquals("velocity/FULL_DOCUMENT/1", scalar(db, database, "SELECT engine || '/' || mode || '/' || version FROM certify.credential_template WHERE id = 'sd-1'"));
        assertEquals("ldp-1/1", scalar(db, database, "SELECT template_id || '/' || template_version FROM certify.credential_config WHERE config_id = 'ldp-1'"));
        assertNull(scalar(db, database, "SELECT template_id FROM certify.credential_config WHERE config_id = 'mdoc-1'"), "no template, no template row");
        assertTrue(db.tables(database).containsAll(Set.of("credential_template", "issuance_transaction")));
        assertTrue(db.indexes(database).stream().anyMatch(i -> i.contains("uq_credential_config_tenant_key")), "unique indexes lead with tenant_id");

        // the rollback script returns to the 1.0.0 shape with the legacy rows untouched, and the migration applies again
        Path rollback = PostgresSupport.DDL_DIR.getParent().getParent().resolve("db_upgrade_script/inji_certify/sql/1.0.0_to_1.1.0_rollback.sql");
        try (Connection c = db.dataSource(database).getConnection(); Statement s = c.createStatement()) {
            StringBuilder sql = new StringBuilder();
            for (String line : Files.readAllLines(rollback, StandardCharsets.UTF_8)) {
                if (!line.startsWith("\\")) {
                    sql.append(line).append('\n');
                }
            }
            s.execute(sql.toString());
        }
        assertEquals(15, db.tables(database).size(), "1.0.0 tables again");
        assertEquals("3", scalar(db, database, "SELECT count(*)::text FROM certify.credential_config"));
        assertFalse(db.columns(database).stream().anyMatch(c -> c.startsWith("credential_config.format_config")));
        assertTrue(db.constraints(database).stream().anyMatch(c -> c.contains("uq_ledger_tracked_credential_id")));
        assertEquals(1, db.flyway(database).migrate().migrationsExecuted, "1.1.0 applies again after the rollback");
        assertEquals("2", scalar(db, database, "SELECT count(*)::text FROM certify.credential_template"));
    }

    private static String insert(String id, String key, String format, String template, String context, String types, String vct, String doctype,
                                 String appId, String refId, String algo, String suite, String sdClaim, String claims, String purposes) {
        return "INSERT INTO credential_config (config_id, credential_config_key_id, status, vc_template, context, credential_type, sd_jwt_vct, doctype,"
                + " credential_format, did_url, key_manager_app_id, key_manager_ref_id, signature_algo, signature_crypto_suite, sd_claim, claims,"
                + " credential_status_purpose, display, display_order, scope, cryptographic_binding_methods_supported, credential_signing_alg_values_supported,"
                + " proof_types_supported, cr_dtimes) VALUES ('" + id + "', '" + key + "', 'active', " + template + ", " + context + ", " + types + ", "
                + vct + ", " + doctype + ", '" + format + "', 'did:web:issuer', " + appId + ", " + refId + ", " + algo + ", " + suite + ", " + sdClaim + ", "
                + (claims.equals("NULL") ? "NULL" : claims + "::jsonb") + ", " + purposes + ", '[]'::jsonb, ARRAY['fullName'], 'scope', ARRAY['did:jwk'], ARRAY['EdDSA'],"
                + " '{}'::jsonb, NOW())";
    }

    private static JsonNode json(PostgresSupport db, String database, String sql) throws Exception {
        return MAPPER.readTree(scalar(db, database, sql));
    }

    private static String scalar(PostgresSupport db, String database, String sql) throws SQLException {
        try (Connection c = db.dataSource(database).getConnection(); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }
}
