package io.mosip.certify.db;

import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The upgrade road a release 0.14.0 deployment takes (CLAUDE.md, non-negotiable 3; docs/design/11-roadmap.md Phase 2
 * exit criterion "upgrade and rollback rehearsed on 0.14.0 and develop dumps"): the 0.14.0 DDL as shipped in
 * {@code e54539a} (vendored under src/test/resources/db/v0.14.0), rows in the 0.14.0 shape, the operator's
 * 0.14.0_to_1.0.0 upgrade script, then Flyway baselining and the 1.1.0 migration with its backfill, the 1.1.0
 * rollback script, and the migration again. The result must carry every column a fresh Flyway schema has.
 */
@Testcontainers(disabledWithoutDocker = true)
class UpgradeFrom014Test {

    static final Path DDL_014 = locate("src/test/resources/db/v0.14.0");
    static final Path UPGRADE_SCRIPTS = PostgresSupport.DDL_DIR.getParent().getParent().resolve("db_upgrade_script").resolve("inji_certify").resolve("sql");
    static final int DDL_FILES_014 = 12;

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");
    static final PostgresSupport SUPPORT = new PostgresSupport(POSTGRES);

    @Test
    void aReleaseFourteenDatabaseUpgradesToOneOneAndBack() throws Exception {
        String db = SUPPORT.freshDatabase("v014");
        SUPPORT.applyDdlScripts(db, DDL_014, DDL_FILES_014);
        assertEquals(DDL_FILES_014, SUPPORT.tables(db).size(), SUPPORT.tables(db).toString());
        assertTrue(SUPPORT.columns(db).stream().anyMatch(c -> c.startsWith("credential_config.credential_subject:")), "0.14.0 names the claims column credential_subject");

        // two rows as a 0.14.0 operator wrote them through the v1 configuration API of that release
        SUPPORT.execute(db, "INSERT INTO credential_config (credential_config_key_id, config_id, status, vc_template, context, credential_type, credential_format,"
                + " did_url, key_manager_app_id, key_manager_ref_id, signature_algo, signature_crypto_suite, display, display_order, scope,"
                + " cryptographic_binding_methods_supported, credential_signing_alg_values_supported, proof_types_supported, credential_subject, cr_dtimes)"
                + " VALUES ('LegacyFarmerCredential', 'cfg-ldp', 'active', 'eyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfQ==', 'https://www.w3.org/2018/credentials/v1',"
                + " 'VerifiableCredential,FarmerCredential', 'ldp_vc', 'did:web:example', 'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN', 'EdDSA', 'Ed25519Signature2020',"
                + " '[{\"name\":\"Farmer\",\"locale\":\"en\",\"logo\":{\"url\":\"https://example.org/logo.png\"}}]', ARRAY['fullName'], 'farmer_vc_ldp', ARRAY['did:jwk'],"
                + " ARRAY['Ed25519Signature2020'], '{\"jwt\":{\"proof_signing_alg_values_supported\":[\"ES256\"]}}', '{\"fullName\":{\"display\":[{\"name\":\"Name\",\"locale\":\"en\"}]}}', now())");
        SUPPORT.execute(db, "INSERT INTO credential_config (credential_config_key_id, config_id, status, sd_jwt_vct, sd_claim, credential_format,"
                + " key_manager_app_id, key_manager_ref_id, signature_algo, display, display_order, scope, cryptographic_binding_methods_supported,"
                + " credential_signing_alg_values_supported, proof_types_supported, sd_jwt_claims, cr_dtimes)"
                + " VALUES ('LegacySdJwtCredential', 'cfg-sd', 'active', 'urn:example:vct', 'fullName', 'vc+sd-jwt', 'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN', 'ES256',"
                + " '[{\"name\":\"SD\",\"locale\":\"en\"}]', ARRAY['fullName'], 'sd_vc', ARRAY['jwk'], ARRAY['ES256'],"
                + " '{\"jwt\":{\"proof_signing_alg_values_supported\":[\"ES256\"]}}', '{\"fullName\":{\"display\":[{\"name\":\"Name\",\"locale\":\"en\"}]}}', now())");

        // the operator's road to 1.0.0: the shipped upgrade script
        SUPPORT.applySqlFile(db, UPGRADE_SCRIPTS.resolve("0.14.0_to_1.0.0_upgrade.sql"));
        assertTrue(SUPPORT.columns(db).stream().anyMatch(c -> c.startsWith("credential_config.claims:")), "1.0.0 renamed credential_subject to claims");
        assertEquals(Set.of("dc+sd-jwt"), SUPPORT.query(db, "SELECT credential_format FROM credential_config WHERE credential_config_key_id = 'LegacySdJwtCredential'"));
        assertEquals(Set.of("https://example.org/logo.png"), SUPPORT.query(db, "SELECT display->0->'logo'->>'uri' FROM credential_config WHERE credential_config_key_id = 'LegacyFarmerCredential'"), "1.0.0 renamed logo.url to logo.uri");

        // then the rebuild: Flyway adopts the schema and applies 1.1.0 with its backfill
        MigrateResult result = SUPPORT.flyway(db).migrate();
        assertEquals(1, result.migrationsExecuted, "baseline, then only 1.1.0");
        MigrationInfo[] applied = SUPPORT.flyway(db).info().applied();
        assertEquals(FlywayDefaults.BASELINE_VERSION, applied[0].getVersion().toString());
        assertEquals("1.1.0.000", applied[1].getVersion().toString());
        assertEquals(Set.of("2"), SUPPORT.query(db, "SELECT DISTINCT config_version::text FROM credential_config"), "every row is backfilled to the v2 model");
        assertEquals(Set.of("urn:example:vct"), SUPPORT.query(db, "SELECT format_config->>'vct' FROM credential_config WHERE credential_config_key_id = 'LegacySdJwtCredential'"));
        assertEquals(Set.of("VerifiableCredential"), SUPPORT.query(db, "SELECT format_config->'types'->>0 FROM credential_config WHERE credential_config_key_id = 'LegacyFarmerCredential'"));
        assertEquals(Set.of("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN"), SUPPORT.query(db, "SELECT signing_config->>'alias' FROM credential_config WHERE credential_config_key_id = 'LegacyFarmerCredential'"));
        assertEquals(Set.of("cfg-ldp"), SUPPORT.query(db, "SELECT template_id FROM credential_config WHERE credential_config_key_id = 'LegacyFarmerCredential'"), "the template blob becomes credential_template version 1");
        assertEquals(Set.of("{\"type\": [\"VerifiableCredential\"]}"), SUPPORT.query(db, "SELECT content FROM credential_template WHERE id = 'cfg-ldp'"), "decoded from base64");
        assertEquals(Set.of("default"), SUPPORT.query(db, "SELECT DISTINCT tenant_id FROM credential_config"));

        // the upgraded schema carries every column, index and constraint a fresh Flyway schema has
        String fresh = SUPPORT.freshDatabase("v014_fresh");
        SUPPORT.flyway(fresh).migrate();
        assertEquals(SUPPORT.tables(fresh), SUPPORT.tables(db), "tables after the 0.14.0 road differ from a fresh schema");
        Set<String> missingColumns = new TreeSet<>(SUPPORT.columns(fresh));
        missingColumns.removeAll(SUPPORT.columns(db));
        assertTrue(missingColumns.isEmpty(), "columns a fresh schema has but the upgraded 0.14.0 database lacks: " + missingColumns);
        Set<String> extraColumns = new TreeSet<>(SUPPORT.columns(db));
        extraColumns.removeAll(SUPPORT.columns(fresh));
        System.out.println("[upgrade 0.14.0] columns that differ from a fresh schema (kept as a finding): " + extraColumns);
        Set<String> missingIndexes = new TreeSet<>(SUPPORT.indexes(fresh));
        missingIndexes.removeAll(SUPPORT.indexes(db));
        assertTrue(missingIndexes.isEmpty(), "indexes a fresh schema has but the upgraded database lacks: " + missingIndexes);

        // the rollback script takes 1.1.0 away, and the migration puts it back
        SUPPORT.applySqlFile(db, UPGRADE_SCRIPTS.resolve("1.0.0_to_1.1.0_rollback.sql"));
        assertFalse(SUPPORT.columns(db).stream().anyMatch(c -> c.startsWith("credential_config.format_config:")), "rollback drops the v2 columns");
        assertFalse(SUPPORT.tables(db).contains("credential_template"));
        assertEquals(Set.of("LegacyFarmerCredential", "LegacySdJwtCredential"), SUPPORT.query(db, "SELECT credential_config_key_id FROM credential_config"), "rows survive the rollback");
        assertEquals(1, SUPPORT.flyway(db).migrate().migrationsExecuted, "1.1.0 applies again after the rollback");
        assertEquals(Set.of("2"), SUPPORT.query(db, "SELECT DISTINCT config_version::text FROM credential_config"));
    }

    private static Path locate(String relative) {
        Path path = Path.of(relative);
        if (!Files.isDirectory(path)) {
            path = Path.of("certify-service").resolve(relative);
        }
        if (!Files.isDirectory(path)) {
            throw new IllegalStateException(relative + " not found from " + Path.of("").toAbsolutePath());
        }
        return path.toAbsolutePath();
    }
}
