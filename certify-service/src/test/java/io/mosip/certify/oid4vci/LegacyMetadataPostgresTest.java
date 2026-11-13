package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.db.FlywayDefaults;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * G32 on the database a deployment actually runs: reading the credential issuer metadata, or one configuration, never
 * writes {@code credential_config}, and the {@code TEXT[]} columns round-trip through PostgreSQL's real arrays.
 *
 * <p>Every read of an {@code mso_mdoc} row used to rewrite it: Hibernate's snapshot of {@code msoMdocClaims} never
 * equalled the loaded value (fixed in {@code TypedJsonBinaryType}), so a read in a read-write transaction flushed one
 * whole-row {@code UPDATE}. PostgreSQL got back the values it had just returned, so no document changed and the old
 * version of this test (which compared documents and array values) passed with the defect present; the H2 test schema
 * showed it as bracket nesting (F-17 review rounds 1 and 2). The guard is therefore the row version itself: a row's
 * {@code xmin} changes with every {@code UPDATE} even when the values do not, and Hibernate's statistics count the
 * entity updates. Each read evicts the issuer-metadata cache first, so it reaches the database (the loads are counted
 * too, so the test cannot pass by not reading). Four paths are held: the metadata through the registry, one
 * configuration through the v1 service, a load inside a read-write transaction (the root cause, without any
 * read-only attribute to hide it), and a load through the request-bound {@code EntityManager} that
 * {@code spring.jpa.open-in-view} keeps for a whole request, flushed by a later read-write transaction in that request.
 * Skipped without Docker.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@Testcontainers(disabledWithoutDocker = true)
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}",
        // entity update and load counts for the no-write assertions
        "spring.jpa.properties.hibernate.generate_statistics=true"
})
class LegacyMetadataPostgresTest {

    static final String SCHEMA = "certify";
    static final String LDP_ID = "PostgresStableLdp";
    static final String MDOC_ID = "PostgresStableMdl";

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    /** What a deployment does before the service starts: the Flyway job, then the keymanager policy rows from db_scripts. */
    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) throws Exception {
        String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/"
                + POSTGRES.getDatabaseName() + "?currentSchema=" + SCHEMA;
        DataSource dataSource = dataSource(url);
        Flyway.configure().dataSource(dataSource).schemas(SCHEMA).defaultSchema(SCHEMA)
                .locations(FlywayDefaults.DEFAULT_LOCATIONS.toArray(new String[0]))
                .baselineOnMigrate(true).baselineVersion(FlywayDefaults.BASELINE_VERSION)
                .load().migrate();
        seedKeyPolicies(dataSource);

        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driverClassName", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.sql.init.mode", () -> "never");
        registry.add("mosip.kernel.keymanager.hsm.config-path", () -> Path.of("target", "metadata-postgres-pki.p12").toString());
    }

    static DataSource dataSource(String url) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        ds.setUser(POSTGRES.getUsername());
        ds.setPassword(POSTGRES.getPassword());
        return ds;
    }

    /** The rows of db_scripts/inji_certify/dml/certify-key_policy_def.csv, which init_db.sh loads with psql \COPY. */
    static void seedKeyPolicies(DataSource dataSource) throws Exception {
        List<String> lines = Files.readAllLines(locate("db_scripts/inji_certify/dml/certify-key_policy_def.csv"), StandardCharsets.UTF_8);
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("INSERT INTO " + SCHEMA
                + ".key_policy_def (app_id, key_validity_duration, pre_expire_days, access_allowed, is_active, cr_by, cr_dtimes) VALUES (?, ?, ?, ?, ?, ?, NOW())")) {
            for (String line : lines.subList(1, lines.size())) {
                if (line.isBlank()) {
                    continue;
                }
                String[] f = line.split(",");
                ps.setString(1, f[0]);
                ps.setInt(2, Integer.parseInt(f[1]));
                ps.setInt(3, Integer.parseInt(f[2]));
                ps.setString(4, f[3]);
                ps.setBoolean(5, Boolean.parseBoolean(f[4]));
                ps.setString(6, f[5]);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    static Path locate(String relative) {
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve(relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException(relative + " not found above " + Paths.get("").toAbsolutePath());
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void seed() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(LDP_ID, "ldp_vc"));
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(MDOC_ID, "mso_mdoc"));
        }
    }

    @Test
    void repeatedLegacyMetadataReadsCarryStableArrays() throws Exception {
        List<List<String>> cbm = new ArrayList<>();
        List<List<String>> order = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            JsonNode document = metadata("/issuance/.well-known/openid-credential-issuer");
            JsonNode mdoc = document.path("credential_configurations_supported").path(MDOC_ID);
            JsonNode ldp = document.path("credential_configurations_supported").path(LDP_ID);
            List<String> mdocCbm = strings(mdoc.path("cryptographic_binding_methods_supported"));
            List<String> mdocOrder = strings(mdoc.path("order"));
            // the real text[] columns hold exactly what was written: no "[cose_key]"-in-a-string nesting
            assertEquals(List.of("cose_key"), mdocCbm, "read " + i + ": " + mdoc);
            assertEquals(List.of("family_name", "birth_date"), mdocOrder, "read " + i + ": " + mdoc);
            assertEquals(List.of("did:jwk", "did:web"), strings(ldp.path("cryptographic_binding_methods_supported")));
            assertEquals(List.of("fullName"), strings(ldp.path("order")));
            cbm.add(mdocCbm);
            order.add(mdocOrder);
            // the 1.0 surface builds the same metadata from the same rows; alternating must not change either
            JsonNode oneZero = metadata("/oid4vci/.well-known/openid-credential-issuer");
            assertEquals(List.of("cose_key"),
                    strings(oneZero.path("credential_configurations_supported").path(MDOC_ID).path("cryptographic_binding_methods_supported")));
        }
        assertEquals(List.of(List.of("cose_key"), List.of("cose_key"), List.of("cose_key")), cbm);
        assertEquals(List.of(List.of("family_name", "birth_date"), List.of("family_name", "birth_date"),
                List.of("family_name", "birth_date")), order);

        // and the stored row itself is unchanged after those reads
        List<String> storedCbm = jdbcArray("cryptographic_binding_methods_supported");
        assertEquals(List.of("cose_key"), storedCbm, "the read path must not rewrite the column");
        assertEquals(List.of("family_name", "birth_date"), jdbcArray("display_order"));
    }

    @Autowired javax.sql.DataSource dataSource;
    @Autowired io.mosip.certify.core.spi.CredentialRegistry credentialRegistry;
    @Autowired jakarta.persistence.EntityManagerFactory entityManagerFactory;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;

    /** The metadata documents are built from the rows without writing them: no row version moves, no entity update. */
    @Test
    void metadataReadsNeverWriteTheRows() throws Exception {
        long ldp = xmin(LDP_ID);
        long mdoc = xmin(MDOC_ID);
        org.hibernate.stat.EntityStatistics rows = rowStatistics();
        long loads = rows.getLoadCount();
        long updates = rows.getUpdateCount();
        for (int i = 0; i < 3; i++) {
            for (String path : List.of("/oid4vci/.well-known/openid-credential-issuer", "/.well-known/openid-credential-issuer",
                    "/issuance/.well-known/openid-credential-issuer")) {
                credentialRegistry.evict(); // the registry caches the document; every read must reach the rows
                long before = rows.getLoadCount();
                metadata(path);
                assertTrue(rows.getLoadCount() > before, path + " read " + i + " must load the rows, not a cached document");
            }
        }
        assertTrue(rows.getLoadCount() - loads >= 9);
        assertEquals(updates, rows.getUpdateCount(), "a metadata read must not update credential_config");
        assertEquals(mdoc, xmin(MDOC_ID), "the mso_mdoc row was rewritten by a metadata read");
        assertEquals(ldp, xmin(LDP_ID), "the ldp_vc row was rewritten by a metadata read");
    }

    /** {@code getCredentialConfigurationById}, the v1 config API's read: the same guard. */
    @Test
    void readingOneConfigurationNeverWritesIt() throws Exception {
        long mdoc = xmin(MDOC_ID);
        org.hibernate.stat.EntityStatistics rows = rowStatistics();
        long updates = rows.getUpdateCount();
        for (int i = 0; i < 3; i++) {
            long before = rows.getLoadCount();
            assertEquals(MDOC_ID, credentialConfigurationService.getCredentialConfigurationById(MDOC_ID).getCredentialConfigKeyId());
            assertTrue(rows.getLoadCount() > before, "read " + i + " must load the row");
        }
        assertEquals(updates, rows.getUpdateCount(), "reading a configuration must not update it");
        assertEquals(mdoc, xmin(MDOC_ID), "the mso_mdoc row was rewritten by getCredentialConfigurationById");
    }

    /**
     * The root cause on its own: a load inside a read-write transaction, then a commit, with no read-only attribute in
     * the way. Any service that reads a configuration inside its own read-write transaction takes this path.
     */
    @Test
    void loadingInAReadWriteTransactionWritesNothing() {
        long mdoc = xmin(MDOC_ID);
        long updates = rowStatistics().getUpdateCount();
        new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status ->
                assertTrue(credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isPresent()));
        assertEquals(updates, rowStatistics().getUpdateCount(), "a load and a commit must not update the row");
        assertEquals(mdoc, xmin(MDOC_ID), "the mso_mdoc row was rewritten by a read-write transaction that only loaded it");
    }

    /**
     * What {@code spring.jpa.open-in-view} (on by default) does for a request: one {@code EntityManager} bound to the
     * thread, so a configuration looked up outside any transaction stays managed, and the next read-write transaction
     * of that request (a status-list allocation, a ledger write) flushes it on commit.
     */
    @Test
    void aRequestBoundLookupIsNotFlushedByALaterTransaction() {
        long mdoc = xmin(MDOC_ID);
        long updates = rowStatistics().getUpdateCount();
        jakarta.persistence.EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        org.springframework.transaction.support.TransactionSynchronizationManager.bindResource(entityManagerFactory,
                new org.springframework.orm.jpa.EntityManagerHolder(requestEntityManager));
        try {
            assertTrue(credentialConfigRepository.findByTenantIdAndCredentialConfigKeyId("default", MDOC_ID).isPresent());
            new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status ->
                    assertTrue(credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isPresent()));
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
        }
        assertEquals(updates, rowStatistics().getUpdateCount(), "the request's later transaction must not flush the lookup");
        assertEquals(mdoc, xmin(MDOC_ID), "the mso_mdoc row was rewritten by a request that only looked it up");
    }

    private org.hibernate.stat.EntityStatistics rowStatistics() {
        org.hibernate.stat.Statistics statistics = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class).getStatistics();
        assertTrue(statistics.isStatisticsEnabled(), "hibernate.generate_statistics must be on for this test");
        return statistics.getEntityStatistics(io.mosip.certify.entity.CredentialConfig.class.getName());
    }

    /** PostgreSQL's row version: a new one for every UPDATE of the row, whatever it writes. */
    private long xmin(String credentialConfigKeyId) {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT xmin::text FROM " + SCHEMA
                     + ".credential_config WHERE credential_config_key_id = ?")) {
            ps.setString(1, credentialConfigKeyId);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), credentialConfigKeyId + " is seeded");
                return Long.parseLong(rs.getString(1));
            }
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private List<String> jdbcArray(String column) throws Exception {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT " + column + " FROM " + SCHEMA
                     + ".credential_config WHERE credential_config_key_id = ?")) {
            ps.setString(1, MDOC_ID);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                java.sql.Array array = rs.getArray(1);
                return java.util.Arrays.stream((Object[]) array.getArray()).map(String::valueOf).toList();
            }
        }
    }

    private JsonNode metadata(String path) throws Exception {
        String body = mockMvc.perform(get(path)).andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body);
    }

    private List<String> strings(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return values;
    }

    private static CredentialConfigurationDTO config(String id, String format) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat(format);
        dto.setVcTemplate("dGVzdA==");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("postgres_stable_scope");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(id);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        if ("mso_mdoc".equals(format)) {
            dto.setDocType("org.iso.18013.5.1.mDL");
            dto.setDisplayOrder(List.of("family_name", "birth_date"));
            ClaimsDisplayFieldsConfigDTO claim = new ClaimsDisplayFieldsConfigDTO();
            dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", claim)));
        } else {
            dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
            dto.setCredentialTypes(List.of("VerifiableCredential", id));
            dto.setDisplayOrder(List.of("fullName"));
        }
        return dto;
    }
}
