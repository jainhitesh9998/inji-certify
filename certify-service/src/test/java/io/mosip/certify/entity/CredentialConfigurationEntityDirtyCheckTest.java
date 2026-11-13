package io.mosip.certify.entity;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import io.hypersistence.utils.hibernate.type.util.JsonConfiguration;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

/**
 * F-17 review round 2, B1: loading a {@code credential_config} row in a read-write session and flushing must not write
 * it. Every {@code mso_mdoc} row used to be rewritten on every such load, because the snapshot hypersistence-utils took
 * of {@code msoMdocClaims} ({@code Map<String, Map<String, Claims>>}) held {@code LinkedHashMap}s where the entity held
 * {@code Claims}, so the attribute was always dirty ({@link TypedJsonBinaryType} has the details).
 *
 * <p>This is the mapping on its own: Hibernate bootstrapped with just {@link CredentialConfig} on an in-memory H2 with
 * the test schema ({@code src/test/resources/schema.sql}), no Spring, no transaction attributes - so neither a
 * read-only transaction nor a cache can hide a dirty attribute. The PostgreSQL proof through the real services is
 * {@code LegacyMetadataPostgresTest}.
 */
class CredentialConfigurationEntityDirtyCheckTest {

    static final String URL = "jdbc:h2:mem:credential-config-dirty-check;DB_CLOSE_DELAY=-1";

    static SessionFactory sessionFactory;

    @BeforeAll
    static void bootstrap() throws Exception {
        try (Connection connection = DriverManager.getConnection(URL, "sa", ""); Statement statement = connection.createStatement()) {
            statement.execute("RUNSCRIPT FROM 'classpath:schema.sql'");
        }
        StandardServiceRegistry registry = new StandardServiceRegistryBuilder()
                .applySetting("hibernate.connection.url", URL)
                .applySetting("hibernate.connection.username", "sa")
                .applySetting("hibernate.connection.password", "")
                .applySetting("hibernate.dialect", "org.hibernate.dialect.H2Dialect")
                .applySetting("hibernate.hbm2ddl.auto", "none")
                // Spring Boot's column naming (credentialFormat -> credential_format), as the application maps the entity
                .applySetting("hibernate.physical_naming_strategy", "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy")
                .applySetting("hibernate.generate_statistics", "true")
                .applySetting("jakarta.persistence.validation.mode", "none")
                .build();
        sessionFactory = new MetadataSources(registry).addAnnotatedClass(CredentialConfig.class).buildMetadata().buildSessionFactory();
    }

    @AfterAll
    static void close() {
        if (sessionFactory != null) {
            sessionFactory.close();
        }
    }

    @Test
    void loadingAndFlushingAnMdocRowIssuesNoUpdate() {
        persist(mdocRow("dirty-check-mdl"));

        Statistics statistics = sessionFactory.getStatistics();
        statistics.clear();
        try (Session session = sessionFactory.openSession()) {
            session.beginTransaction();
            CredentialConfig loaded = session.get(CredentialConfig.class, "dirty-check-mdl");
            Object claim = loaded.getMsoMdocClaims().get("org.iso.18013.5.1").get("family_name");
            assertInstanceOf(Claims.class, claim, "the entity holds the declared type");
            assertFalse(session.isDirty(), "a row that was only loaded is not dirty (msoMdocClaims was, on every load)");
            session.flush();
            session.getTransaction().commit();
        }
        assertEquals(1, statistics.getEntityLoadCount(), "the row was loaded from the database");
        assertEquals(0, statistics.getEntityUpdateCount(), "a load followed by a flush and a commit writes nothing");
    }

    /** Every JSON attribute of the entity, populated: none of them may be falsely dirty after a load. */
    @Test
    void noJsonAttributeOfALoadedRowIsDirty() {
        CredentialConfig row = mdocRow("dirty-check-all");
        row.setClaims(Map.of("given_name", claims("Given name")));
        row.setSdJwtClaims(Map.of("family_name", claims("Family name")));
        row.setPluginConfigurations(List.of(Map.of("mosip.certify.mock.data-provider.test-one", "valueOne")));
        row.setQrSettings(List.of(Map.of("Full Name", List.of("$.credentialSubject.fullName"))));
        row.setFormatConfig(Map.of("doctype", "org.iso.18013.5.1.mDL"));
        row.setSigningConfig(Map.of("algorithm", "ES256"));
        persist(row);

        Statistics statistics = sessionFactory.getStatistics();
        statistics.clear();
        try (Session session = sessionFactory.openSession()) {
            session.beginTransaction();
            session.get(CredentialConfig.class, "dirty-check-all");
            assertFalse(session.isDirty());
            session.getTransaction().commit();
        }
        assertEquals(0, statistics.getEntityUpdateCount());
    }

    /** A real change is still detected and written: the typed copy did not make the attribute immutable. */
    @Test
    void aChangedClaimIsStillWritten() {
        persist(mdocRow("dirty-check-change"));

        Statistics statistics = sessionFactory.getStatistics();
        statistics.clear();
        try (Session session = sessionFactory.openSession()) {
            session.beginTransaction();
            CredentialConfig loaded = session.get(CredentialConfig.class, "dirty-check-change");
            loaded.getMsoMdocClaims().get("org.iso.18013.5.1").get("family_name").setMandatory(true); // in place
            session.getTransaction().commit();
        }
        assertEquals(1, statistics.getEntityUpdateCount(), "an in-place change of a nested Claims is a change");
        try (Session session = sessionFactory.openSession()) {
            CredentialConfig reread = session.get(CredentialConfig.class, "dirty-check-change");
            assertEquals(true, reread.getMsoMdocClaims().get("org.iso.18013.5.1").get("family_name").isMandatory());
        }
    }

    /**
     * F-17 review round 3, item 3: the second-level cache form. Hibernate disassembles an attribute into the cache and
     * assembles it back through the attribute's mutability plan, which for a {@code @Type} is the user type. The
     * inherited pair went through the same untyped clone as the snapshot, so a cache round trip handed back
     * {@code LinkedHashMap}s that never equal the {@code Claims} written; the typed pair returns an equal, typed value.
     */
    @Test
    void aCacheRoundTripIsTypedAndEqual() {
        org.hibernate.type.descriptor.java.MutabilityPlan<Object> plan = mdocClaimsPlan();
        Map<String, Map<String, Claims>> value = mdocRow("plan-cache").getMsoMdocClaims();
        try (Session session = sessionFactory.openSession()) {
            java.io.Serializable cached = plan.disassemble(value, session);
            Object assembled = plan.assemble(cached, session);
            assertEquals(value, assembled, "a cache round trip returns the value that was cached");
            assertInstanceOf(Claims.class, ((Map<?, ?>) ((Map<?, ?>) assembled).get("org.iso.18013.5.1")).get("family_name"));
            assertNotSame(assembled, plan.assemble(cached, session), "every assembly is a value of its own");
        }
    }

    /**
     * Copies are independent of what they came from, both ways: the load snapshot ({@code deepCopy}) and the cache form
     * ({@code disassemble}/{@code assemble}). Changing a nested {@code Claims} in one never changes the other.
     */
    @Test
    void copiesAndTheirOriginalsNeverShareState() {
        org.hibernate.type.descriptor.java.MutabilityPlan<Object> plan = mdocClaimsPlan();
        try (Session session = sessionFactory.openSession()) {
            Map<String, Map<String, Claims>> original = mdocRow("plan-isolation").getMsoMdocClaims();
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Claims>> copy = (Map<String, Map<String, Claims>>) plan.deepCopy(original);
            assertEquals(original, copy);
            copy.get("org.iso.18013.5.1").get("family_name").setMandatory(true);
            assertFalse(original.get("org.iso.18013.5.1").get("family_name").isMandatory(), "changing the copy changed the original");
            original.get("org.iso.18013.5.1").get("birth_date").setDisplay(List.of(new Claims.Display("Changed", "en")));
            assertEquals("Date of birth", copy.get("org.iso.18013.5.1").get("birth_date").getDisplay().get(0).getName(),
                    "changing the original changed the copy");

            java.io.Serializable cached = plan.disassemble(original, session);
            original.get("org.iso.18013.5.1").get("family_name").setMandatory(true); // after caching
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Claims>> assembled = (Map<String, Map<String, Claims>>) plan.assemble(cached, session);
            assertFalse(assembled.get("org.iso.18013.5.1").get("family_name").isMandatory(), "a change after caching reached the cache");
            assembled.get("org.iso.18013.5.1").get("birth_date").setMandatory(true);
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Claims>> again = (Map<String, Map<String, Claims>>) plan.assemble(cached, session);
            assertFalse(again.get("org.iso.18013.5.1").get("birth_date").isMandatory(), "changing an assembled value changed the cache");
        }
    }

    /** The mutability plan Hibernate built for {@code msoMdocClaims}: what it uses for the load snapshot and the cache. */
    @SuppressWarnings("unchecked")
    private static org.hibernate.type.descriptor.java.MutabilityPlan<Object> mdocClaimsPlan() {
        org.hibernate.persister.entity.EntityPersister persister = sessionFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class)
                .getMappingMetamodel().getEntityDescriptor(CredentialConfig.class);
        return (org.hibernate.type.descriptor.java.MutabilityPlan<Object>)
                persister.findAttributeMapping("msoMdocClaims").getAttributeMetadata().getMutabilityPlan();
    }

    /**
     * The mechanism, held so a future hypersistence-utils that keeps the nested type is noticed (then
     * {@link TypedJsonBinaryType} can go): {@link JsonBinaryType}'s snapshot copy of a map of maps reads the inner values
     * back as {@code LinkedHashMap}, which never equals a {@code Claims}.
     */
    @Test
    void jsonBinaryTypeCopyLosesTheNestedValueType() {
        Map<String, Map<String, Claims>> value = new LinkedHashMap<>();
        value.put("org.iso.18013.5.1", new LinkedHashMap<>(Map.of("family_name", claims("Family name"))));

        Map<?, ?> copy = (Map<?, ?>) JsonConfiguration.INSTANCE.getObjectMapperWrapper().clone(value);

        Object nested = ((Map<?, ?>) copy.get("org.iso.18013.5.1")).get("family_name");
        assertInstanceOf(LinkedHashMap.class, nested, "hypersistence-utils copies the nested Claims as a LinkedHashMap");
        assertNotEquals(value, copy, "so the copy never equals the value, and the attribute is dirty on every load");
    }

    private static void persist(CredentialConfig row) {
        try (Session session = sessionFactory.openSession()) {
            session.beginTransaction();
            session.persist(row);
            session.getTransaction().commit();
        }
    }

    private static CredentialConfig mdocRow(String id) {
        CredentialConfig row = new CredentialConfig();
        row.setConfigId(id);
        row.setCredentialConfigKeyId(id);
        row.setStatus("active");
        row.setCredentialFormat("mso_mdoc");
        row.setDocType("org.iso.18013.5.1.mDL");
        row.setScope("dirty_check_scope");
        row.setSignatureAlgo("ES256");
        MetaDataDisplay display = new MetaDataDisplay();
        display.setName(id);
        display.setLocale("en");
        row.setDisplay(List.of(display));
        row.setOrder(List.of("family_name", "birth_date"));
        row.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        row.setCredentialSigningAlgValuesSupported(List.of("ES256"));
        row.setProofTypesSupported(Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
        Map<String, Map<String, Claims>> mdocClaims = new LinkedHashMap<>();
        Map<String, Claims> namespace = new LinkedHashMap<>();
        namespace.put("family_name", claims("Family name"));
        namespace.put("birth_date", claims("Date of birth"));
        mdocClaims.put("org.iso.18013.5.1", namespace);
        row.setMsoMdocClaims(mdocClaims);
        row.setCreatedTimes(LocalDateTime.now());
        return row;
    }

    private static Claims claims(String name) {
        return new Claims(List.of(new Claims.Display(name, "en")), false);
    }
}
