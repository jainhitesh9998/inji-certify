package io.mosip.certify.tools;

import io.mosip.certify.datasource.file.FileDataSourceAutoConfiguration;
import io.mosip.certify.keyprovider.keymanager.KeymanagerKeyInitializer;
import io.mosip.certify.keyprovider.keymanager.KeymanagerKeyProviderConfiguration;
import io.mosip.certify.keyprovider.x509file.X509FileAutoConfiguration;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.trust.PkiAutoConfiguration;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The migration job must not read or validate demo files, trust anchors or key material (M-10 review, M-13). */
class MigrateOnlyTest {

    @Test
    void theMigrationJobExcludesTheFileDataSource() {
        assertTrue(MigrateOnly.AUTOCONFIGURATION_EXCLUDES.contains(FileDataSourceAutoConfiguration.class.getName()),
                "a broken demo file must not block a migration");
    }

    @Test
    void theMigrationJobExcludesTheTrustAnchorRegistry() {
        // it reads IACAs and CRLs, refuses a stale CRL and writes dev-mode CRL numbers: nothing a migration needs (M-06)
        assertTrue(MigrateOnly.AUTOCONFIGURATION_EXCLUDES.contains(PkiAutoConfiguration.class.getName()),
                "a stale CRL or a broken trust anchor must not block a migration");
    }

    @Test
    void theMigrationJobExcludesEveryKeyProvider() {
        // x509-file opens (and in dev mode writes) a keystore; keymanager's initializer creates keys in key_store (M-13)
        assertTrue(MigrateOnly.AUTOCONFIGURATION_EXCLUDES.contains(X509FileAutoConfiguration.class.getName()));
        assertTrue(MigrateOnly.AUTOCONFIGURATION_EXCLUDES.contains(KeymanagerKeyProviderConfiguration.class.getName()));
    }

    @Test
    void theExclusionIsAPropertyNotAnAnnotationOnTheScannedConfigurationClass() {
        // MigrateOnly is a @SpringBootConfiguration under io.mosip.certify: an @EnableAutoConfiguration(exclude) here
        // would remove the file data source from every context that scans it, the service included.
        EnableAutoConfiguration enable = MigrateOnly.class.getAnnotation(EnableAutoConfiguration.class);
        assertNotNull(enable);
        assertEquals(0, enable.exclude().length);
        assertEquals(0, enable.excludeName().length);
    }

    @Test
    void theMigrationContextStartsWithAnMdlProfileWhoseKeystoreIsMissingAndRunsNoProvider(@TempDir Path dir) {
        Path keystore = dir.resolve("missing").resolve("mdl.p12");
        // the test profile also sets spring.autoconfigure.exclude and spring.flyway.enabled=false, as a deployment's
        // configuration may: the job's settings must win over both
        try (ConfigurableApplicationContext context = MigrateOnly.application().run(
                "--spring.cloud.config.enabled=false",
                "--spring.datasource.url=jdbc:h2:mem:migrate_only_" + System.nanoTime() + ";DB_CLOSE_DELAY=-1",
                "--spring.sql.init.mode=never",
                "--spring.flyway.locations=classpath:db/migrate-only-probe",
                "--spring.flyway.baseline-on-migrate=false",
                "--mosip.certify.plugin-mode=DataProvider",
                "--certify.keyprovider.x509-file.enabled=true",
                "--certify.keyprovider.x509-file.dev-mode=false",
                "--certify.keyprovider.x509-file.path=" + keystore,
                "--certify.keyprovider.x509-file.password=changeit",
                "--certify.keyprovider.x509-file.keys[0].alias=mdl-dsc",
                "--certify.keyprovider.x509-file.keys[0].algorithm=ES256",
                "--certify.keyprovider.x509-file.keys[0].profile=mdoc-dsc",
                "--certify.datasource.file.sources.mdldemo.path=" + dir.resolve("missing.json"))) {

            assertEquals(0, context.getBeansOfType(KeyProvider.class).size(), "no key provider is created");
            assertEquals(0, context.getBeansOfType(KeymanagerKeyInitializer.class).size(), "no key is provisioned");
            assertEquals(0, context.getBeansOfType(TrustAnchorRegistry.class).size(), "no trust anchor is read");
            assertFalse(Files.exists(keystore.getParent()), "nothing is written next to the keystore");

            List<String> excludes = List.of(context.getEnvironment().getProperty(MigrateOnly.EXCLUDE_PROPERTY, String[].class));
            assertTrue(excludes.contains(X509FileAutoConfiguration.class.getName()));
            assertTrue(excludes.contains(SecurityAutoConfiguration.class.getName()), "the deployment's own exclusions are kept");

            assertEquals(1, context.getBeansOfType(Flyway.class).size(), "Flyway runs although the profile disables it");
            Integer probe = new JdbcTemplate(context.getBean(DataSource.class))
                    .queryForObject("SELECT COUNT(*) FROM migrate_only_probe", Integer.class);
            assertEquals(0, probe, "the probe migration was applied");
        }
    }
}
