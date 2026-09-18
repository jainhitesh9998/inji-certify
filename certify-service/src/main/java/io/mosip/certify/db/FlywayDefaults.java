package io.mosip.certify.db;

import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayConfigurationCustomizer;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Flyway defaults that make an unconfigured deployment behave correctly (docs/design/08-database.md):
 * an existing database is baselined at {@value #BASELINE_VERSION} and left untouched, an empty database gets
 * the schema from the per-module baseline migrations, and later migrations apply in version order.
 * Any {@code spring.flyway.*} property set by the deployment wins over these defaults.
 */
@Slf4j
@Component
public class FlywayDefaults implements FlywayConfigurationCustomizer {

    /** Highest baseline version; every existing database is assumed to be at this level. */
    public static final String BASELINE_VERSION = "1.0.0.003";

    public static final List<String> DEFAULT_LOCATIONS = List.of(
            "classpath:db/migration/core",
            "classpath:db/migration/keymanager",
            "classpath:db/migration/verify",
            "classpath:db/migration/as");

    private final Environment environment;

    public FlywayDefaults(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void customize(FluentConfiguration configuration) {
        if (!environment.containsProperty("spring.flyway.baseline-on-migrate")) {
            configuration.baselineOnMigrate(true);
        }
        if (!environment.containsProperty("spring.flyway.baseline-version")) {
            configuration.baselineVersion(BASELINE_VERSION);
        }
        if (!environment.containsProperty("spring.flyway.baseline-description")) {
            configuration.baselineDescription("schema present before Flyway (inji-certify 1.0.0)");
        }
        if (!environment.containsProperty("spring.flyway.validate-on-migrate")) {
            configuration.validateOnMigrate(true);
        }
        if (!environment.containsProperty("spring.flyway.locations")) {
            configuration.locations(DEFAULT_LOCATIONS.toArray(new String[0]));
        }
        if (!environment.containsProperty("spring.flyway.schemas") && !environment.containsProperty("spring.flyway.default-schema")) {
            String schema = schemaFromUrl(environment.getProperty("spring.datasource.url", ""));
            if (schema != null) {
                configuration.schemas(schema).defaultSchema(schema);
            }
        }
        log.info("Flyway: locations={}, baselineOnMigrate={}, baselineVersion={}, schemas={}",
                List.of(configuration.getLocations()), configuration.isBaselineOnMigrate(),
                configuration.getBaselineVersion(), List.of(configuration.getSchemas()));
    }

    /** The {@code currentSchema} parameter of a PostgreSQL JDBC URL, e.g. {@code ...?currentSchema=certify}. */
    static String schemaFromUrl(String jdbcUrl) {
        int q = jdbcUrl.indexOf('?');
        if (q < 0) {
            return null;
        }
        for (String param : jdbcUrl.substring(q + 1).split("&")) {
            int eq = param.indexOf('=');
            if (eq > 0 && "currentSchema".equals(param.substring(0, eq))) {
                String value = param.substring(eq + 1).trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }
}
