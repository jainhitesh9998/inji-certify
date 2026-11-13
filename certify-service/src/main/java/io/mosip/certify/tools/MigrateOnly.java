package io.mosip.certify.tools;

import io.mosip.certify.db.FlywayDefaults;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;

/**
 * Runs the Flyway migrations and exits: the entry point for the Helm pre-upgrade Job and for operators
 * who migrate before rolling out a release. Reads the same configuration (config server, profiles) as the
 * service but starts no web server and no other beans.
 *
 * <p>The file data source is excluded so a migration job never reads, validates or holds the demo JSON and its
 * binaries: a broken demo file must not block a migration. The trust-anchor registry (M-06) is excluded for the same
 * reason: it reads and validates IACA certificates and CRLs, refuses to start on a stale CRL, and in dev mode issues
 * a CRL and writes its number next to the keystore, none of which a migration needs. The exclusion is listed in
 * {@code spring.autoconfigure.exclude} rather than on {@code @EnableAutoConfiguration(exclude = ...)}: this class is a
 * {@link SpringBootConfiguration} inside the application's scan base, and an annotation exclusion there applies to every
 * context that scans {@code io.mosip.certify.tools}, which would silently remove the service's own file sources.</p>
 *
 * <pre>java -Dloader.main=io.mosip.certify.tools.MigrateOnly -jar certify-service.jar</pre>
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import({DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class, FlywayDefaults.class})
public class MigrateOnly {

    /** Auto-configurations the migration job does not need; tested against the classes it names. */
    static final String AUTOCONFIGURATION_EXCLUDES =
            "io.mosip.certify.datasource.file.FileDataSourceAutoConfiguration,"
                    + "io.mosip.certify.trust.PkiAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration";

    public static void main(String[] args) {
        ConfigurableApplicationContext context = new SpringApplicationBuilder(MigrateOnly.class)
                .web(WebApplicationType.NONE)
                .bannerMode(Banner.Mode.OFF)
                .properties("spring.flyway.enabled=true", "spring.jpa.hibernate.ddl-auto=none",
                        "spring.autoconfigure.exclude=" + AUTOCONFIGURATION_EXCLUDES)
                .run(args);
        context.close();
    }
}
