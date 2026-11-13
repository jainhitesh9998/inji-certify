package io.mosip.certify.tools;

import io.mosip.certify.db.FlywayDefaults;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runs the Flyway migrations and exits: the entry point for the Helm pre-upgrade Job and for operators
 * who migrate before rolling out a release. Reads the same configuration (config server, profiles) as the
 * service but starts no web server and no other beans.
 *
 * <p>Every auto-configuration that reads, generates or writes key material or loads files is excluded, so a migration
 * job never needs the service's keystores, demo data or trust anchors and never changes them: the file data source (a
 * broken demo file must not block a migration); the trust-anchor registry (M-06: it reads and validates IACA
 * certificates and CRLs, refuses to start on an invalid one, and in dev mode issues a CRL and writes its number next
 * to the keystore); the {@code x509-file} key provider (it opens a PKCS#12 keystore, refuses a missing one and in dev
 * mode generates keys and writes the keystore); and the keymanager key provider with its startup key provisioning
 * ({@code KeymanagerKeyInitializer} creates master and signing keys in {@code key_store}).</p>
 *
 * <p>The exclusion is a {@code spring.autoconfigure.exclude} property rather than
 * {@code @EnableAutoConfiguration(exclude = ...)}: this class is a {@link SpringBootConfiguration} inside the
 * application's scan base, and an annotation exclusion there applies to every context that scans
 * {@code io.mosip.certify.tools}, which would silently remove the service's own file sources and keys. The property is
 * merged with any {@code spring.autoconfigure.exclude} the deployment's configuration sets and put first by a
 * last-running context initializer, after Spring Cloud's bootstrap has added the config-server sources, so a
 * deployment's own list can neither replace nor shorten it (M-13).</p>
 *
 * <pre>java -Dloader.main=io.mosip.certify.tools.MigrateOnly -jar certify-service.jar</pre>
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import({DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class, FlywayDefaults.class})
public class MigrateOnly {

    static final String EXCLUDE_PROPERTY = "spring.autoconfigure.exclude";

    /** Auto-configurations the migration job does not need; tested against the classes it names. */
    static final String AUTOCONFIGURATION_EXCLUDES =
            "io.mosip.certify.datasource.file.FileDataSourceAutoConfiguration,"
                    + "io.mosip.certify.trust.PkiAutoConfiguration,"
                    + "io.mosip.certify.keyprovider.x509file.X509FileAutoConfiguration,"
                    + "io.mosip.certify.keyprovider.keymanager.KeymanagerKeyProviderConfiguration,"
                    + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,"
                    + "org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration";

    /** Name of the property source that carries the job's own settings, ahead of every other source. */
    static final String PROPERTY_SOURCE = "certifyMigrateOnly";

    public static void main(String[] args) {
        ConfigurableApplicationContext context = application().run(args);
        context.close();
    }

    /** The migration application; {@code main} runs it, tests start it against an in-memory database. */
    static SpringApplicationBuilder application() {
        return new SpringApplicationBuilder(MigrateOnly.class)
                .web(WebApplicationType.NONE)
                .bannerMode(Banner.Mode.OFF)
                .initializers(new ForceSettings());
    }

    /** Runs after every other initializer, Spring Cloud's {@code PropertySourceBootstrapConfiguration} included. */
    static final class ForceSettings implements ApplicationContextInitializer<ConfigurableApplicationContext>, Ordered {
        @Override
        public void initialize(ConfigurableApplicationContext context) {
            force(context.getEnvironment());
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }

    /** Puts the job's settings first: Flyway on, no schema generation, and the exclusions merged with the deployment's. */
    static void force(ConfigurableEnvironment environment) {
        Set<String> excludes = new LinkedHashSet<>(List.of(AUTOCONFIGURATION_EXCLUDES.split(",")));
        Binder.get(environment).bind(EXCLUDE_PROPERTY, Bindable.listOf(String.class))
                .ifBound(configured -> configured.stream().map(String::trim).filter(s -> !s.isEmpty()).forEach(excludes::add));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("spring.flyway.enabled", "true");
        properties.put("spring.jpa.hibernate.ddl-auto", "none");
        properties.put(EXCLUDE_PROPERTY, String.join(",", excludes));
        environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE, properties));
    }
}
