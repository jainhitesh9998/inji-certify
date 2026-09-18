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
 * <pre>java -Dloader.main=io.mosip.certify.tools.MigrateOnly -jar certify-service.jar</pre>
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import({DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class, FlywayDefaults.class})
public class MigrateOnly {

    public static void main(String[] args) {
        ConfigurableApplicationContext context = new SpringApplicationBuilder(MigrateOnly.class)
                .web(WebApplicationType.NONE)
                .bannerMode(Banner.Mode.OFF)
                .properties("spring.flyway.enabled=true", "spring.jpa.hibernate.ddl-auto=none",
                        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration")
                .run(args);
        context.close();
    }
}
