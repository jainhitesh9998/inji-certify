package io.mosip.certify.vcapi;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Adapter-declared security for {@code /vc-api/**} (CLAUDE.md rule 9: no new entries in the URL lists): the chain
 * permits the requests and {@link VcApiClientAuthFilter} decides. Same profile as {@code SecurityConfig}, which
 * provides {@code HttpSecurity} outside the {@code test} profile only.
 */
@Configuration
@Profile("!test")
@ConditionalOnProperty(prefix = VcApiProperties.PREFIX, name = "enabled", havingValue = "true")
public class VcApiSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 11)
    public SecurityFilterChain vcApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/vc-api/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
