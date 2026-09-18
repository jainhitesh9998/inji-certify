package io.mosip.certify.oid4vci;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Adapter-declared security for {@code /oid4vci/**} (CLAUDE.md rule 9: no new entries in the URL lists): the chain
 * permits the requests and the adapter's token filter decides, so the surface carries its own rules.
 */
@Configuration
@org.springframework.context.annotation.Profile(value = {"!test"}) // same profile as SecurityConfig: no HttpSecurity outside it
public class Oid4vciSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    public SecurityFilterChain oid4vciSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/oid4vci/**", "/t/*/oid4vci/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
