package io.mosip.certify.trust;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Opens {@code GET /mdoc/iaca} and its downloads when {@code certify.pki.publication.enabled} is set: a chain of its
 * own, as the offer page and the adapters declare theirs, instead of an entry in the security URL lists (CLAUDE.md
 * rule 9). Read-only: any other method is refused. Same profile as {@code SecurityConfig}, which provides
 * {@code HttpSecurity} outside the {@code test} profile only.
 */
@Configuration
@Profile("!test")
@ConditionalOnProperty(prefix = "certify.pki.publication", name = "enabled", havingValue = "true")
public class IacaPublicationSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 13)
    public SecurityFilterChain iacaPublicationSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/mdoc/iaca", "/mdoc/iaca/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET)).permitAll()
                        .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.HEAD)).permitAll()
                        .anyRequest().denyAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
