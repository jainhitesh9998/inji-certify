package io.mosip.certify.offer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Opens {@code /offer/**} (the static offer page and its script) when {@code certify.offer-page.enabled} is set:
 * a chain of its own, as the adapters declare theirs, instead of an entry in the security URL lists. Same profile as
 * {@code SecurityConfig}, which provides {@code HttpSecurity} outside the {@code test} profile only.
 */
@Configuration
@Profile("!test")
@EnableConfigurationProperties(OfferPageProperties.class)
@ConditionalOnProperty(prefix = OfferPageProperties.PREFIX, name = "enabled", havingValue = "true")
public class OfferPageSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 12)
    public SecurityFilterChain offerPageSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/offer/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
