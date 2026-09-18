package io.mosip.certify.authz;

import io.mosip.certify.core.dto.AuthorizationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.web.context.WebApplicationContext;

/** One {@link AuthorizationContext} per HTTP request, injected through a scoped proxy. */
@Configuration
public class AuthorizationContextConfig {

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AuthorizationContext authorizationContext() {
        return new AuthorizationContext();
    }
}
