package io.mosip.certify.tenancy;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.TenantResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Resolves the tenant of every request once, before the token filters, into the request-scoped
 * {@link AuthorizationContext}; present only when tenancy is enabled, so a single-tenant deployment runs no extra filter.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
@ConditionalOnProperty(prefix = TenancyProperties.PREFIX, name = "enabled", havingValue = "true")
public class TenantResolutionFilter extends OncePerRequestFilter {

    public static final String ATTRIBUTE_PATH = "path";

    private final TenantResolver resolver;
    private final AuthorizationContext authorizationContext;

    public TenantResolutionFilter(TenantResolver resolver, AuthorizationContext authorizationContext) {
        this.resolver = resolver;
        this.authorizationContext = authorizationContext;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        Map<String, Object> attributes = new HashMap<>();
        String host = request.getHeader("Host");
        attributes.put(HostTenantResolver.ATTRIBUTE_HOST, host != null ? host : request.getServerName());
        attributes.put(ATTRIBUTE_PATH, request.getRequestURI());
        TenantContext tenant = resolver.resolve(attributes);
        authorizationContext.setTenantId(tenant == null ? TenantContext.DEFAULT_TENANT_ID : tenant.tenantId());
        chain.doFilter(request, response);
    }
}
