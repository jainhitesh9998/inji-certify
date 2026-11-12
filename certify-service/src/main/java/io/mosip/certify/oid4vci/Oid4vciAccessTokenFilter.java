package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.filter.AccessTokenValidationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * The same bearer/DPoP validation as the compatibility surface, applied to every {@code /oid4vci/} request - plus the
 * audiences that belong to this surface <em>for the request's tenant</em>: an access token addressed to that tenant's
 * issuer identifier or credential endpoint is accepted here without the deployment adding either to
 * {@code mosip.certify.authn.allowed-audiences}. An offer that targets {@code oid4vci} mints its token with exactly its
 * tenant's credential-endpoint audience (PreAuthorizedCodeService), so the wallet can redeem it at
 * {@code /t/{tenant}/oid4vci/credential}. Tenant A's token is not accepted at tenant B's surface, nor at the default
 * one; a token addressed to the compatibility endpoint keeps working wherever the deployment's own list says it does.
 *
 * <p>The tenant is read from the request-scoped {@link AuthorizationContext}, which {@code TenantResolutionFilter}
 * populates before any token filter runs ({@code Order.HIGHEST_PRECEDENCE + 1} against the default order of a
 * {@code @Component} filter). Without a tenant resolver the context answers {@code default}, so a single-tenant
 * deployment sees exactly the one identifier it always had.
 *
 * <p>The resolvers arrive through {@link ObjectProvider}s so a slice that registers this filter without the new
 * surface's beans (a plain {@code @WebMvcTest}) still starts; there the filter simply has no surface audiences.
 */
@Component
@Profile("!local")
public class Oid4vciAccessTokenFilter extends AccessTokenValidationFilter {

    @Autowired
    private ObjectProvider<Oid4vciIssuerResolver> issuers;

    @Autowired
    private ObjectProvider<AuthorizationContext> authorizationContext;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !Oid4vciPaths.isOid4vci(request);
    }

    @Override
    protected List<String> additionalAudiences() {
        Oid4vciIssuerResolver resolver = issuers == null ? null : issuers.getIfAvailable();
        if (resolver == null) {
            return List.of();
        }
        AuthorizationContext context = authorizationContext == null ? null : authorizationContext.getIfAvailable();
        Oid4vciIssuer oid4vci = resolver.forTenant(context == null ? null : context.getTenantId());
        return List.of(oid4vci.identifier(), oid4vci.credentialEndpoint());
    }
}
