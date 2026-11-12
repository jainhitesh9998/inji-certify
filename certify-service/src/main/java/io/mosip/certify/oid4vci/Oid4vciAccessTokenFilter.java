package io.mosip.certify.oid4vci;

import io.mosip.certify.filter.AccessTokenValidationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * The same bearer/DPoP validation as the compatibility surface, applied to every {@code /oid4vci/} request - plus the
 * audiences that belong to this surface: an access token addressed to this issuer identifier or to this surface's
 * credential endpoint is accepted here without the deployment adding either to
 * {@code mosip.certify.authn.allowed-audiences}. An offer that targets {@code oid4vci} mints its token with exactly
 * that credential-endpoint audience (PreAuthorizedCodeService), so the wallet can redeem it at
 * {@code /oid4vci/credential}. Tokens addressed to the compatibility endpoint keep working: the deployment's own list
 * still applies.
 *
 * <p>The issuer identifier arrives through an {@link ObjectProvider} so a slice that registers this filter without the
 * new surface's beans (a plain {@code @WebMvcTest}) still starts; there the filter simply has no surface audiences.
 */
@Component
@Profile("!local")
public class Oid4vciAccessTokenFilter extends AccessTokenValidationFilter {

    @Autowired
    private ObjectProvider<Oid4vciIssuer> issuer;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !Oid4vciPaths.isOid4vci(request);
    }

    @Override
    protected List<String> additionalAudiences() {
        Oid4vciIssuer oid4vci = issuer == null ? null : issuer.getIfAvailable();
        return oid4vci == null ? List.of() : List.of(oid4vci.identifier(), oid4vci.credentialEndpoint());
    }
}
