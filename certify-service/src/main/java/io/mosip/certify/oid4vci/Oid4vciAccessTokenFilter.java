package io.mosip.certify.oid4vci;

import io.mosip.certify.filter.AccessTokenValidationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** The same bearer/DPoP validation as the compatibility surface, applied to every {@code /oid4vci/} request. */
@Component
@Profile("!local")
public class Oid4vciAccessTokenFilter extends AccessTokenValidationFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !Oid4vciPaths.isOid4vci(request);
    }
}
