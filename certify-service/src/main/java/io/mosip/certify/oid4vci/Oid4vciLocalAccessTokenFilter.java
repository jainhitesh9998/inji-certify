package io.mosip.certify.oid4vci;

import io.mosip.certify.filter.LocalAccessTokenValidationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** The local-profile TestBearer filter, applied to every {@code /oid4vci/} request. */
@Component
@Profile("local")
public class Oid4vciLocalAccessTokenFilter extends LocalAccessTokenValidationFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !Oid4vciPaths.isOid4vci(request);
    }
}
