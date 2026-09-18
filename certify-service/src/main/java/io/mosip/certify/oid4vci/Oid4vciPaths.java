package io.mosip.certify.oid4vci;

import jakarta.servlet.http.HttpServletRequest;

/** The new surface lives under {@code {servletPath}/oid4vci}; the adapter, not a URL list, decides what it secures. */
final class Oid4vciPaths {

    static final String PREFIX = "/oid4vci/";

    private Oid4vciPaths() {}

    static final String WELL_KNOWN = PREFIX + ".well-known/";
    static final String NONCE = PREFIX + "nonce";

    /** Every /oid4vci/ request except the public discovery and nonce endpoints carries an access token. */
    static boolean isOid4vci(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.contains(PREFIX) && !uri.contains(WELL_KNOWN) && !uri.endsWith(NONCE);
    }
}
