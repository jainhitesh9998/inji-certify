package io.mosip.certify.oid4vci;

import jakarta.servlet.http.HttpServletRequest;

/** The new surface lives under {@code {servletPath}/oid4vci}; the adapter, not a URL list, decides what it secures. */
final class Oid4vciPaths {

    static final String PREFIX = "/oid4vci/";

    private Oid4vciPaths() {}

    static boolean isOid4vci(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.contains(PREFIX);
    }
}
