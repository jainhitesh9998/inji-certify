package io.mosip.certify.oid4vci;

/**
 * The new surface's Credential Issuer Identifier: {@code mosip.certify.identifier} plus {@code /oid4vci} unless
 * {@code certify.oid4vci.issuer-identifier} names it. Metadata, endpoints and proof audiences derive from it.
 */
public record Oid4vciIssuer(String identifier) {

    public static final String SUFFIX = "/oid4vci";

    public static Oid4vciIssuer derive(String legacyIdentifier, String configured) {
        return derive(legacyIdentifier, null, configured);
    }

    /**
     * {@code {domain}{servletPath}/oid4vci} (docs/design/09-api-compatibility.md): deployments set
     * {@code mosip.certify.identifier} to the bare domain and append {@code server.servlet.path} to every endpoint,
     * so the servlet path is added here unless the identifier already ends with it.
     */
    public static Oid4vciIssuer derive(String legacyIdentifier, String servletPath, String configured) {
        if (configured != null && !configured.isBlank()) {
            return new Oid4vciIssuer(configured.replaceAll("/+$", ""));
        }
        String base = legacyIdentifier.replaceAll("/+$", "");
        String path = servletPath == null ? "" : servletPath.trim().replaceAll("/+$", "");
        if (!path.isEmpty() && !path.equals("/") && !base.endsWith(path)) {
            base = base + (path.startsWith("/") ? path : "/" + path);
        }
        return new Oid4vciIssuer(base + SUFFIX);
    }

    public String credentialEndpoint() {
        return identifier + "/credential";
    }

    public String nonceEndpoint() {
        return identifier + "/nonce";
    }

    public String notificationEndpoint() {
        return identifier + "/notification";
    }
}
