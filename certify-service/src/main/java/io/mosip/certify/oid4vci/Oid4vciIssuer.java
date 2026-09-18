package io.mosip.certify.oid4vci;

/**
 * The new surface's Credential Issuer Identifier: {@code mosip.certify.identifier} plus {@code /oid4vci} unless
 * {@code certify.oid4vci.issuer-identifier} names it. Metadata, endpoints and proof audiences derive from it.
 */
public record Oid4vciIssuer(String identifier) {

    public static final String SUFFIX = "/oid4vci";

    public static Oid4vciIssuer derive(String legacyIdentifier, String configured) {
        if (configured != null && !configured.isBlank()) {
            return new Oid4vciIssuer(configured.replaceAll("/+$", ""));
        }
        return new Oid4vciIssuer(legacyIdentifier.replaceAll("/+$", "") + SUFFIX);
    }

    public String credentialEndpoint() {
        return identifier + "/credential";
    }

    public String nonceEndpoint() {
        return identifier + "/nonce";
    }
}
