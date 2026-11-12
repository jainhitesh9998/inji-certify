package io.mosip.certify.oid4vci;

import io.mosip.certify.core.exception.InvalidRequestException;

/**
 * The surface a pre-authorized credential offer targets (docs/design/20-mdl-issuer.md, decision D5). The offer's
 * {@code credential_issuer} and the audience of the access token it yields are that surface's identifier, so a wallet
 * that follows the offer lands on the endpoint the issuer document named.
 */
public enum OfferSurface {

    /** Today's paths: {@code credential_issuer} is {@code mosip.certify.identifier}, credentials come from {@code /issuance/credential}. */
    LEGACY("legacy"),

    /** The OpenID4VCI 1.0 surface: {@code credential_issuer} is the {@code /oid4vci} identifier, credentials from {@code /oid4vci/credential}. */
    OID4VCI("oid4vci");

    private final String wireName;

    OfferSurface(String wireName) {
        this.wireName = wireName;
    }

    /** The value the request and {@code certify.protocol.oid4vci-v1.offers.default-issuer} carry. */
    public String wireName() {
        return wireName;
    }

    /**
     * @param value the request's {@code issuer} or the configured default; {@code null} or blank means {@link #LEGACY}
     * @throws InvalidRequestException for a value that is neither surface, before anything is cached or offered
     */
    public static OfferSurface from(String value) {
        if (value == null || value.isBlank()) {
            return LEGACY;
        }
        for (OfferSurface surface : values()) {
            if (surface.wireName.equalsIgnoreCase(value.trim())) {
                return surface;
            }
        }
        throw new InvalidRequestException("invalid_issuer");
    }
}
