package io.mosip.certify.offer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The credential offer page served at {@code {servletPath}/offer/}: a browser page that creates a pre-authorized
 * offer on this issuer, shows it as a QR code for a wallet, and can play the wallet itself. Off unless {@code enabled}
 * (the page is bundled either way; without the switch the security chain does not open its path).
 */
@ConfigurationProperties(prefix = OfferPageProperties.PREFIX)
public record OfferPageProperties(@DefaultValue("false") boolean enabled) {

    public static final String PREFIX = "certify.offer-page";
}
