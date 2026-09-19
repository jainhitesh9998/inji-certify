package io.mosip.certify.vcapi;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;
import java.util.Map;

/**
 * The VC-API issuer adapter (W3C CCG VC API, now VCALM, {@code /credentials/issue} and {@code /credentials/status}
 * under {@code /vc-api}). Off unless {@code enabled}; callers are issuer coordinators registered under
 * {@code clients.<id>} and authenticate with HTTP Basic (client id and {@code secret}).
 */
@ConfigurationProperties(prefix = VcApiProperties.PREFIX)
public record VcApiProperties(@DefaultValue("false") boolean enabled, @DefaultValue Map<String, Client> clients) {

    public static final String PREFIX = "certify.protocol.vc-api";

    /**
     * @param secret                   the HTTP Basic password of the client
     * @param credentialConfigurations the configuration ids the client may issue; empty means every supplied-credential configuration
     */
    public record Client(String secret, @DefaultValue List<String> credentialConfigurations) {}
}
