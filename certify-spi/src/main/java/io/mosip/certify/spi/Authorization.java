package io.mosip.certify.spi;

import java.util.Map;
import java.util.Objects;

/**
 * What the caller proved about itself, protocol-agnostic: the validated token claims for holder-token flows,
 * the client identity for client-credential flows (VC-API), or {@link #NONE} for the CLI.
 *
 * @param scheme    {@code Bearer}, {@code DPoP}, {@code client_credentials}, {@code mtls}, or {@code none}
 * @param claims    validated claims (subject, scope, client_id, authorization_details, cnf, ...)
 * @param tokenHash hash of the presented access token, when there is one
 */
public record Authorization(String scheme, Map<String, Object> claims, String tokenHash) {

    public static final Authorization NONE = new Authorization("none", Map.of(), null);

    public Authorization {
        Objects.requireNonNull(scheme, "scheme");
        claims = claims == null ? Map.of() : Map.copyOf(claims);
    }

    public boolean isPresent() {
        return !"none".equals(scheme);
    }

    public String scope() {
        Object scope = claims.get("scope");
        return scope == null ? "" : scope.toString();
    }

    public String clientId() {
        Object clientId = claims.get("client_id");
        return clientId == null ? null : clientId.toString();
    }
}
