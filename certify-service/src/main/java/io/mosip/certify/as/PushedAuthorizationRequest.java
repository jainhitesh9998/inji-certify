package io.mosip.certify.as;

import java.io.Serializable;

/** A pushed authorization request (RFC 9126) between {@code POST /oauth/par} and {@code GET /oauth/authorize}. */
public record PushedAuthorizationRequest(String id, String clientId, String redirectUri, String scope, String authorizationDetails,
                                         String codeChallenge, String codeChallengeMethod, String state, String issuerState,
                                         long expiresAtEpochSeconds) implements Serializable {

    public static final String URN_PREFIX = "urn:ietf:params:oauth:request_uri:";

    public String requestUri() {
        return URN_PREFIX + id;
    }
}
