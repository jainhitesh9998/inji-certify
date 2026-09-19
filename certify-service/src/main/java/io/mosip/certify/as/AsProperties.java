package io.mosip.certify.as;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Certify's own authorization server for the authorization code flow (docs/design/17-conformance-gaps.md, item 1).
 * The flow is on once a client is registered under {@code certify.as.clients.<client-id>.redirect-uris}; the subject
 * of an authorization comes from {@code certify.as.authorization.subject-mode}: {@code none} refuses every request
 * (the default), {@code fixed} approves every request for {@code fixed-subject} without user interaction, which is
 * what a conformance run or a demo needs and what a production deployment must not enable.
 */
@ConfigurationProperties(prefix = "certify.as")
public record AsProperties(@DefaultValue Map<String, Client> clients, @DefaultValue Authorization authorization, @DefaultValue Par par,
                           @DefaultValue ClientAttestation clientAttestation) {

    public static final String SUBJECT_MODE_NONE = "none";
    public static final String SUBJECT_MODE_FIXED = "fixed";

    public record Client(@DefaultValue List<String> redirectUris) {}

    public record Authorization(@DefaultValue("none") String subjectMode, String fixedSubject) {}

    /** How long a pushed authorization request may be used ({@code expires_in} of the PAR response). */
    public record Par(@DefaultValue("PT90S") Duration expiresIn) {}

    /**
     * Attestation-based client authentication: {@code attesters.<id>.jwks} holds an attester's JWK Set (JSON);
     * {@code required=true} refuses unauthenticated calls to the OAuth endpoints, as HAIP demands.
     */
    public record ClientAttestation(@DefaultValue("false") boolean required, @DefaultValue Map<String, Attester> attesters,
                                    @DefaultValue("PT60S") Duration clockSkew, @DefaultValue("PT5M") Duration popMaxAge) {}

    public record Attester(String jwks) {}

    public Client client(String clientId) {
        return clients == null || clientId == null ? null : clients.get(clientId);
    }

    public boolean enabled() {
        return clients != null && !clients.isEmpty();
    }
}
