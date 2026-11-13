/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * Service for handling OAuth 2.0 Authorization Server Metadata
 */
@Slf4j
@Service
public class OAuthAuthorizationServerMetadataService {

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.as.AsProperties> asProperties;

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.dpop.DpopProofValidator> dpopProofValidator;

    @Value("${mosip.certify.oauth.issuer:}")
    private String issuer;

    @Value("${mosip.certify.oauth.token-endpoint:}")
    private String tokenEndpoint;

    @Value("${mosip.certify.oauth.jwks-uri:}")
    private String jwksUri;

    @Value("${mosip.certify.oauth.grant-types-supported:authorization_code}")
    private String grantTypesSupported;

    @Value("${mosip.certify.oauth.response-types-supported:code}")
    private String responseTypesSupported;

    @Value("${mosip.certify.oauth.code-challenge-methods-supported:S256}")
    private String codeChallengeMethodsSupported;

    @Value("${mosip.certify.oauth.interactive-authorization-endpoint:}")
    private String interactiveAuthorizationEndpoint;

    @Value("${mosip.certify.oauth.require-interactive-authorization-request:true}")
    private boolean requireInteractiveAuthorizationRequest;

    /** The deployment's authorization server (the base `mosip.certify.oauth.token-endpoint` and issuer are built from). */
    @Value("${mosip.certify.authorization.url:}")
    private String authorizationUrl;

    /** The deployment's own base URL, the other base its own token endpoint may be built from. */
    @Value("${mosip.certify.domain.url:}")
    private String domainUrl;

    @Value("${server.servlet.path:}")
    private String servletPath;

    /**
     * Builds and returns OAuth 2.0 Authorization Server Metadata
     * @return OAuthAuthorizationServerMetadataDTO containing the OAuth Authorization Server metadata
     */
    public OAuthAuthorizationServerMetadataDTO getOAuthAuthorizationServerMetadata() {
        log.debug("Building OAuth Authorization Server metadata");

        OAuthAuthorizationServerMetadataDTO metadata = new OAuthAuthorizationServerMetadataDTO();
        
        metadata.setIssuer(issuer);
        metadata.setTokenEndpoint(tokenEndpoint);
        metadata.setJwksUri(jwksUri);
        metadata.setGrantTypesSupported(parseCommaSeparatedValues(grantTypesSupported));
        metadata.setResponseTypesSupported(parseCommaSeparatedValues(responseTypesSupported));
        metadata.setCodeChallengeMethodsSupported(parseCommaSeparatedValues(codeChallengeMethodsSupported));
        metadata.setInteractiveAuthorizationEndpoint(interactiveAuthorizationEndpoint);
        metadata.setRequireInteractiveAuthorizationRequest(requireInteractiveAuthorizationRequest);
        // the authorization code flow is advertised once a client is registered (certify.as.clients); the endpoints
        // hang next to the token endpoint, so an unchanged deployment's document is unchanged
        io.mosip.certify.dpop.DpopProofValidator dpop = dpopProofValidator == null ? null : dpopProofValidator.getIfAvailable();
        if (dpop != null && dpop.getAllowedAlgorithms() != null && !dpop.getAllowedAlgorithms().isEmpty()) {
            metadata.setDpopSigningAlgValuesSupported(dpop.getAllowedAlgorithms()); // RFC 9449 section 5.1
        }
        io.mosip.certify.as.AsProperties as = asProperties == null ? null : asProperties.getIfAvailable(); // null when built outside Spring (unit tests)
        // Certify's own token endpoint serves the pre-authorized grant whether or not an authorization-code client is
        // registered, so the two features are advertised independently of each other.
        boolean ownTokenEndpoint = as != null && tokenEndpoint != null && tokenEndpoint.endsWith("/oauth/token");
        // The grant filtering below describes this server, so it runs only when the document actually is Certify's own:
        // an exact match against the token URL built from the deployment's identity. The suffix test above cannot tell
        // eSignet (`https://esignet.example/v1/esignet/oauth/token`) or any external AS at `.../oauth/token` from
        // Certify's own endpoint, and such a document must stay exactly as configured (F-17 review round 1, M1). The
        // pre-existing features keep their historical condition on purpose: changing when they appear would change
        // documents existing deployments serve.
        if (as != null && describesOwnTokenEndpoint()) {
            advertiseOnlyCompletableGrants(metadata, as);
        }
        if (ownTokenEndpoint && as.enabled()) {
            String base = tokenEndpoint.substring(0, tokenEndpoint.length() - "/oauth/token".length());
            metadata.setAuthorizationEndpoint(base + "/oauth/authorize");
            metadata.setPushedAuthorizationRequestEndpoint(base + "/oauth/par");
            metadata.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            if (as.clientAttestation() != null && as.clientAttestation().attesters() != null && !as.clientAttestation().attesters().isEmpty()) {
                metadata.setTokenEndpointAuthMethodsSupported(java.util.List.of(io.mosip.certify.as.ClientAttestationValidator.AUTH_METHOD));
            }
        }
        // OID4VCI 1.0 section 12.3: a Token Request with a pre-authorized code and no client_id is answered here, so an
        // offer can be followed without interacting with the issuer. Opt-in per deployment
        // (certify.as.pre-authorized-grant.advertise-anonymous-access, default off): an unchanged deployment's document
        // keeps the exact bytes it had, and every 0.14.0 golden stays green. Never advertised once client attestation is
        // required (the token request is authenticated then, so it is not anonymous), nor when the deployment does not
        // list the pre-authorized code grant, nor with an external AS (eSignet), whose own metadata is authoritative.
        if (ownTokenEndpoint && advertiseAnonymousPreAuthorizedGrant(as, metadata.getGrantTypesSupported())) {
            metadata.setPreAuthorizedGrantAnonymousAccessSupported(Boolean.TRUE);
        }

        log.debug("OAuth Authorization Server metadata built successfully for issuer: {}", issuer);
        return metadata;
    }

    /**
     * RFC 8414 section 2: {@code authorization_endpoint} is REQUIRED unless no grant type that uses the authorization
     * endpoint is supported. A document that lists {@code authorization_code} without any way to obtain a code is what
     * that clause forbids, and a wallet that follows the document refuses the issuer (gap G29).
     *
     * <p>Certify's own Interactive Authorization Endpoint is not an OpenID4VCI 1.0 final feature: it implements an
     * earlier revision of the OpenID4VCI 1.1 editor's draft (docs/design/16-iae-audit.md), and 1.0 final has no such
     * endpoint. Keeping {@code authorization_code} when the IAE is configured is therefore the owner-approved
     * compatibility interpretation - a code is obtainable there, so the grant is not advertised without a way to
     * complete it - not strict RFC 8414 conformance: a strict wallet that requires {@code authorization_endpoint}
     * whenever the grant is listed still refuses this document (Talao rejects it). G29 records that remaining gap.
     *
     * <p>Only called when the document describes Certify's own token endpoint; an external authorization server
     * (eSignet), whose metadata this service merely repeats, keeps whatever the deployment configured. The rules:
     * <ul>
     *   <li>{@code authorization_code} stays only when a code can be obtained: Certify's own authorization endpoint is
     *       served (a client is registered, {@code certify.as.clients}) or the IAE is configured
     *       ({@code mosip.certify.oauth.interactive-authorization-endpoint});</li>
     *   <li>{@code grant_types_supported} is never empty or absent: RFC 8414 section 2 gives an omitted list the default
     *       <code>["authorization_code", "implicit"]</code>, both grant types that use the authorization endpoint, and
     *       the DTO's {@code NON_EMPTY} include would drop an empty one. Certify's own token endpoint always serves the
     *       pre-authorized code grant, so that is what an otherwise empty list becomes;</li>
     *   <li>{@code code_challenge_methods_supported} is published only while the authorization code grant is;</li>
     *   <li>{@code interactive_authorization_endpoint} and {@code require_interactive_authorization_request} are written
     *       together, and only with the endpoint configured: the requirement means nothing without the endpoint.</li>
     * </ul>
     *
     * <p>The configured list is trimmed and blank entries are dropped here. The historical parser in
     * {@link #parseCommaSeparatedValues} keeps its bytes for the external-AS path, which this method does not touch.
     */
    private void advertiseOnlyCompletableGrants(OAuthAuthorizationServerMetadataDTO metadata, io.mosip.certify.as.AsProperties as) {
        boolean interactiveAuthorization = interactiveAuthorizationEndpoint != null && !interactiveAuthorizationEndpoint.isBlank();
        boolean ownAuthorizationEndpoint = as.enabled();

        List<String> grants = configuredGrantsTrimmed();
        if (!ownAuthorizationEndpoint && !interactiveAuthorization) {
            grants.removeIf(io.mosip.certify.core.constants.IarConstants.GRANT_TYPE_AUTHORIZATION_CODE::equals);
        }
        if (grants.isEmpty()) {
            grants.add(io.mosip.certify.core.constants.Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        }
        metadata.setGrantTypesSupported(grants);
        if (!grants.contains(io.mosip.certify.core.constants.IarConstants.GRANT_TYPE_AUTHORIZATION_CODE)) {
            metadata.setCodeChallengeMethodsSupported(null);
        }
        if (interactiveAuthorization) {
            metadata.setInteractiveAuthorizationEndpoint(interactiveAuthorizationEndpoint);
            metadata.setRequireInteractiveAuthorizationRequest(requireInteractiveAuthorizationRequest);
        } else {
            metadata.setInteractiveAuthorizationEndpoint(null);
            metadata.setRequireInteractiveAuthorizationRequest(null);
        }
    }

    /**
     * {@code mosip.certify.oauth.grant-types-supported} trimmed, blank entries dropped. Only the own-endpoint filtering
     * uses this: {@link #parseCommaSeparatedValues} keeps its historical (untrimmed) reading for the external-AS
     * document, whose bytes must not change.
     */
    private List<String> configuredGrantsTrimmed() {
        List<String> grants = new java.util.ArrayList<>();
        if (grantTypesSupported == null) {
            return grants;
        }
        for (String grant : grantTypesSupported.split(",")) {
            if (!grant.isBlank()) {
                grants.add(grant.trim());
            }
        }
        return grants;
    }

    /**
     * Whether {@code mosip.certify.oauth.token-endpoint} is the token URL of Certify's own authorization server: the
     * configured value equals {@code <base><server.servlet.path>/oauth/token} for one of the deployment's own bases
     * ({@code mosip.certify.authorization.url}, comma-separated as the metadata builder reads it, and
     * {@code mosip.certify.domain.url}), compared exactly after normalising one trailing slash. A suffix test would
     * mistake an external authorization server's {@code .../oauth/token} (eSignet's
     * {@code https://esignet.example/v1/esignet/oauth/token}) for Certify's own, and the grant rules must never rewrite
     * an external server's document (F-17 review round 1, M1).
     */
    private boolean describesOwnTokenEndpoint() {
        String described = normaliseEndpoint(tokenEndpoint);
        if (described == null) {
            return false;
        }
        String path = servletPath == null ? "" : servletPath;
        for (String bases : new String[]{authorizationUrl, domainUrl}) {
            if (bases == null) {
                continue;
            }
            for (String base : bases.split(",")) {
                String own = normaliseEndpoint(base.trim());
                if (own != null && described.equals(own + path + "/oauth/token")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** A URL without surrounding whitespace and with one trailing slash removed; {@code null} when blank. */
    private static String normaliseEndpoint(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        String trimmed = url.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    /** {@code true} when {@code certify.as.client-attestation.required} refuses unauthenticated token requests. */
    private static boolean clientAttestationRequired(io.mosip.certify.as.AsProperties as) {
        return as.clientAttestation() != null && as.clientAttestation().required();
    }

    /**
     * {@code certify.as.pre-authorized-grant.advertise-anonymous-access} is on (default off), client attestation is not
     * required and the effective {@code grant_types_supported} lists the pre-authorized code grant: only then is the
     * anonymous pre-authorized grant real, and only then may the document say so. The effective list is used rather than
     * the configured string, so a grant this service added to keep the document completable is advertised the same way.
     */
    private boolean advertiseAnonymousPreAuthorizedGrant(io.mosip.certify.as.AsProperties as, List<String> effectiveGrantTypes) {
        if (as.preAuthorizedGrant() == null || !as.preAuthorizedGrant().advertiseAnonymousAccess()) {
            return false;
        }
        if (clientAttestationRequired(as)) {
            return false;
        }
        return effectiveGrantTypes != null
                && effectiveGrantTypes.contains(io.mosip.certify.core.constants.Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
    }

    /**
     * Helper method to parse comma-separated values into a list
     * @param commaSeparatedValues the comma-separated string
     * @return List of string values
     */
    private List<String> parseCommaSeparatedValues(String commaSeparatedValues) {
        if (commaSeparatedValues == null || commaSeparatedValues.trim().isEmpty()) {
            return Arrays.asList();
        }
        return Arrays.asList(commaSeparatedValues.split(","));
    }
}
