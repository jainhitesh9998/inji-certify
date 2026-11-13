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
        if (ownTokenEndpoint) {
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
     * <p>Only called for Certify's own token endpoint; an external authorization server (eSignet), whose metadata this
     * service merely repeats, keeps whatever the deployment configured. The rules:
     * <ul>
     *   <li>{@code authorization_code} stays only when a code can be obtained: Certify's own authorization endpoint is
     *       served (a client is registered, {@code certify.as.clients}) or an Interactive Authorization Endpoint is
     *       configured ({@code mosip.certify.oauth.interactive-authorization-endpoint}). With the IAE the code comes from
     *       that endpoint - OpenID4VCI 1.0's presentation during issuance - not from an authorization endpoint, so RFC
     *       8414 section 2's clause is satisfied without {@code authorization_endpoint};</li>
     *   <li>{@code grant_types_supported} is never empty or absent: RFC 8414 section 2 gives an omitted list the default
     *       <code>["authorization_code", "implicit"]</code>, both grant types that use the authorization endpoint, and
     *       the DTO's {@code NON_EMPTY} include would drop an empty one. Certify's own token endpoint always serves the
     *       pre-authorized code grant, so that is what an otherwise empty list becomes;</li>
     *   <li>{@code code_challenge_methods_supported} is published only while the authorization code grant is;</li>
     *   <li>{@code interactive_authorization_endpoint} and {@code require_interactive_authorization_request} are written
     *       together, and only with the endpoint configured: the requirement means nothing without the endpoint.</li>
     * </ul>
     */
    private void advertiseOnlyCompletableGrants(OAuthAuthorizationServerMetadataDTO metadata, io.mosip.certify.as.AsProperties as) {
        boolean interactiveAuthorization = interactiveAuthorizationEndpoint != null && !interactiveAuthorizationEndpoint.isBlank();
        boolean ownAuthorizationEndpoint = as.enabled();

        List<String> grants = new java.util.ArrayList<>(parseCommaSeparatedValues(grantTypesSupported));
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
