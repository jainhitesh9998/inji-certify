/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.as.AsProperties;
import io.mosip.certify.as.ClientAttestationValidator;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import io.mosip.certify.dpop.DpopProofValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletPath;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for handling OAuth 2.0 Authorization Server Metadata
 */
@Slf4j
@Service
public class OAuthAuthorizationServerMetadataService {

    /** Certify's identity: the compatibility Credential Issuer Identifier (a legacy key, read through the Environment). */
    static final String IDENTIFIER_PROPERTY = "mosip.certify.identifier";

    /** Certify's identity: the deployment's own base URL (a legacy key, read through the Environment). */
    static final String DOMAIN_URL_PROPERTY = "mosip.certify.domain.url";

    /** RFC 7591 section 2: the token endpoint authenticates a public client with nothing at all. */
    static final String TOKEN_ENDPOINT_AUTH_METHOD_NONE = "none";

    @Autowired
    private ObjectProvider<AsProperties> asProperties;

    @Autowired
    private ObjectProvider<DpopProofValidator> dpopProofValidator;

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

    /** Certify's identity ({@link #IDENTIFIER_PROPERTY}, {@link #DOMAIN_URL_PROPERTY}); absent outside Spring. */
    @Autowired
    private Environment environment;

    /** Where Spring Boot mounts the DispatcherServlet ({@code spring.mvc.servlet.path}); absent outside a web context. */
    @Autowired
    private ObjectProvider<DispatcherServletPath> dispatcherServletPath;

    /** {@code server.servlet.context-path} as Spring Boot bound it; absent outside a web context. */
    @Autowired
    private ObjectProvider<ServerProperties> serverProperties;

    /** One WARN per instance for a token endpoint on Certify's own origin that is not its own token URL. */
    private final AtomicBoolean ownEndpointMissReported = new AtomicBoolean();

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
        DpopProofValidator dpop = dpopProofValidator == null ? null : dpopProofValidator.getIfAvailable();
        if (dpop != null && dpop.getAllowedAlgorithms() != null && !dpop.getAllowedAlgorithms().isEmpty()) {
            metadata.setDpopSigningAlgValuesSupported(dpop.getAllowedAlgorithms()); // RFC 9449 section 5.1
        }
        AsProperties as = asProperties == null ? null : asProperties.getIfAvailable(); // null when built outside Spring (unit tests)
        // Certify's own token endpoint serves the pre-authorized grant whether or not an authorization-code client is
        // registered, so the two features are advertised independently of each other.
        boolean ownTokenEndpoint = as != null && tokenEndpoint != null && tokenEndpoint.endsWith("/oauth/token");
        // The grant filtering below describes this server, so it runs only when the document actually is Certify's own:
        // an exact match against the token URL built from Certify's identity (decided by the project owner, 2026-11-13).
        // The suffix test above cannot tell eSignet (`https://esignet.example/v1/esignet/oauth/token`) or any external AS
        // at `.../oauth/token` from Certify's own endpoint, and such a document must stay exactly as configured. The
        // pre-existing features keep their historical condition on purpose: changing when they appear would change
        // documents existing deployments serve.
        boolean own = as != null && describesOwnTokenEndpoint();
        if (own) {
            advertiseOnlyCompletableGrants(metadata, as);
        }
        // The code-flow endpoints keep their historical `/oauth/token` suffix condition (P3-05): an external AS at that
        // path with clients registered here gets them too, which gap G39 records rather than this change moving it.
        if (ownTokenEndpoint && as.enabled()) {
            String base = tokenEndpoint.substring(0, tokenEndpoint.length() - "/oauth/token".length());
            metadata.setAuthorizationEndpoint(base + "/oauth/authorize");
            metadata.setPushedAuthorizationRequestEndpoint(base + "/oauth/par");
            metadata.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            if (own) {
                metadata.setTokenEndpointAuthMethodsSupported(ownTokenEndpointAuthMethods(as));
            } else if (clientAttestationConfigured(as)) {
                // not Certify's own token URL (F-17's identity rule): the attested method as P3-06 published it, and
                // nothing new - this service cannot know how another server authenticates its clients
                metadata.setTokenEndpointAuthMethodsSupported(List.of(ClientAttestationValidator.AUTH_METHOD));
            }
        }
        // OID4VCI 1.0 section 12.3: a Token Request with a pre-authorized code and no client_id is answered here, so an
        // offer can be followed without interacting with the issuer. Opt-in per deployment
        // (certify.as.pre-authorized-grant.advertise-anonymous-access, default off): an unchanged deployment's document
        // keeps the exact bytes it had, and every 0.14.0 golden stays green. Never advertised once client attestation is
        // required (the token request is authenticated then, so it is not anonymous), nor when the deployment does not
        // list the pre-authorized code grant. Both conditions are historical and kept on purpose so no existing document
        // moves: the `/oauth/token` suffix test (it also matches an external AS at `.../oauth/token`, eSignet included,
        // and a deployment that opted in with such an AS keeps the flag it has always published) and the CONFIGURED
        // grant list, not the effective one (an own deployment that configures only `authorization_code` becomes
        // pre-authorized only above, but does not newly gain this flag).
        if (ownTokenEndpoint && advertiseAnonymousPreAuthorizedGrant(as)) {
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
     * <p>Only called when the document describes Certify's own token endpoint; any other authorization server
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
     * {@link #parseCommaSeparatedValues} keeps its bytes for every other document, which this method does not touch.
     */
    private void advertiseOnlyCompletableGrants(OAuthAuthorizationServerMetadataDTO metadata, AsProperties as) {
        boolean interactiveAuthorization = interactiveAuthorizationEndpoint != null && !interactiveAuthorizationEndpoint.isBlank();
        boolean ownAuthorizationEndpoint = as.enabled();

        List<String> grants = configuredGrantsTrimmed();
        if (!ownAuthorizationEndpoint && !interactiveAuthorization) {
            grants.removeIf(IarConstants.GRANT_TYPE_AUTHORIZATION_CODE::equals);
        }
        if (grants.isEmpty()) {
            grants.add(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        }
        metadata.setGrantTypesSupported(grants);
        if (!grants.contains(IarConstants.GRANT_TYPE_AUTHORIZATION_CODE)) {
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
     * uses this: {@link #parseCommaSeparatedValues} keeps its historical (untrimmed) reading for every other document,
     * whose bytes must not change.
     */
    private List<String> configuredGrantsTrimmed() {
        List<String> grants = new ArrayList<>();
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
     * Whether {@code mosip.certify.oauth.token-endpoint} is the token URL of Certify's own authorization server. Decided
     * by the project owner (2026-11-13): it is exactly Certify's identity - {@code mosip.certify.identifier} or
     * {@code mosip.certify.domain.url}, either a comma-separated list - followed by the context path, the servlet path
     * and {@code /oauth/token}, one trailing slash normalised on each URL. {@code mosip.certify.authorization.url} and
     * {@code mosip.certify.oauth.issuer} are not ownership bases: they name whichever authorization server the deployment
     * uses, so {@code https://idp.example/v1/certify/oauth/token} with {@code authorization.url=https://idp.example} is
     * an external server's document. Anything that is not own is served exactly as configured (pre-F-17 behaviour).
     */
    private boolean describesOwnTokenEndpoint() {
        String described = normaliseEndpoint(tokenEndpoint);
        if (described == null) {
            return false;
        }
        String path = ownPath();
        List<String> identities = identities();
        for (String identity : identities) {
            if (described.equals(identity + path + "/oauth/token")) {
                return true;
            }
        }
        reportOwnEndpointMiss(described, path, identities);
        return false;
    }

    /** {@code mosip.certify.identifier} then {@code mosip.certify.domain.url}, each comma-separated, normalised. */
    private List<String> identities() {
        List<String> identities = new ArrayList<>();
        if (environment != null) {
            identities.addAll(splitUrls(environment.getProperty(IDENTIFIER_PROPERTY)));
            identities.addAll(splitUrls(environment.getProperty(DOMAIN_URL_PROPERTY)));
        }
        return identities;
    }

    /**
     * The URL path Certify's controllers are served under, as Spring Boot mounted them: {@code server.servlet.context-path}
     * ({@code ServerProperties.Servlet#setContextPath} strips it and drops one trailing slash) followed by the
     * DispatcherServlet's prefix ({@link DispatcherServletPath#getPrefix}: a trailing slash is dropped, so
     * {@code spring.mvc.servlet.path=/} is the empty prefix). Empty outside a web context.
     */
    private String ownPath() {
        ServerProperties server = serverProperties == null ? null : serverProperties.getIfAvailable();
        String contextPath = server == null || server.getServlet() == null ? null : server.getServlet().getContextPath();
        String context = contextPath == null ? "" : contextPath.strip();
        if (context.endsWith("/")) {
            context = context.substring(0, context.length() - 1);
        }
        DispatcherServletPath mounted = dispatcherServletPath == null ? null : dispatcherServletPath.getIfAvailable();
        return context + (mounted == null || mounted.getPath() == null ? "" : mounted.getPrefix());
    }

    /** The comma-separated URLs of one property, each normalised; nothing for a blank property. */
    private static List<String> splitUrls(String urls) {
        List<String> result = new ArrayList<>();
        if (urls == null) {
            return result;
        }
        for (String url : urls.split(",")) {
            String normalised = normaliseEndpoint(url);
            if (normalised != null) {
                result.add(normalised);
            }
        }
        return result;
    }

    /**
     * A token endpoint on Certify's own origin (scheme, host and port of one of its identities) that is not its own
     * token URL is most likely Certify's endpoint with a path this service did not expect (a servlet path changed in
     * one place only); the document is then served exactly as configured and the RFC 8414 grant rules do not run. Said
     * once, so the miss is visible without repeating on every metadata request. A token endpoint on another origin is
     * an external authorization server (eSignet) and is not reported.
     */
    private void reportOwnEndpointMiss(String described, String path, List<String> identities) {
        String origin = origin(described);
        if (origin == null) {
            return;
        }
        for (String identity : identities) {
            if (origin.equals(origin(identity)) && ownEndpointMissReported.compareAndSet(false, true)) {
                log.warn("mosip.certify.oauth.token-endpoint {} is on Certify's own origin {} but is not {}{}/oauth/token for "
                                + "any of mosip.certify.identifier or mosip.certify.domain.url, so it is not treated as Certify's "
                                + "own token endpoint: the authorization server metadata is served exactly as configured and the "
                                + "RFC 8414 section 2 grant rules are not applied. If it is Certify's own, make it "
                                + "<identity><context path><servlet path>/oauth/token.",
                        described, origin, identity, path);
                return;
            }
        }
    }

    /** {@code scheme://host[:port]} in lower case, the scheme's default port omitted; {@code null} when not a URL. */
    private static String origin(String url) {
        try {
            URI uri = new URI(url);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            boolean defaultPort = port == -1 || ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
            return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /** A URL without surrounding whitespace and with one trailing slash removed; {@code null} when blank. */
    private static String normaliseEndpoint(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        String trimmed = url.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    /**
     * How Certify's own token endpoint authenticates the clients of its code flow, which is what the document must say:
     * RFC 8414 section 2 reads an omitted {@code token_endpoint_auth_methods_supported} as {@code client_secret_basic},
     * and a client registered under {@code certify.as.clients.<id>} is a public client - redirect URIs and no secret,
     * so there is nothing a Basic header could carry (RFC 7591 section 2, RFC 9126 section 2; F-21 review round 1).
     * {@code none} for those clients; with attesters configured the attested method (draft-ietf-oauth-attestation-based-
     * client-auth), and {@code none} beside it unless {@code certify.as.client-attestation.required} refuses a request
     * without attestation - an unattested public client is accepted then, and the document says so (F-21 review round
     * 2). Only for an own document: another server's methods are not this service's to describe.
     */
    private static List<String> ownTokenEndpointAuthMethods(AsProperties as) {
        if (!clientAttestationConfigured(as)) {
            return List.of(TOKEN_ENDPOINT_AUTH_METHOD_NONE);
        }
        return clientAttestationRequired(as) ? List.of(ClientAttestationValidator.AUTH_METHOD)
                : List.of(ClientAttestationValidator.AUTH_METHOD, TOKEN_ENDPOINT_AUTH_METHOD_NONE);
    }

    /** {@code true} when {@code certify.as.client-attestation.attesters} names at least one attester. */
    private static boolean clientAttestationConfigured(AsProperties as) {
        return as.clientAttestation() != null && as.clientAttestation().attesters() != null
                && !as.clientAttestation().attesters().isEmpty();
    }

    /** {@code true} when {@code certify.as.client-attestation.required} refuses unauthenticated token requests. */
    private static boolean clientAttestationRequired(AsProperties as) {
        return as.clientAttestation() != null && as.clientAttestation().required();
    }

    /**
     * {@code certify.as.pre-authorized-grant.advertise-anonymous-access} is on (default off), client attestation is not
     * required and the pre-authorized code grant is in the configured {@code grant_types_supported}: only then is the
     * anonymous pre-authorized grant real, and only then may the document say so. The configured list, as before F-17,
     * not the effective one: the grant rules must not add this member to a document that did not have it.
     */
    private boolean advertiseAnonymousPreAuthorizedGrant(AsProperties as) {
        if (as.preAuthorizedGrant() == null || !as.preAuthorizedGrant().advertiseAnonymousAccess()) {
            return false;
        }
        if (clientAttestationRequired(as)) {
            return false;
        }
        return parseCommaSeparatedValues(grantTypesSupported)
                .contains(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
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
