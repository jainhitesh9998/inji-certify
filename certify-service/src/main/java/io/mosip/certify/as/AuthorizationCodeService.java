package io.mosip.certify.as;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IarSessionRepository;
import io.mosip.certify.services.OAuthAuthorizationServerMetadataService;
import io.mosip.certify.services.VCICacheService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The authorization code flow of Certify's own authorization server (RFC 6749, RFC 9126 PAR, RFC 7636 PKCE, OpenID4VCI
 * 1.0 section 5): a registered client pushes its request, the authorization endpoint establishes the subject
 * ({@code certify.as.authorization.subject-mode}) and redirects with a single-use code that the existing token endpoint
 * exchanges (the code, PKCE challenge, scope and subject live in {@code iar_session} as the presentation-during-issuance
 * flow stores them, so {@code POST /oauth/token} needs no change).
 */
@Slf4j
@Service
public class AuthorizationCodeService {

    /** The token endpoint recognises codes by this prefix (IarServiceImpl). */
    static final String CODE_PREFIX = "iar_auth_";
    static final String CODE_CHALLENGE_METHOD = "S256";
    static final String RESPONSE_TYPE_CODE = "code";
    static final String AUTHORIZATION_DETAILS_TYPE = "openid_credential";
    static final int CODE_BYTES = 32;

    private final AsProperties properties;
    private final VCICacheService cache;
    private final IarSessionRepository sessions;
    private final CredentialConfigRepository configurations;
    private final OAuthAuthorizationServerMetadataService metadata;
    private final SecureRandom random = new SecureRandom();

    public AuthorizationCodeService(AsProperties properties, VCICacheService cache, IarSessionRepository sessions,
                                    CredentialConfigRepository configurations, OAuthAuthorizationServerMetadataService metadata) {
        this.properties = properties;
        this.cache = cache;
        this.sessions = sessions;
        this.configurations = configurations;
        this.metadata = metadata;
    }

    /** {@code POST /oauth/par}: validates and stores the request, answers the {@code request_uri} and its lifetime. */
    public PushedAuthorizationRequest push(Map<String, String> params) {
        if (!properties.enabled()) {
            throw new AsException(404, "invalid_request", "No client is registered for the authorization code flow");
        }
        if (params.containsKey("request_uri")) {
            throw new AsException(400, "invalid_request", "request_uri is not allowed in a pushed authorization request");
        }
        String clientId = params.get("client_id");
        AsProperties.Client client = properties.client(clientId);
        if (client == null) {
            throw new AsException(401, "invalid_client", "Unknown client_id");
        }
        if (!RESPONSE_TYPE_CODE.equals(params.get("response_type"))) {
            throw new AsException(400, "unsupported_response_type", "response_type must be code");
        }
        String redirectUri = params.get("redirect_uri");
        if (redirectUri == null || client.redirectUris() == null || !client.redirectUris().contains(redirectUri)) {
            throw new AsException(400, "invalid_request", "redirect_uri is not registered for this client");
        }
        String codeChallenge = params.get("code_challenge");
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new AsException(400, "invalid_request", "code_challenge is required");
        }
        if (!CODE_CHALLENGE_METHOD.equals(params.get("code_challenge_method"))) {
            throw new AsException(400, "invalid_request", "code_challenge_method must be S256");
        }
        String scope = blankToNull(params.get("scope"));
        String authorizationDetails = blankToNull(params.get("authorization_details"));
        if (scope == null && authorizationDetails == null) {
            throw new AsException(400, "invalid_request", "scope or authorization_details is required");
        }
        String effectiveScope = effectiveScope(scope, authorizationDetails);
        String id = token(24);
        long expiresAt = Instant.now().plus(properties.par().expiresIn()).getEpochSecond();
        PushedAuthorizationRequest request = new PushedAuthorizationRequest(id, clientId, redirectUri, effectiveScope, authorizationDetails,
                codeChallenge, CODE_CHALLENGE_METHOD, blankToNull(params.get("state")), blankToNull(params.get("issuer_state")), expiresAt);
        cache.setPushedAuthorizationRequest(id, request);
        log.info("Pushed authorization request {} for client {}", id, clientId);
        return request;
    }

    /**
     * {@code GET /oauth/authorize}: resolves the pushed request (single use), establishes the subject and answers the
     * redirect URL carrying the code (or the OAuth error) plus {@code state} and {@code iss} (RFC 9207).
     */
    public String authorize(String clientId, String requestUri) {
        if (!properties.enabled()) {
            throw new AsException(404, "invalid_request", "No client is registered for the authorization code flow");
        }
        if (requestUri == null || !requestUri.startsWith(PushedAuthorizationRequest.URN_PREFIX)) {
            throw new AsException(400, "invalid_request", "A pushed request_uri is required (require_pushed_authorization_requests)");
        }
        String id = requestUri.substring(PushedAuthorizationRequest.URN_PREFIX.length());
        PushedAuthorizationRequest request = cache.getPushedAuthorizationRequest(id);
        if (request == null || !request.clientId().equals(clientId)) {
            throw new AsException(400, "invalid_request", "Unknown or expired request_uri");
        }
        cache.evictPushedAuthorizationRequest(id); // a request_uri is used once (RFC 9126 section 2.2)
        if (request.expiresAtEpochSeconds() < Instant.now().getEpochSecond()) {
            throw new AsException(400, "invalid_request", "request_uri has expired");
        }
        String issuer = metadata.getOAuthAuthorizationServerMetadata().getIssuer();
        String subject = subject();
        if (subject == null) {
            return redirect(request, Map.of("error", "access_denied", "error_description", "No subject could be established for this request"), issuer);
        }
        String code = CODE_PREFIX + token(CODE_BYTES);
        LocalDateTime now = LocalDateTime.now();
        IarSession session = new IarSession();
        session.setAuthSession("authz-" + token(24));
        session.setTransactionId("authz-" + request.id());
        session.setClientId(request.clientId());
        session.setScope(request.scope());
        session.setCodeChallenge(request.codeChallenge());
        session.setCodeChallengeMethod(request.codeChallengeMethod());
        session.setAuthorizationCode(code);
        session.setCodeIssuedAt(now);
        session.setIsCodeUsed(false);
        session.setCreatedDtimes(now);
        session.setExpiresAt(now.plusMinutes(10));
        session.setIdentityData(subject);
        sessions.save(session);
        log.info("Authorization code issued to client {} for subject mode {}", request.clientId(), properties.authorization().subjectMode());
        return redirect(request, Map.of("code", code), issuer);
    }

    private String subject() {
        AsProperties.Authorization authorization = properties.authorization();
        if (AsProperties.SUBJECT_MODE_FIXED.equalsIgnoreCase(authorization.subjectMode()) && blankToNull(authorization.fixedSubject()) != null) {
            return authorization.fixedSubject().trim();
        }
        return null;
    }

    /** The scope the token carries: the requested scopes (each must be a configuration's scope) or the scope of the configurations named in authorization_details. */
    private String effectiveScope(String scope, String authorizationDetails) {
        Map<String, String> scopeByConfiguration = configurations.findAll().stream()
                .filter(c -> c.getStatus() == null || Constants.ACTIVE.equalsIgnoreCase(c.getStatus()))
                .filter(c -> c.getScope() != null)
                .collect(Collectors.toMap(c -> c.getCredentialConfigKeyId(), c -> c.getScope(), (a, b) -> a));
        Set<String> knownScopes = Set.copyOf(scopeByConfiguration.values());
        if (scope != null) {
            List<String> requested = Arrays.stream(scope.trim().split("\\s+")).toList();
            for (String s : requested) {
                if (!knownScopes.contains(s)) {
                    throw new AsException(400, "invalid_scope", "Unknown scope " + s);
                }
            }
            return String.join(" ", requested);
        }
        List<String> ids = AuthorizationDetails.credentialConfigurationIds(authorizationDetails);
        if (ids.isEmpty()) {
            throw new AsException(400, "invalid_request", "authorization_details must name openid_credential entries with credential_configuration_id");
        }
        return ids.stream().map(id -> Optional.ofNullable(scopeByConfiguration.get(id))
                        .orElseThrow(() -> new AsException(400, "invalid_request", "Unknown credential_configuration_id " + id)))
                .distinct().collect(Collectors.joining(" "));
    }

    private String redirect(PushedAuthorizationRequest request, Map<String, String> parameters, String issuer) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(request.redirectUri());
        parameters.forEach(builder::queryParam);
        if (request.state() != null) {
            builder.queryParam("state", request.state());
        }
        if (issuer != null && !issuer.isBlank()) {
            builder.queryParam("iss", issuer);
        }
        return builder.encode().build().toUriString();
    }

    private String token(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
