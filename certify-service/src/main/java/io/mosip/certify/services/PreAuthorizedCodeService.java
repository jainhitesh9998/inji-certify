package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.certify.oid4vci.Oid4vciIssuerResolver;
import io.mosip.certify.oid4vci.Oid4vciProperties;
import io.mosip.certify.oid4vci.OfferSurface;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class PreAuthorizedCodeService {

    private final VCICacheService vciCacheService;

    private final AccessTokenJwtUtil accessTokenJwtUtil;

    private final ObjectMapper objectMapper;

    private final CredentialConfigurationService credentialConfigurationService;
    private final CredentialRegistry credentialRegistry;

    private final CredentialConfigRepository credentialConfigRepository;

    private final Validator validator;

    private final Oid4vciProperties oid4vciProperties;

    private final Oid4vciIssuerResolver oid4vciIssuers;

    private final AuthorizationContext authorizationContext;

    @Value("${mosip.certify.identifier}")
    private String issuerIdentifier;

    @Value("${mosip.certify.pre-auth.default-expiry-seconds:600}")
    private int defaultExpirySeconds;

    @Value("${mosip.certify.pre-auth.min-expiry-seconds:60}")
    private int minExpirySeconds;

    @Value("${mosip.certify.pre-auth.max-expiry-seconds:86400}")
    private int maxExpirySeconds;

    @Value("${mosip.certify.credential-offer-url:}")
    private String credentialOfferUrl;

    @Value("${mosip.certify.oauth.token.expires-in-seconds:600}")
    private int accessTokenExpirySeconds;

    @Value("${mosip.certify.oauth.issuer:}")
    private String oauthIssuer;

    @Value("${mosip.certify.oauth.access-token.audience:}")
    private String oauthAudience;

    @Autowired
    public PreAuthorizedCodeService(VCICacheService vciCacheService,
                                    CredentialRegistry credentialRegistry,
                                    AccessTokenJwtUtil accessTokenJwtUtil,
                                    ObjectMapper objectMapper,
                                    CredentialConfigurationService credentialConfigurationService,
                                    CredentialConfigRepository credentialConfigRepository,
                                    Validator validator,
                                    Oid4vciProperties oid4vciProperties,
                                    Oid4vciIssuerResolver oid4vciIssuers,
                                    AuthorizationContext authorizationContext) {
        this.vciCacheService = vciCacheService;
        this.accessTokenJwtUtil = accessTokenJwtUtil;
        this.objectMapper = objectMapper;
        this.credentialConfigurationService = credentialConfigurationService;
        this.credentialRegistry = credentialRegistry;
        this.credentialConfigRepository = credentialConfigRepository;
        this.validator = validator;
        this.oid4vciProperties = oid4vciProperties;
        this.oid4vciIssuers = oid4vciIssuers;
        this.authorizationContext = authorizationContext;
    }
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * The longest {@code subject} an offer may name: an identifier the data provider resolves (a CSV row id, an
     * individual id, a {@code did:jwk}), cached with the offer until it is redeemed, so it is bounded like every other
     * stored field of a public request (F-21 review round 2; the PAR endpoint caps {@code state} the same way).
     */
    static final int MAX_SUBJECT_LENGTH = 512;

    /** Measures the claims as JSON; a mapper of its own, so the size does not depend on the injected one's modules. */
    private static final ObjectMapper CLAIMS_SIZE = new ObjectMapper();

    /** The deep link a QR code carries and, when the caller asked for the offer by value, the offer itself. */
    public record CredentialOfferResult(String deepLink, CredentialOfferResponse offer) {}

    /**
     * Creates an offer by reference (OpenID4VCI 1.0 section 4.1.1): the caller gets the
     * {@code openid-credential-offer://} deep link and fetches the offer itself from it.
     */
    public String generatePreAuthorizedCode(PreAuthorizedRequest request) {
        return createCredentialOffer(request).deepLink();
    }

    /**
     * Creates a pre-authorized offer for the surface the request names, or the configured default
     * ({@code certify.protocol.oid4vci-v1.offers.default-issuer}) when it names none. The offer's
     * {@code credential_issuer} is that surface's identifier, and the access token the offer's code is exchanged for is
     * addressed to the same surface's credential endpoint. With {@code offer_by_value} the offer document travels in the
     * response and URL-encoded inside the deep link instead of only being reachable through it.
     */
    public CredentialOfferResult createCredentialOffer(PreAuthorizedRequest request) {
        validatePreAuthorizedRequest(request);
        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;
        if (expirySeconds < minExpirySeconds || expirySeconds > maxExpirySeconds) {
            log.error("expires_in {} out of bounds [{}, {}]", expirySeconds, minExpirySeconds, maxExpirySeconds);
            throw new InvalidRequestException(ErrorConstants.INVALID_EXPIRY_RANGE);
        }
        OfferSurface surface = requestedSurface(request);
        // Only an /oid4vci offer is bound to a tenant: a legacy offer stays tenant-agnostic, exactly as it was before
        // the surface existed, so an unchanged deployment keeps the same token audience and no cross-tenant rule; its
        // cached entry only gains issuer "legacy", which never reaches the wire (M-09 review round 2).
        String tenantId = surface == OfferSurface.OID4VCI ? requestTenantId() : null;

        String offerId = UUID.randomUUID().toString();
        String preAuthCode = generateUniquePreAuthCode();

        long currentTime = System.currentTimeMillis();
        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(request.getCredentialConfigurationId())
                .claims(request.getClaims())
                .subject(blankToNull(request.getSubject()))
                .txnCode(request.getTxCode())
                .issuer(surface.wireName())
                .tenantId(tenantId)
                .audience(audience(surface, tenantId))
                .createdAt(currentTime)
                .expiresAt(currentTime + (expirySeconds * 1000L)).build();

        vciCacheService.setPreAuthCodeData(preAuthCode, codeData);

        CredentialOfferResponse offerResponse = buildCredentialOffer(request.getCredentialConfigurationId(), preAuthCode, request.getTxCode(), surface, tenantId);
        boolean byValue = Boolean.TRUE.equals(request.getOfferByValue());
        if (byValue) {
            // by value nothing points at the cached copy, so caching it would only leave an offer nobody can reach
            return new CredentialOfferResult(buildCredentialOfferByValueLink(offerResponse), offerResponse);
        }
        vciCacheService.setCredentialOffer(offerId, offerResponse);
        return new CredentialOfferResult(buildCredentialOfferUri(offerId), null);
    }

    /**
     * The surface the request names, else the configured default. A blank {@code issuer} is absent:
     * {@link PreAuthorizedRequest#setIssuer} stores it that way before bean validation sees it, and this check repeats
     * the reading for a request built without that setter.
     */
    private OfferSurface requestedSurface(PreAuthorizedRequest request) {
        if (request.getIssuer() == null || request.getIssuer().isBlank()) {
            return oid4vciProperties.offers().defaultIssuer();
        }
        return OfferSurface.from(request.getIssuer());
    }

    /** The tenant the request belongs to, resolved before the token filters and stamped on the offer. */
    private String requestTenantId() {
        return authorizationContext == null ? AuthorizationContext.DEFAULT_TENANT : authorizationContext.getTenantId();
    }

    /**
     * The offer's {@code credential_issuer} (OpenID4VCI 1.0 section 4.1.1): the surface the offer targets. For
     * {@code oid4vci} it is exactly the value the surface's discovery document publishes as {@code credential_issuer}
     * (tenant-aware), so a wallet that reads the offer and then the metadata sees one identifier.
     */
    private String credentialIssuer(OfferSurface surface, String tenantId) {
        if (surface == OfferSurface.OID4VCI) {
            return oid4vciIssuers.forTenant(tenantId).identifier();
        }
        return issuerIdentifier;
    }

    private void validatePreAuthorizedRequest(PreAuthorizedRequest request) {
        CredentialIssuerMetadataDTO metadata = credentialRegistry.issuerMetadata();
        Map<String, CredentialConfigurationSupportedDTO> supportedConfigs = metadata
                .getCredentialConfigurationSupportedDTO();

        if (supportedConfigs == null || !supportedConfigs.containsKey(request.getCredentialConfigurationId())) {
            log.error("Invalid credential configuration ID: {}", request.getCredentialConfigurationId());
            throw new InvalidRequestException(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID);
        }

        CredentialConfigurationSupportedDTO config = supportedConfigs.get(request.getCredentialConfigurationId());
        String subject = blankToNull(request.getSubject());
        if (subject != null && subject.length() > MAX_SUBJECT_LENGTH) {
            log.error("subject of {} characters refused (at most {})", subject.length(), MAX_SUBJECT_LENGTH);
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "subject is longer than " + MAX_SUBJECT_LENGTH + " characters");
        }
        Map<String, Object> claims = request.getClaims();
        boolean claimsPresent = claims != null && !claims.isEmpty();
        if (claimsPresent) {
            requireBoundedClaims(claims);
        }
        // A subject names the record the data provider resolves; claims, whenever they are given, are identity data and
        // are validated (bean validation already refused an offer with neither). Validated next to a subject too (F-21
        // review round 2): they are cached with the offer and copied into the token's transaction either way, and
        // PreAuthDataProviderPlugin issues them as the credential's data even when a subject is present, so skipping the
        // check there let unknown claims through to a credential and let any caller park them in the cache.
        if (subject == null || claimsPresent) {
            validateClaims(config, claimsPresent ? claims : Map.of());
        }
    }

    /**
     * {@code invalid_request} unless the claims fit {@code certify.protocol.oid4vci-v1.offers.max-claims-values} and
     * {@code max-claims-bytes} (see {@link Oid4vciProperties.Offers}): every value counts, at any depth, so the heap a
     * cached offer can cost is bounded by both numbers, not just by its length.
     */
    private void requireBoundedClaims(Map<String, Object> claims) {
        Oid4vciProperties.Offers offers = oid4vciProperties.offers();
        int values = countValues(claims, offers.maxClaimsValues());
        if (values > offers.maxClaimsValues()) {
            log.error("claims with more than {} values refused", offers.maxClaimsValues());
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "claims hold more than " + offers.maxClaimsValues() + " JSON values");
        }
        int bytes;
        try {
            bytes = CLAIMS_SIZE.writeValueAsBytes(claims).length;
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "claims cannot be written as JSON");
        }
        if (bytes > offers.maxClaimsBytes()) {
            log.error("claims of {} bytes as JSON refused (at most {})", bytes, offers.maxClaimsBytes());
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "claims are larger than " + offers.maxClaimsBytes() + " bytes as JSON");
        }
    }

    /** The JSON values inside {@code claims} at any depth (objects, arrays and scalars), counted up to {@code limit} + 1. */
    static int countValues(Map<String, Object> claims, int limit) {
        List<Object> pending = new ArrayList<>(claims.values()); // a JSON null is a value too, so no ArrayDeque
        int count = 0;
        while (!pending.isEmpty() && count <= limit) {
            Object value = pending.remove(pending.size() - 1);
            count++;
            if (value instanceof Map<?, ?> map) {
                pending.addAll(map.values());
            } else if (value instanceof Collection<?> list) {
                pending.addAll(list);
            }
        }
        return count;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private void validateClaims(CredentialConfigurationSupportedDTO config, Map<String, Object> providedClaims) {
        if (config.getCredentialMetadataDTO() == null ||
                config.getCredentialMetadataDTO().getClaims() == null) {
            return;
        }

        Set<String> allowedClaimKeys = new HashSet<>();
        List<String> mandatoryClaims = new ArrayList<>();

        for (CredentialMetadataDTO.Claims claim :
                config.getCredentialMetadataDTO().getClaims()) {

            List<String> path = claim.getPath();

            if (path != null && !path.isEmpty()) {
                String claimKey = path.getLast();

                allowedClaimKeys.add(claimKey);
                if (Boolean.TRUE.equals(claim.isMandatory())) {
                    mandatoryClaims.add(claimKey);
                }
            }
        }

        List<String> missingMandatoryClaims = mandatoryClaims.stream()
                .filter(key ->
                        !providedClaims.containsKey(key) ||
                                providedClaims.get(key) == null ||
                                providedClaims.get(key).toString().trim().isEmpty()
                )
                .toList();

        if (!missingMandatoryClaims.isEmpty()) {
            log.error("Missing mandatory claims: {}", missingMandatoryClaims);
            throw new InvalidRequestException(ErrorConstants.MISSING_MANDATORY_CLAIM);
        }

        List<String> unknownClaims = new ArrayList<>();
        for (String providedClaim : providedClaims.keySet()) {
            if (!allowedClaimKeys.contains(providedClaim)) {
                unknownClaims.add(providedClaim);
            }
        }
        if (!unknownClaims.isEmpty()) {
            log.error("Unknown claims provided: {}", unknownClaims);
            throw new InvalidRequestException(ErrorConstants.UNKNOWN_CLAIMS);
        }
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        log.info("Retrieving credential offer for ID: {}", offerId);

        // Trim offerId early to ensure validation and cache lookup use the same value
        if (offerId != null) {
            offerId = offerId.trim();
        }

        if (!isValidUUID(offerId)) {
            log.error("Invalid offer_id format: {}", offerId);
            throw new InvalidRequestException(ErrorConstants.INVALID_OFFER_ID_FORMAT);
        }

        CredentialOfferResponse offer = vciCacheService.getCredentialOffer(offerId);

        if (offer == null) {
            log.error("Credential offer not found or expired for ID: {}", offerId);
            throw new CertifyException(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND, "Credential offer not found or expired");
        }

        log.info("Successfully retrieved credential offer for ID: {}", offerId);
        return offer;
    }

    private boolean isValidUUID(String str) {
        if (str == null || str.trim().isEmpty()) {
            return false;
        }
        try {
            UUID.fromString(str.trim());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String generateUniquePreAuthCode() {
        String preAuthCode;
        int attempts = 0;
        final int MAX_ATTEMPTS = 3;

        do {
            preAuthCode = generateSecureCode(32);
            attempts++;
            if (vciCacheService.getPreAuthCodeData(preAuthCode) == null) {
                return preAuthCode;
            }
        } while (attempts < MAX_ATTEMPTS);

        throw new IllegalStateException(
                "Failed to generate unique pre-authorized code after " + MAX_ATTEMPTS + " attempts");
    }

    private CredentialOfferResponse buildCredentialOffer(String configId, String preAuthCode, String txnCode,
                                                         OfferSurface surface, String tenantId) {
        Grant.PreAuthorizedCodeGrantType grant = Grant.PreAuthorizedCodeGrantType.builder()
                .preAuthorizedCode(preAuthCode)
                .txCode(StringUtils.hasText(txnCode) ? buildTxCodeInfo(txnCode) : null).build();

        Grant grants = Grant.builder().preAuthorizedCode(grant).build();

        return CredentialOfferResponse.builder()
                .credentialIssuer(credentialIssuer(surface, tenantId))
                .credentialConfigurationIds(Collections.singletonList(configId))
                .grants(grants)
                .build();
    }

    private TxCode buildTxCodeInfo(String txnCode) {
        return TxCode.builder()
                .length(txnCode.length())
                .inputMode(txnCode.matches("\\d+") ? "numeric" : "text")
                .description("Please enter the transaction code provided to you")
                .build();
    }

    private String buildCredentialOfferUri(String offerId) {
        String offerFetchUrl = credentialOfferUrl + offerId;
        return "openid-credential-offer://?credential_offer_uri=" + percentEncode(offerFetchUrl);
    }

    /** The deep link that carries the offer itself, URL-encoded (OpenID4VCI 1.0 section 4.1.1, {@code credential_offer}). */
    private String buildCredentialOfferByValueLink(CredentialOfferResponse offer) {
        try {
            return "openid-credential-offer://?credential_offer="
                    + percentEncode(objectMapper.writeValueAsString(offer));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "The credential offer could not be serialized", e);
        }
    }

    /**
     * RFC 3986 percent-encoding for the query value of a deep link: {@link URLEncoder} encodes a space as {@code +}
     * (application/x-www-form-urlencoded), which a wallet reading the raw query would decode literally, so the space is
     * written as {@code %20} and every other byte as its percent triplet.
     */
    private static String percentEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 is always supported, this should never happen
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "UTF-8 encoding not supported", e);
        }
    }

    private String generateSecureCode(int length) {
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            code.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        }
        return code.toString();
    }

    /**
     * Exchange pre-authorized code for access token
     */
    public OAuthTokenResponse exchangePreAuthorizedCode(OAuthTokenRequest request) {
        Set<ConstraintViolation<OAuthTokenRequest>> violations =
                validator.validate(request);

        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }

        log.info("Processing token request for grant_type: {}", request.getGrant_type());

        // Retrieve and validate pre-auth code data
        PreAuthCodeData codeData = vciCacheService.getPreAuthCodeData(request.getPre_authorized_code());

        validateTokenRequest(request, codeData);

        // Generate access token
        String accessToken = generateAccessToken(codeData, request.getDpopJkt());

        long currentTime = System.currentTimeMillis();

        PreAuthTransaction transaction = new PreAuthTransaction();
        transaction.setCredentialConfigurationId(codeData.getCredentialConfigurationId());
        transaction.setClaims(codeData.getClaims());
        transaction.setCreatedAt(currentTime);

        vciCacheService.setPreAuthTransaction(CommonUtil.generateOIDCAtHash(accessToken), transaction);

        log.info("Successfully exchanged pre-authorized code for access token");

        OAuthTokenResponse response = new OAuthTokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType(request.getDpopJkt() != null ? io.mosip.certify.core.constants.Constants.DPOP : "Bearer");
        response.setExpiresIn(accessTokenExpirySeconds);
        return response;
    }

    private void validateTokenRequest(OAuthTokenRequest request, PreAuthCodeData codeData) {

        // Validate grant type
        if (!Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(request.getGrant_type())) {
            log.error("Unsupported grant type: {}", request.getGrant_type());
            throw new CertifyException(ErrorConstants.UNSUPPORTED_GRANT_TYPE, "Grant type not supported");
        }

        // An /oid4vci code belongs to the tenant that issued the offer: another tenant's token endpoint must not redeem
        // it, or a token minted beside an offer at one tenant would be accepted at another (checked before the claim,
        // so a misrouted request does not burn the code). A legacy code carries no tenant and is redeemed anywhere, as
        // before.
        String offerTenant = codeData == null ? null : offerTenant(codeData);
        if (offerTenant != null && !offerTenant.equals(requestTenantId())) {
            log.error("Pre-authorized code of tenant {} presented at tenant {}", offerTenant, requestTenantId());
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code was not issued by this tenant");
        }

        // Atomically claim the pre-authorized code
        boolean claimed = vciCacheService.claimPreAuthCode(request.getPre_authorized_code());
        if (!claimed) {
            log.error("Pre-authorized code already used or invalid");
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code has already been used  or invalid");
        }

        // Check expiry
        long currentTime = System.currentTimeMillis();
        if (codeData.getExpiresAt() < currentTime) {
            log.error("Pre-authorized code expired. Expiry: {}, Current: {}", codeData.getExpiresAt(), currentTime);
            throw new CertifyException("pre_auth_code_expired", "Pre-authorized code has expired");
        }

        // Validate transaction code if required
        String expectedTxCode = codeData.getTxnCode();
        if (StringUtils.hasText(expectedTxCode) && !StringUtils.hasText(request.getTx_code())) {
            log.error("Transaction code required but not provided");
            throw new CertifyException("tx_code_required", "Transaction code is required for this pre-authorized code");
        }
        if (StringUtils.hasText(expectedTxCode) && !expectedTxCode.equals(request.getTx_code())) {
            log.error("Transaction code mismatch");
            throw new CertifyException("tx_code_mismatch", "Transaction code does not match");
        }
    }

    /**
     * Generate a signed JWT access token for pre-authorized code flow.
     * Calls AccessTokenJwtUtil.generateSignedJwt directly with raw parameters.
     */
    private String generateAccessToken(PreAuthCodeData codeData, String dpopJkt) {
        try {
            // the token subject: the record the offer named, else the offer's claims as JSON (PreAuthDataProviderPlugin reads them from the cache)
            String claimsJson = codeData.getSubject() != null ? codeData.getSubject()
                    : objectMapper.writeValueAsString(codeData.getClaims() == null ? Map.of() : codeData.getClaims());
            String credentialConfigId = codeData.getCredentialConfigurationId();

            // Lookup credential configuration in database
            String credentialScope = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigId)
                    .map(credentialConfig -> {
                        if (!Constants.ACTIVE.equals(credentialConfig.getStatus())) {
                            log.error("Credential configuration is not active for ID: {}, status: {}",
                                    credentialConfigId, credentialConfig.getStatus());
                            throw new CertifyException("invalid_request",
                                    "Credential configuration is not active: " + credentialConfigId);
                        }
                        String scope = credentialConfig.getScope();
                        if (!StringUtils.hasText(scope)) {
                            log.error("Scope is not configured for credential configuration ID: {}", credentialConfigId);
                            throw new CertifyException("server_error",
                                    "Scope not configured for credential: " + credentialConfigId);
                        }
                        return scope;
                    })
                    .orElseThrow(() -> {
                        log.error("Credential configuration not found for ID: {}", credentialConfigId);
                        return new CertifyException("invalid_request",
                                "Invalid credential_configuration_id: " + credentialConfigId);
                    });

            return accessTokenJwtUtil.generateSignedJwt(
                    claimsJson,
                    credentialScope,
                    "",
                    oauthIssuer,
                    audience(codeData),
                    accessTokenExpirySeconds,
                    dpopJkt
            );
        } catch (Exception e) {
            log.error("Failed to generate access token for pre-authorized code flow", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate access token", e);
        }
    }

    /**
     * The access token's audience is the one resolved when the offer was created (OpenID4VCI 1.0 section 6.1: a token
     * for this issuer's credential endpoint), so it stays the tenant's own endpoint even when the code is exchanged
     * later. An entry written before the field existed carries none and keeps the configured legacy audience.
     */
    private String audience(PreAuthCodeData codeData) {
        return codeData.getAudience() != null ? codeData.getAudience() : oauthAudience;
    }

    /**
     * The audience of the token an offer's code is exchanged for: none for {@code legacy}, whose token keeps the
     * deployment's configured {@code mosip.certify.oauth.access-token.audience} exactly as before (nothing is stored,
     * so nothing can drift), and this surface's credential endpoint (tenant-aware) for {@code oid4vci}, which its
     * access-token filter accepts.
     */
    private String audience(OfferSurface surface, String tenantId) {
        if (surface != OfferSurface.OID4VCI) {
            return null;
        }
        return oid4vciIssuers.forTenant(tenantId).credentialEndpoint();
    }

    /**
     * The tenant a cached code is bound to. An {@code oid4vci} offer stamps its tenant, so that is the tenant; an
     * {@code oid4vci} entry without one can only be one written before offers were bound (that build was never
     * released), and those belong to {@code default}. A {@code legacy} entry answers {@code null}: no tenant rule
     * applies to it, as before the surface existed.
     */
    private static String offerTenant(PreAuthCodeData codeData) {
        if (codeData.getTenantId() != null) {
            return codeData.getTenantId();
        }
        return OfferSurface.OID4VCI.wireName().equals(codeData.getIssuer()) ? AuthorizationContext.DEFAULT_TENANT : null;
    }
}