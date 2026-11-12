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
        String tenantId = requestTenantId();

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
        // a subject names the record the data provider resolves; otherwise the claims are the identity data and are
        // validated as before (bean validation already refused an offer with neither)
        if (blankToNull(request.getSubject()) == null) {
            validateClaims(config, request.getClaims() == null ? Map.of() : request.getClaims());
        }
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

        // A code belongs to the tenant that issued the offer: another tenant's token endpoint must not redeem it, or a
        // token minted beside an offer at one tenant would be accepted at another (checked before the claim, so a
        // misrouted request does not burn the code)
        if (codeData != null && codeData.getTenantId() != null && !codeData.getTenantId().equals(requestTenantId())) {
            log.error("Pre-authorized code of tenant {} presented at tenant {}", codeData.getTenantId(), requestTenantId());
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
     * The audience of the token an offer's code is exchanged for: the compatibility endpoint as configured for
     * {@code legacy}, this surface's credential endpoint (tenant-aware) for {@code oid4vci}, which its access-token
     * filter accepts.
     */
    private String audience(OfferSurface surface, String tenantId) {
        if (surface != OfferSurface.OID4VCI) {
            return oauthAudience;
        }
        return oid4vciIssuers.forTenant(tenantId).credentialEndpoint();
    }
}