package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import jakarta.validation.Validator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PreAuthorizedCodeServiceTest {

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private AccessTokenJwtUtil accessTokenJwtUtil;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @Mock
    private CredentialRegistry credentialRegistry;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private Validator validator;

    private io.mosip.certify.oid4vci.Oid4vciProperties oid4vciProperties;

    private io.mosip.certify.oid4vci.Oid4vciIssuerResolver oid4vciIssuers;

    private io.mosip.certify.core.dto.AuthorizationContext authorizationContext;

    private PreAuthorizedRequest request;
    private Map<String, Object> issuerMetadata;
    private Map<String, Object> supportedConfigs;
    private Map<String, Object> config;
    private CredentialIssuerMetadataDTO metadataDTO;
    private final String CONFIG_ID = "test-config";

    private PreAuthorizedCodeService preAuthorizedCodeService;
    @Before
    public void setup() throws Exception {
        oid4vciProperties = new io.mosip.certify.oid4vci.Oid4vciProperties(
                new io.mosip.certify.oid4vci.Oid4vciProperties.CompatCore(false),
                new io.mosip.certify.oid4vci.Oid4vciProperties.Notification(java.time.Duration.ofDays(1), java.time.Duration.ofHours(1)),
                new io.mosip.certify.oid4vci.Oid4vciProperties.Nonce(true),
                new io.mosip.certify.oid4vci.Oid4vciProperties.Batch(10),
                new io.mosip.certify.oid4vci.Oid4vciProperties.KeyAttestation(Map.of(), java.time.Duration.ofSeconds(60)),
                new io.mosip.certify.oid4vci.Oid4vciProperties.DidWebHolders(false, java.time.Duration.ofSeconds(5)),
                new io.mosip.certify.oid4vci.Oid4vciProperties.Offers(io.mosip.certify.oid4vci.OfferSurface.LEGACY));
        authorizationContext = new io.mosip.certify.core.dto.AuthorizationContext();
        oid4vciIssuers = new io.mosip.certify.oid4vci.Oid4vciIssuerResolver(
                new io.mosip.certify.oid4vci.Oid4vciIssuer("https://issuer.com/oid4vci"),
                new io.mosip.certify.tenancy.TenantContexts(tenancy()));
        preAuthorizedCodeService = new PreAuthorizedCodeService(vciCacheService, credentialRegistry,
                accessTokenJwtUtil,
                objectMapper,
                credentialConfigurationService,
                credentialConfigRepository,
                validator,
                oid4vciProperties,
                oid4vciIssuers,
                authorizationContext
        );
        ReflectionTestUtils.setField(preAuthorizedCodeService, "issuerIdentifier", "https://issuer.com");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "defaultExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "minExpirySeconds", 60);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "maxExpirySeconds", 86400);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "credentialOfferUrl", "https://credentialOffer.com/");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "accessTokenExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "oauthIssuer", "https://oauth.issuer.com");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "oauthAudience", "https://oauth.audience.com");

        request = new PreAuthorizedRequest();
        request.setCredentialConfigurationId(CONFIG_ID);
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        request.setClaims(claims);

        issuerMetadata = new HashMap<>();
        supportedConfigs = new HashMap<>();
        config = new HashMap<>();
        Map<String, Object> requiredClaims = new HashMap<>();
        Map<String, Object> nameClaim = new HashMap<>();
        nameClaim.put(Constants.MANDATORY, true);
        requiredClaims.put("name", nameClaim);
        config.put(Constants.CLAIMS, requiredClaims);
        supportedConfigs.put(CONFIG_ID, config);
        issuerMetadata.put(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED, supportedConfigs);

        // Mock ObjectMapper for JSON serialization
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"name\":\"John Doe\"}");
        // Setup mock for credentialConfigurationService
        Map<String, CredentialConfigurationSupportedDTO> supportedDTOMap = new LinkedHashMap<>();
        CredentialConfigurationSupportedDTO configDTO = new CredentialConfigurationSupportedDTO();
        CredentialMetadataDTO metadata = new CredentialMetadataDTO();
        List<CredentialMetadataDTO.Claims> claimsList = new ArrayList<>();

        CredentialMetadataDTO.Claims givenName = new CredentialMetadataDTO.Claims();
        givenName.setPath(List.of("credentialSubject", "name"));

        ClaimsDisplayFieldsConfigDTO.Display givenNameDisplay =
                new ClaimsDisplayFieldsConfigDTO.Display();
        givenNameDisplay.setName("Given Name");
        givenNameDisplay.setLocale("en-US");

        givenName.setDisplay(List.of(givenNameDisplay));
        givenName.setMandatory(true);

        claimsList.add(givenName);
        metadata.setClaims(claimsList);
        configDTO.setCredentialMetadataDTO(metadata);
        supportedDTOMap.put(CONFIG_ID, configDTO);



        metadataDTO = mock(CredentialIssuerMetadataDTO.class);
        when(metadataDTO.getCredentialConfigurationSupportedDTO()).thenReturn(supportedDTOMap);

        // KEY FIX: Mock the credentialConfigurationService to return metadataDTO
        when(credentialRegistry.issuerMetadata()).thenReturn(metadataDTO);

        // Mock credentialConfigRepository
        CredentialConfig credentialConfig = new CredentialConfig();
        credentialConfig.setStatus(Constants.ACTIVE);
        credentialConfig.setScope("test_scope");
        when(credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID)).thenReturn(Optional.of(credentialConfig));
        when(validator.validate(any())).thenReturn(Collections.emptySet());
    }

    @Test
    public void generatePreAuthorizedCode_Success() {
        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        Assert.assertTrue(result.startsWith("openid-credential-offer://?credential_offer_uri="));
        verify(vciCacheService).setPreAuthCodeData(anyString(), any(PreAuthCodeData.class));
        verify(vciCacheService).setCredentialOffer(anyString(), any(CredentialOfferResponse.class));
    }

    @Test
    public void generatePreAuthorizedCode_SubjectWithoutClaims_SkipsClaimValidation() {
        PreAuthorizedRequest subjectRequest = new PreAuthorizedRequest();
        subjectRequest.setCredentialConfigurationId(CONFIG_ID);
        subjectRequest.setSubject("2154189532");

        String result = preAuthorizedCodeService.generatePreAuthorizedCode(subjectRequest);

        Assert.assertTrue(result.startsWith("openid-credential-offer://?credential_offer_uri="));
        org.mockito.ArgumentCaptor<PreAuthCodeData> stored = org.mockito.ArgumentCaptor.forClass(PreAuthCodeData.class);
        verify(vciCacheService).setPreAuthCodeData(anyString(), stored.capture());
        Assert.assertEquals("2154189532", stored.getValue().getSubject());
    }

    @Test
    public void exchangePreAuthorizedCode_WithSubject_UsesItAsTheTokenSubject() throws Exception {
        String preAuthCode = "subject-pre-auth-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .subject("2154189532")
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();
        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(), org.mockito.ArgumentMatchers.isNull()))
                .thenReturn("test.jwt.token");

        OAuthTokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertEquals("test.jwt.token", response.getAccessToken());
        verify(accessTokenJwtUtil).generateSignedJwt(org.mockito.ArgumentMatchers.eq("2154189532"), anyString(), anyString(), anyString(), anyString(), anyInt(), org.mockito.ArgumentMatchers.isNull());
    }

    @Test
    public void generatePreAuthorizedCode_WithTxCode_Success() {
        request.setTxCode("1234");
        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        verify(vciCacheService).setPreAuthCodeData(anyString(), any(PreAuthCodeData.class));
        verify(vciCacheService).setCredentialOffer(anyString(), any(CredentialOfferResponse.class));
    }

    @Test
    public void generatePreAuthorizedCode_Failure_If_InvalidConfigId() {
        request.setCredentialConfigurationId("invalid-id");

        // Update metadata mock to not include invalid-id
        Map<String, CredentialConfigurationSupportedDTO> emptyMap = new LinkedHashMap<>();
        when(metadataDTO.getCredentialConfigurationSupportedDTO()).thenReturn(emptyMap);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                        () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID, exception.getMessage());
    }

    @Test
    public void generatePreAuthorizedCode_MissingMandatoryClaim() {
        request.getClaims().remove("name");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.MISSING_MANDATORY_CLAIM, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_UnknownClaim() {
        request.getClaims().put("unknown", "value");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.UNKNOWN_CLAIMS, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooLow() {
        request.setExpiresIn(10);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooHigh() {
        request.setExpiresIn(100000);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_RetryOnCollision_Success() {
        // First attempt returns existing data (collision), second returns null
        // (success)
        when(vciCacheService.getPreAuthCodeData(anyString()))
                .thenReturn(new PreAuthCodeData())
                .thenReturn(null);

        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        // Should have called getPreAuthCodeData 2 times
        verify(vciCacheService, times(2)).getPreAuthCodeData(anyString());
    }

    @Test
    public void generatePreAuthorizedCode_MaxRetriesExceeded_Fail() {
        // Always returns existing data (collision)
        when(vciCacheService.getPreAuthCodeData(anyString())).thenReturn(new PreAuthCodeData());

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertTrue(exception.getMessage().contains("Failed to generate unique pre-authorized code"));
        // Should have tried MAX_ATTEMPTS (3)
        verify(vciCacheService, times(3)).getPreAuthCodeData(anyString());
    }

    // Tests for getCredentialOffer method

    @Test
    public void getCredentialOffer_Success() {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";
        CredentialOfferResponse expectedOffer = CredentialOfferResponse.builder()
                .credentialIssuer("https://issuer.com")
                .build();

        when(vciCacheService.getCredentialOffer(validUuid)).thenReturn(expectedOffer);

        CredentialOfferResponse result = preAuthorizedCodeService.getCredentialOffer(validUuid);

        Assert.assertNotNull(result);
        Assert.assertEquals(expectedOffer, result);
        verify(vciCacheService).getCredentialOffer(validUuid);
    }

    @Test
    public void getCredentialOffer_InvalidUuidFormat_ThrowsInvalidRequestException() {
        String invalidUuid = "not-a-valid-uuid";

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(invalidUuid));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_NullOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(null));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_EmptyOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(""));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_WhitespaceOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer("   "));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_NotFound_ThrowsCertifyException() {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";

        when(vciCacheService.getCredentialOffer(validUuid)).thenReturn(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(validUuid));

        Assert.assertEquals(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND, exception.getErrorCode());
        verify(vciCacheService).getCredentialOffer(validUuid);
    }

    @Test
    public void exchangePreAuthorizedCode_Success() throws Exception {
        String preAuthCode = "test-pre-auth-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(claims)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000) // expires in 10 minutes
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(), org.mockito.ArgumentMatchers.isNull()))
                .thenReturn("test.jwt.token");

        OAuthTokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        Assert.assertEquals("test.jwt.token", response.getAccessToken());
        Assert.assertEquals("Bearer", response.getTokenType());
        Assert.assertEquals(Integer.valueOf(600), response.getExpiresIn());

        verify(vciCacheService).getPreAuthCodeData(preAuthCode);
        verify(vciCacheService).claimPreAuthCode(preAuthCode);
        verify(vciCacheService).setPreAuthTransaction(anyString(), any(PreAuthTransaction.class));
    }

    @Test
    public void exchangePreAuthorizedCode_WithTxCode_Success() throws Exception {
        String preAuthCode = "test-pre-auth-code";
        String txCode = "1234";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        tokenRequest.setTx_code(txCode);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(claims)
                .txnCode(txCode)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(), org.mockito.ArgumentMatchers.isNull()))
                .thenReturn("test.jwt.token");

        OAuthTokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        verify(vciCacheService).claimPreAuthCode(preAuthCode);
    }

    @Test
    public void exchangePreAuthorizedCode_UnsupportedGrantType_ThrowsCertifyException() {
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type("invalid_grant_type");
        tokenRequest.setPre_authorized_code("test-code");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData("test-code")).thenReturn(codeData);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_GRANT_TYPE, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_InvalidPreAuthCode_ThrowsCertifyException() {
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code("invalid-code");

        when(vciCacheService.getPreAuthCodeData("invalid-code")).thenReturn(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_ExpiredCode_ThrowsCertifyException() {
        String preAuthCode = "expired-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis() - 700000)
                .expiresAt(System.currentTimeMillis() - 100000) // expired
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("pre_auth_code_expired", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_AlreadyUsedCode_ThrowsCertifyException() {
        String preAuthCode = "used-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(false);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeRequired_ThrowsCertifyException() {
        String preAuthCode = "test-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // txCode is required
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_required", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeMismatch_ThrowsCertifyException() {
        String preAuthCode = "test-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        tokenRequest.setTx_code("wrong-code");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // expected txCode
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_mismatch", exception.getErrorCode());
    }

    // ---- the surface an offer targets (M-09, decision D5) ------------------------------------------------------

    @Test
    public void offerWithoutAnIssuerTargetsTheConfiguredDefault_Legacy() {
        PreAuthorizedCodeService.CredentialOfferResult result = preAuthorizedCodeService.createCredentialOffer(request);

        Assert.assertEquals("https://issuer.com", capturedOffer().getCredentialIssuer());
    }

    @Test
    public void offerWithoutAnIssuerTargetsTheConfiguredDefault_Oid4vci() {
        PreAuthorizedCodeService service = serviceWithDefaultIssuer("oid4vci");

        PreAuthorizedCodeService.CredentialOfferResult result = service.createCredentialOffer(request);

        Assert.assertEquals("https://issuer.com/oid4vci", capturedOffer().getCredentialIssuer());
        Assert.assertNotNull(result.deepLink());
    }

    @Test
    public void theRequestOverridesTheConfiguredDefault() {
        request.setIssuer("oid4vci");

        preAuthorizedCodeService.createCredentialOffer(request);

        Assert.assertEquals("https://issuer.com/oid4vci", capturedOffer().getCredentialIssuer());
    }

    @Test
    public void anUnknownIssuerIsRefusedBeforeAnythingIsCached() {
        request.setIssuer("oid5vci");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.createCredentialOffer(request));

        Assert.assertEquals("invalid_issuer", exception.getErrorCode());
        verify(vciCacheService, never()).setPreAuthCodeData(anyString(), any(PreAuthCodeData.class));
    }

    @Test
    public void anOfferCanBeReturnedByValue() {
        request.setIssuer("oid4vci");
        request.setOfferByValue(true);

        PreAuthorizedCodeService.CredentialOfferResult result = preAuthorizedCodeService.createCredentialOffer(request);

        Assert.assertNotNull("the offer document travels in the answer", result.offer());
        Assert.assertEquals("https://issuer.com/oid4vci", result.offer().getCredentialIssuer());
        Assert.assertTrue(result.deepLink(), result.deepLink().startsWith("openid-credential-offer://?credential_offer="));
        Assert.assertFalse(result.deepLink().contains("credential_offer_uri="));
        Assert.assertFalse("a space is %20 in an RFC 3986 query value, never +", result.deepLink().contains("+"));
        Assert.assertTrue(result.deepLink(), result.deepLink().contains("%20"));
    }

    @Test
    public void anOfferByReferenceCarriesNoOfferDocument() {
        PreAuthorizedCodeService.CredentialOfferResult result = preAuthorizedCodeService.createCredentialOffer(request);

        Assert.assertNull(result.offer());
        Assert.assertTrue(result.deepLink(), result.deepLink().startsWith("openid-credential-offer://?credential_offer_uri="));
    }

    @Test
    public void theTokenForAnOid4vciOfferIsAddressedToTheSurfaceCredentialEndpoint() throws Exception {
        String preAuthCode = "oid4vci-pre-auth-code";
        OAuthTokenRequest tokenRequest = tokenRequest(preAuthCode);
        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .issuer("oid4vci")
                .audience("https://issuer.com/oid4vci/credential")
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build());
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(),
                org.mockito.ArgumentMatchers.isNull())).thenReturn("test.jwt.token");

        preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        verify(accessTokenJwtUtil).generateSignedJwt(anyString(), anyString(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("https://issuer.com/oid4vci/credential"), anyInt(),
                org.mockito.ArgumentMatchers.isNull());
    }

    /** An entry written before the audience was stored keeps the configured legacy audience, as it always did. */
    @Test
    public void anEntryWithoutAStoredAudienceFallsBackToTheConfiguredAudience() throws Exception {
        String preAuthCode = "legacy-pre-auth-code";
        OAuthTokenRequest tokenRequest = tokenRequest(preAuthCode);
        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .issuer("legacy")
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build());
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(),
                org.mockito.ArgumentMatchers.isNull())).thenReturn("test.jwt.token");

        preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        verify(accessTokenJwtUtil).generateSignedJwt(anyString(), anyString(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("https://oauth.audience.com"), anyInt(),
                org.mockito.ArgumentMatchers.isNull());
    }

    // ---- the tenant an offer belongs to (M-09 review) ----------------------------------------------------------

    /** An offer created under path tenant {@code a} names and addresses that tenant's own surface. */
    @Test
    public void anOfferIsBoundToItsTenantAndThatTenantsAudience() {
        request.setIssuer("oid4vci");
        authorizationContext.setTenantId("a");

        preAuthorizedCodeService.createCredentialOffer(request);

        PreAuthCodeData codeData = capturedCodeData();
        Assert.assertEquals("a", codeData.getTenantId());
        Assert.assertEquals("https://issuer.com/t/a/oid4vci/credential", codeData.getAudience());
        Assert.assertEquals("https://issuer.com/t/a/oid4vci", capturedOffer().getCredentialIssuer());
    }

    /** Tenant A's code is refused at tenant B's token endpoint, without burning the code. */
    @Test
    public void aCodeOfOneTenantIsRefusedAtAnotherTenantsTokenEndpoint() {
        String preAuthCode = "tenant-a-pre-auth-code";
        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .issuer("oid4vci")
                .tenantId("a")
                .audience("https://issuer.com/t/a/oid4vci/credential")
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build());
        authorizationContext.setTenantId("b");

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest(preAuthCode)));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
        verify(vciCacheService, never()).claimPreAuthCode(anyString());
    }

    /** The same code at its own tenant's token endpoint is redeemed, with the audience stored at creation. */
    @Test
    public void aCodeOfOneTenantIsRedeemedAtItsOwnTenantsTokenEndpoint() {
        String preAuthCode = "tenant-a-pre-auth-code";
        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .issuer("oid4vci")
                .tenantId("a")
                .audience("https://issuer.com/t/a/oid4vci/credential")
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build());
        when(vciCacheService.claimPreAuthCode(preAuthCode)).thenReturn(true);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt(),
                org.mockito.ArgumentMatchers.isNull())).thenReturn("test.jwt.token");
        authorizationContext.setTenantId("a");

        preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest(preAuthCode));

        verify(accessTokenJwtUtil).generateSignedJwt(anyString(), anyString(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("https://issuer.com/t/a/oid4vci/credential"), anyInt(),
                org.mockito.ArgumentMatchers.isNull());
    }

    /** By value nothing points at a cached offer, so no unreachable entry is left behind. */
    @Test
    public void anOfferByValueIsNotCachedByReference() {
        request.setOfferByValue(true);

        preAuthorizedCodeService.createCredentialOffer(request);

        verify(vciCacheService, never()).setCredentialOffer(anyString(), any(io.mosip.certify.core.dto.CredentialOfferResponse.class));
    }

    private OAuthTokenRequest tokenRequest(String preAuthCode) {
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        return tokenRequest;
    }

    private io.mosip.certify.tenancy.TenancyProperties tenancy() {
        return new io.mosip.certify.tenancy.TenancyProperties(true, io.mosip.certify.tenancy.TenancyProperties.RESOLVER_PATH,
                Map.of("a", tenant(), "b", tenant()));
    }

    private io.mosip.certify.tenancy.TenancyProperties.Tenant tenant() {
        return new io.mosip.certify.tenancy.TenancyProperties.Tenant(List.of(), null, null, null, List.of(), List.of());
    }

    private PreAuthCodeData capturedCodeData() {
        org.mockito.ArgumentCaptor<PreAuthCodeData> stored = org.mockito.ArgumentCaptor.forClass(PreAuthCodeData.class);
        verify(vciCacheService).setPreAuthCodeData(anyString(), stored.capture());
        return stored.getValue();
    }

    private PreAuthorizedCodeService serviceWithDefaultIssuer(String defaultIssuer) {
        return new PreAuthorizedCodeService(vciCacheService, credentialRegistry, accessTokenJwtUtil, objectMapper,
                credentialConfigurationService, credentialConfigRepository, validator,
                new io.mosip.certify.oid4vci.Oid4vciProperties(
                        new io.mosip.certify.oid4vci.Oid4vciProperties.CompatCore(false),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.Notification(java.time.Duration.ofDays(1), java.time.Duration.ofHours(1)),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.Nonce(true),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.Batch(10),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.KeyAttestation(Map.of(), java.time.Duration.ofSeconds(60)),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.DidWebHolders(false, java.time.Duration.ofSeconds(5)),
                        new io.mosip.certify.oid4vci.Oid4vciProperties.Offers(
                                io.mosip.certify.oid4vci.OfferSurface.from(defaultIssuer))),
                oid4vciIssuers, authorizationContext);
    }

    private CredentialOfferResponse capturedOffer() {
        org.mockito.ArgumentCaptor<CredentialOfferResponse> stored = org.mockito.ArgumentCaptor.forClass(CredentialOfferResponse.class);
        verify(vciCacheService).setCredentialOffer(anyString(), stored.capture());
        return stored.getValue();
    }
}
