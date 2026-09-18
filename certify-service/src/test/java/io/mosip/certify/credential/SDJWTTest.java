package io.mosip.certify.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDtoV2;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SDJWTTest {

    @Mock
    private VCFormatter mockFormatter;

    @Mock
    private SignatureService mockSignatureService;

    private ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private SDJWT sdjwt;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(sdjwt, "objectMapper", objectMapper);
    }

    @Test
    public void testCanHandle_ShouldReturnTrueForCorrectFormat() {
        assertTrue(sdjwt.canHandle(VCFormats.DC_SD_JWT));
    }

    @Test
    public void testCanHandle_ShouldReturnFalseForIncorrectFormat() {
        assertFalse(sdjwt.canHandle(VCFormats.LDP_VC));
    }

    @Test
    public void testCreateCredential_WithValidInput_ReturnsSdJwt() throws JsonProcessingException {
        String mockTemplateName = "mockTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        String templateJson = "{\"name\": \"John\", \"age\": 30}";
        when(mockFormatter.format(any(Map.class))).thenReturn(templateJson);
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.name"));

        String result = sdjwt.createCredential(templateParams, mockTemplateName);

        assertNotNull(result);
        assertTrue(result.contains("~"));
    }

    @Test
    public void should_throwCertifyException_when_sdClaimPathIsMissing() throws JsonProcessingException {
        String mockTemplateName = "mockTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        String templateJson = "{\"name\": \"John\", \"age\": 30}";
        when(mockFormatter.format(any(Map.class))).thenReturn(templateJson);
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.invalid_claim"));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            sdjwt.createCredential(templateParams, mockTemplateName);
        });

        assertEquals(ErrorConstants.SD_CLAIMS_PARSE_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("SD-Claim path '$.invalid_claim' not found in the credential template."));
    }

    @Test
    public void should_throwCertifyException_when_templatedJsonIsMalformed() throws JsonProcessingException {
        String mockTemplateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(mockFormatter.format(any(Map.class))).thenReturn("{invalid json}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.invalid"));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            sdjwt.createCredential(templateParams, mockTemplateName);
        });

        assertEquals(ErrorConstants.JSON_PROCESSING_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Failed to process JSON during SD-JWT creation."));
    }

    @Test
    public void testAddProof_SignsIssuerJwsThroughTheKeyProvider() throws Exception {
        io.mosip.certify.issuance.KeyProviderRegistry registry = io.mosip.certify.signing.TestKeyProviders.registry("appID/refID", io.mosip.certify.signing.SignatureAlgorithm.ES256);
        ReflectionTestUtils.setField(sdjwt, "keyProviders", registry);
        String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"vct\":\"Farmer\"}".getBytes());
        String unsignedVC = "eyJhbGciOiJub25lIn0." + payload + "~disclosure";

        VCResult<?> result = sdjwt.addProof(unsignedVC, null, "ES256", "appID", "refID", "url", null);

        String credential = (String) result.getCredential();
        assertTrue(credential.endsWith("~disclosure"));
        com.nimbusds.jose.JWSObject jws = com.nimbusds.jose.JWSObject.parse(credential.substring(0, credential.indexOf('~')));
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertEquals("ES256", jws.getHeader().getAlgorithm().getName());
        assertNotNull(jws.getHeader().getKeyID());
        assertNotNull("x5c as keymanager's jwsSignV2 emitted", jws.getHeader().getX509CertChain());
        assertNotNull(jws.getHeader().getX509CertSHA256Thumbprint());
        assertEquals("{\"vct\":\"Farmer\"}", jws.getPayload().toString());
        com.nimbusds.jose.jwk.ECKey ec = (com.nimbusds.jose.jwk.ECKey) registry.provider("keymanager").resolve(io.mosip.certify.signing.KeyRef.parse("keymanager:appID/refID")).descriptor().toJwk();
        com.nimbusds.jose.crypto.ECDSAVerifier verifier = new com.nimbusds.jose.crypto.ECDSAVerifier(ec);
        verifier.getJCAContext().setProvider(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
        assertTrue("issuer JWS must verify with Nimbus", jws.verify(verifier));
    }

    @Test
    public void testAddProof_RejectsUnknownAlgorithm() {
        ReflectionTestUtils.setField(sdjwt, "keyProviders", io.mosip.certify.signing.TestKeyProviders.registry("appID/refID", io.mosip.certify.signing.SignatureAlgorithm.ES256));
        CertifyException e = assertThrows(CertifyException.class, () -> sdjwt.addProof("h.p~d", null, "HS256", "appID", "refID", "url", null));
        assertEquals(ErrorConstants.VC_SIGNING_ERROR, e.getErrorCode());
    }
}
