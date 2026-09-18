package io.mosip.certify.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TestKeyProviders;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenJwtUtilTest {

    final KeyProviderRegistry registry = TestKeyProviders.registry("CERTIFY_SERVICE", SignatureAlgorithm.RS256);
    final AccessTokenJwtUtil accessTokenJwtUtil = new AccessTokenJwtUtil();

    @Before
    public void setup() {
        ReflectionTestUtils.setField(accessTokenJwtUtil, "objectMapper", new ObjectMapper());
        ReflectionTestUtils.setField(accessTokenJwtUtil, "keyProviders", registry);
    }

    private IarSession session(String identityData, String scope) {
        IarSession session = new IarSession();
        session.setIdentityData(identityData);
        session.setScope(scope);
        session.setClientId("client-123");
        session.setAuthSession("auth-1");
        session.setTransactionId("txn-1");
        return session;
    }

    private SignedJWT verified(String jwt) throws Exception {
        SignedJWT signed = SignedJWT.parse(jwt);
        SigningKey key = TestKeyProviders.provider(registry).resolve(KeyRef.parse("keymanager:CERTIFY_SERVICE"));
        assertEquals("RS256", signed.getHeader().getAlgorithm().getName());
        assertEquals(key.kid(), signed.getHeader().getKeyID());
        assertNull("no typ, as keymanager's jwsSign emitted", signed.getHeader().getType());
        assertTrue("access token must verify with Nimbus", signed.verify(new RSASSAVerifier((RSAKey) key.descriptor().toJwk())));
        return signed;
    }

    @Test
    public void should_returnVerifiableJwt_when_rawParametersAreValid() throws Exception {
        String jwt = accessTokenJwtUtil.generateSignedJwt("subject-data", "test_scope", "client-123", "https://issuer", "https://audience", 300);

        JWTClaimsSet claims = verified(jwt).getJWTClaimsSet();
        assertEquals("https://issuer", claims.getIssuer());
        assertEquals("subject-data", claims.getSubject());
        assertEquals(List.of("https://audience"), claims.getAudience());
        assertEquals("test_scope", claims.getStringClaim("scope"));
        assertEquals("client-123", claims.getStringClaim("client_id"));
        assertNotNull(claims.getIssueTime());
        assertEquals(300_000L, claims.getExpirationTime().getTime() - claims.getIssueTime().getTime());
    }

    @Test
    public void should_returnVerifiableJwt_when_clientIdIsNull() throws Exception {
        String jwt = accessTokenJwtUtil.generateSignedJwt("subject-data", "test_scope", null, "https://issuer", "https://audience", 300);
        assertNull(verified(jwt).getJWTClaimsSet().getStringClaim("client_id"));
    }

    @Test
    public void should_returnVerifiableJwt_when_sessionIsValid() throws Exception {
        String jwt = accessTokenJwtUtil.generateSignedJwt(session("subject-data", "test_scope"), "https://issuer", "https://audience", 300);
        assertEquals("client-123", verified(jwt).getJWTClaimsSet().getStringClaim("client_id"));
    }

    @Test
    public void should_throwCertifyException_when_identityDataIsMissing() {
        CertifyException ex = assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("", "test_scope", "client-123", "https://issuer", "https://audience", 300));
        assertEquals("invalid_request", ex.getErrorCode());
    }

    @Test
    public void should_throwCertifyException_when_scopeIsMissing() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("subject-data", "", "client-123", "https://issuer", "https://audience", 300));
    }

    @Test
    public void should_throwCertifyException_when_sessionIdentityDataIsMissing() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt(session(null, "test_scope"), "https://issuer", "https://audience", 300));
    }

    @Test
    public void should_throwCertifyException_when_sessionScopeIsMissing() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt(session("subject-data", null), "https://issuer", "https://audience", 300));
    }

    @Test
    public void should_wrapAsUnknownError_when_serializationFails() throws Exception {
        ObjectMapper failing = org.mockito.Mockito.mock(ObjectMapper.class);
        org.mockito.Mockito.when(failing.writeValueAsString(org.mockito.ArgumentMatchers.any())).thenThrow(new JsonProcessingException("boom") {});
        ReflectionTestUtils.setField(accessTokenJwtUtil, "objectMapper", failing);
        CertifyException ex = assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("subject-data", "test_scope", "client-123", "https://issuer", "https://audience", 300));
        assertEquals("unknown_error", ex.getErrorCode());
    }

    @Test
    public void should_failClearly_when_serviceKeyIsMissing() {
        ReflectionTestUtils.setField(accessTokenJwtUtil, "keyProviders", TestKeyProviders.registry("OTHER", SignatureAlgorithm.RS256));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("subject-data", "test_scope", "client-123", "https://issuer", "https://audience", 300));
        assertEquals("unknown_error", ex.getErrorCode());
    }
}
