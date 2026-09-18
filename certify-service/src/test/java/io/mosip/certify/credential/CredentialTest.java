package io.mosip.certify.credential;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.credential.Credential;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.certify.vcformatters.VCFormatter;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CredentialTest {

    private VCFormatter mockFormatter;
    private SignatureService mockSignatureService;
    private Credential credential;

    @Before
    public void setUp() {
        mockFormatter = mock(VCFormatter.class);
        mockSignatureService = mock(SignatureService.class);

        // Minimal subclass of Credential to allow testing
        credential = new Credential(mockFormatter, mockSignatureService) {
            @Override
            public boolean canHandle(String format) {
                return false;
            }
        };
        ReflectionTestUtils.setField(credential, "keyProviders", io.mosip.certify.signing.TestKeyProviders.registry("app-1/ref-1", io.mosip.certify.signing.SignatureAlgorithm.ES256));
        ReflectionTestUtils.setField(credential, "cwtSigning", new io.mosip.certify.signing.CwtSigningProperties(180, 0));
    }

    @Test
    public void testAddProofInBaseCredentialClass() {
        JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
        responseDto.setJwtSignedData("signed.jwt.token");

        when(mockSignatureService.jwsSign(any(JWSSignatureRequestDto.class)))
                .thenReturn(responseDto);

        VCResult<?> result = credential.addProof(
                "unsignedVC",
                null,
                "RS256",
                "testAppId",
                "testRefId",
                "https://example.com/pubkey",
                "Ed25519Signature2020"
        );

        assertNotNull(result);
        assertEquals("vc", result.getFormat());
        assertEquals("signed.jwt.token", result.getCredential());
    }

    @Test
    public void testSignQRData_ProducesAVerifiableClaim169Cwt() throws Exception {
        String result = credential.signQRData("{\"4\":\"Golden Farmer\",\"8\":\"1990-01-01\"}", "ES256", "app-1", "ref-1", "did:example:123");

        com.upokecenter.cbor.CBORObject outer = com.upokecenter.cbor.CBORObject.DecodeFromBytes(java.util.HexFormat.of().parseHex(result));
        assertTrue(outer.HasMostOuterTag(61));
        com.upokecenter.cbor.CBORObject sign1 = outer.UntagOne();
        assertTrue(sign1.HasMostOuterTag(18));
        sign1 = sign1.UntagOne();
        byte[] protectedBytes = sign1.get(0).GetByteString();
        com.upokecenter.cbor.CBORObject protectedHeader = com.upokecenter.cbor.CBORObject.DecodeFromBytes(protectedBytes);
        assertEquals(-7, protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32());
        assertEquals("app-1/ref-1", new String(protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(4)).GetByteString()));
        assertEquals(0, sign1.get(1).size());
        com.upokecenter.cbor.CBORObject claims = com.upokecenter.cbor.CBORObject.DecodeFromBytes(sign1.get(2).GetByteString());
        assertEquals("[1, 4, 5, 6, 169]", claims.getKeys().toString());
        assertEquals("did:example:123", claims.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsString());
        long iat = claims.get(com.upokecenter.cbor.CBORObject.FromObject(6)).AsInt64Value();
        assertEquals(iat + 180L * 86400, claims.get(com.upokecenter.cbor.CBORObject.FromObject(4)).AsInt64Value());
        assertEquals(iat, claims.get(com.upokecenter.cbor.CBORObject.FromObject(5)).AsInt64Value());
        com.upokecenter.cbor.CBORObject claim169 = com.upokecenter.cbor.CBORObject.DecodeFromBytes(claims.get(com.upokecenter.cbor.CBORObject.FromObject(169)).GetByteString());
        assertEquals("Golden Farmer", claim169.get(com.upokecenter.cbor.CBORObject.FromObject(4)).AsString());
        byte[] sigStructure = com.upokecenter.cbor.CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(sign1.get(2).GetByteString()).EncodeToBytes();
        java.security.PublicKey publicKey = ((io.mosip.certify.issuance.KeyProviderRegistry) ReflectionTestUtils.getField(credential, "keyProviders"))
                .provider("keymanager").resolve(io.mosip.certify.signing.KeyRef.parse("keymanager:app-1/ref-1")).descriptor().publicKey();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(sigStructure);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(sign1.get(3).GetByteString())));
    }

    @Test(expected = io.mosip.certify.core.exception.CertifyException.class)
    public void testSignQRData_UnknownAlgorithmIsRejected() {
        credential.signQRData("{}", "HS256", "app-1", "ref-1", "did");
    }

    @Test(expected = RuntimeException.class)
    public void testSignQRData_MissingKeyIsPropagated() {
        credential.signQRData("{}", "ES256", "nope", "ref", "did");
    }
}
