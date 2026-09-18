package io.mosip.certify.keyprovider.jca;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.CwtEnvelope;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.io.ByteArrayInputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** COSE_Sign1 structures are decoded with the CBOR library and verified with plain JCA, never with Certify code. */
class CoseEnvelopeTest {

    private static final JcaKeyProvider PROVIDER = JcaKeyProvider.devMode();
    private static final byte[] PAYLOAD = "mobile-security-object".getBytes();

    static boolean verify(CBORObject sign1, SigningKey key, SignatureAlgorithm alg) throws Exception {
        byte[] protectedBytes = sign1.get(0).GetByteString();
        byte[] payload = sign1.get(2).GetByteString();
        byte[] signature = sign1.get(3).GetByteString();
        byte[] toBeSigned = CoseEnvelope.sigStructure(protectedBytes, new byte[0], payload);
        Signature verifier = Signature.getInstance(alg.jcaName(), BouncyCastleProvider.PROVIDER_NAME);
        if (alg == SignatureAlgorithm.PS256) {
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        }
        verifier.initVerify(key.descriptor().publicKey());
        verifier.update(toBeSigned);
        byte[] jcaSignature = alg.isEc() ? ECDSA.transcodeSignatureToDER(signature) : signature;
        return verifier.verify(jcaSignature);
    }

    @Test
    void mdocIssuerAuthPolicyProducesUntaggedSign1WithX5chainAndVerifies() throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-es256"));
        byte[] encoded = CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), key, PROVIDER);

        CBORObject sign1 = CBORObject.DecodeFromBytes(encoded);
        assertFalse(sign1.isTagged());
        assertEquals(CBORType.Array, sign1.getType());
        assertEquals(4, sign1.size());
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
        assertEquals(-7, protectedHeader.get(CBORObject.FromObject(1)).AsInt32());
        CBORObject x5chain = sign1.get(1).get(CBORObject.FromObject(33));
        assertEquals(CBORType.ByteString, x5chain.getType(), "single certificate travels as one bstr");
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(x5chain.GetByteString()));
        assertEquals(key.chain().leaf().orElseThrow(), leaf);
        assertTrue(sign1.get(1).get(CBORObject.FromObject(4)) == null, "mdoc IssuerAuth carries no kid");
        assertTrue(verify(sign1, key, SignatureAlgorithm.ES256));
    }

    @Test
    void eddsaAndPs256Sign1Verify() throws Exception {
        for (String alias : new String[]{"dev-eddsa", "dev-ps256"}) {
            SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:" + alias));
            SignatureAlgorithm alg = key.algorithm();
            CBORObject sign1 = CBORObject.DecodeFromBytes(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), key, PROVIDER));
            CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
            assertEquals(alg.coseId(), protectedHeader.get(CBORObject.FromObject(1)).AsInt32());
            assertTrue(verify(sign1, key, alg), alias + " must verify");
        }
    }

    @Test
    void cwtIsTaggedSign1OverClaimsMap() throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-es256"));
        byte[] encoded = CwtEnvelope.sign(Map.of(1, "https://issuer.example", 169, "claim-169-payload"),
                CoseHeaderPolicy.cwt(), key, PROVIDER, true);
        CBORObject cwt = CBORObject.DecodeFromBytes(encoded);
        assertTrue(cwt.HasMostOuterTag(CwtEnvelope.TAG_CWT));
        CBORObject sign1 = cwt.UntagOne();
        assertTrue(sign1.HasMostOuterTag(CoseEnvelope.TAG_COSE_SIGN1));
        sign1 = sign1.UntagOne();
        CBORObject claims = CBORObject.DecodeFromBytes(sign1.get(2).GetByteString());
        assertEquals("https://issuer.example", claims.get(CBORObject.FromObject(1)).AsString());
        assertEquals("claim-169-payload", claims.get(CBORObject.FromObject(169)).AsString());
        assertEquals(key.kid(), new String(sign1.get(1).get(CBORObject.FromObject(4)).GetByteString()));
        assertTrue(verify(sign1, key, SignatureAlgorithm.ES256));
    }
}
