package io.mosip.certify.proofgenerators;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TestKeyProviders;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The generator signs through the key provider; the proof is checked with plain JCA / Nimbus, not with Certify code. */
class RSASignature2018ProofGeneratorTest {

    static { Security.addProvider(new BouncyCastleProvider()); }

    final KeyProviderRegistry registry = TestKeyProviders.registry("app123/ref456", SignatureAlgorithm.RS256);
    final RSASignature2018ProofGenerator proofGenerator = new RSASignature2018ProofGenerator();
    final Map<String, String> keyID = Map.of(Constants.APPLICATION_ID, "app123", Constants.REFERENCE_ID, "ref456");
    byte[] hash;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(proofGenerator, "keyProviders", registry);
        hash = MessageDigest.getInstance("SHA-256").digest("canonicalized document".getBytes());
    }

    static boolean verifyRaw(byte[] data, byte[] signature, SigningKey key, String jca) throws Exception {
        Signature verifier = Signature.getInstance(jca, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(key.descriptor().publicKey());
        verifier.update(data);
        return verifier.verify(jca.equals("Ed25519") ? signature : com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature));
    }

    @Test
    void nameAndCanonicalizer() {
        assertEquals("RsaSignature2018", proofGenerator.getName());
        assertInstanceOf(URDNA2015Canonicalizer.class, proofGenerator.getCanonicalizer());
    }

    @Test
    void proofVerifiesIndependently() throws Exception {
        LdProof result = proofGenerator.generateProof(LdProof.builder().build(), Base64.getUrlEncoder().encodeToString(hash), keyID);
        SigningKey key = TestKeyProviders.provider(registry).resolve(KeyRef.parse("keymanager:app123/ref456"));

        assertNotNull(result);
        // RFC 7797 detached JWS over binary bytes: rebuild the signing input (ASCII header + '.' + raw hash) and verify with
        // JCA, independent of any JOSE library's handling of the critical b64 header.
        String[] parts = result.getJws().split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[1], "payload segment is detached");
        com.nimbusds.jose.JWSHeader header = com.nimbusds.jose.JWSHeader.parse(new com.nimbusds.jose.util.Base64URL(parts[0]));
        assertEquals(JWSAlgorithm.RS256, header.getAlgorithm());
        assertFalse(header.isBase64URLEncodePayload());
        assertTrue(header.getCriticalParams().contains("b64"));
        assertNotNull(header.getX509CertSHA256Thumbprint(), "x5t#S256 as keymanager emitted");
        byte[] headerPart = (parts[0] + ".").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] signingInput = java.util.Arrays.copyOf(headerPart, headerPart.length + hash.length);
        System.arraycopy(hash, 0, signingInput, headerPart.length, hash.length);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key.descriptor().publicKey());
        verifier.update(signingInput);
        assertTrue(verifier.verify(new com.nimbusds.jose.util.Base64URL(parts[2]).decode()), "detached jws must verify with JCA");
    }

    @Test
    void unknownKeyFails() {
        assertThrows(SigningException.class, () -> proofGenerator.generateProof(LdProof.builder().build(),
                Base64.getUrlEncoder().encodeToString(hash), Map.of(Constants.APPLICATION_ID, "nope", Constants.REFERENCE_ID, "")));
    }
}
