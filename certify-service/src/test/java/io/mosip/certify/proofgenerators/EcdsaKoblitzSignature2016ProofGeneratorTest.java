package io.mosip.certify.proofgenerators;

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The generator signs through the key provider; the detached JWS is checked with plain JCA. */
class EcdsaKoblitzSignature2016ProofGeneratorTest {

    static { Security.addProvider(new BouncyCastleProvider()); }

    final KeyProviderRegistry registry = TestKeyProviders.registry("app123/ref456", SignatureAlgorithm.ES256K);
    final EcdsaKoblitzSignature2016ProofGenerator proofGenerator = new EcdsaKoblitzSignature2016ProofGenerator();
    final Map<String, String> keyID = Map.of(Constants.APPLICATION_ID, "app123", Constants.REFERENCE_ID, "ref456");
    byte[] hash;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(proofGenerator, "keyProviders", registry);
        hash = MessageDigest.getInstance("SHA-256").digest("canonicalized document".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void nameAndCanonicalizer() {
        assertEquals("EcdsaKoblitzSignature2016", proofGenerator.getName());
        assertInstanceOf(URDNA2015Canonicalizer.class, proofGenerator.getCanonicalizer());
    }

    @Test
    void detachedJwsVerifiesWithJca() throws Exception {
        LdProof result = proofGenerator.generateProof(LdProof.builder().build(), Base64.getUrlEncoder().encodeToString(hash), keyID);
        SigningKey key = TestKeyProviders.provider(registry).resolve(KeyRef.parse("keymanager:app123/ref456"));

        String[] parts = result.getJws().split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[1], "payload segment is detached");
        com.nimbusds.jose.JWSHeader header = com.nimbusds.jose.JWSHeader.parse(new com.nimbusds.jose.util.Base64URL(parts[0]));
        assertEquals("ES256K", header.getAlgorithm().getName());
        assertFalse(header.isBase64URLEncodePayload());
        assertTrue(header.getCriticalParams().contains("b64"));
        assertNotNull(header.getX509CertSHA256Thumbprint(), "x5t#S256 as keymanager emitted");
        byte[] headerPart = (parts[0] + ".").getBytes(StandardCharsets.US_ASCII);
        byte[] signingInput = Arrays.copyOf(headerPart, headerPart.length + hash.length);
        System.arraycopy(hash, 0, signingInput, headerPart.length, hash.length);
        byte[] signature = new com.nimbusds.jose.util.Base64URL(parts[2]).decode();
        Signature verifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(key.descriptor().publicKey());
        verifier.update(signingInput);
        boolean ok = "SHA256withECDSA".equals("Ed25519") ? verifier.verify(signature)
                : verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature));
        assertTrue(ok, "detached jws must verify with JCA");
    }

    @Test
    void unknownKeyFails() {
        assertThrows(SigningException.class, () -> proofGenerator.generateProof(LdProof.builder().build(),
                Base64.getUrlEncoder().encodeToString(hash), Map.of(Constants.APPLICATION_ID, "nope", Constants.REFERENCE_ID, "")));
    }
}
