package io.mosip.certify.signing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlgorithmRegistryTest {

    @Test
    void joseAndCoseIdentifiersAgree() {
        assertEquals(SignatureAlgorithm.ES256, AlgorithmRegistry.byJose("ES256").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256, AlgorithmRegistry.byCose(-7).orElseThrow());
        assertEquals(SignatureAlgorithm.EdDSA, AlgorithmRegistry.byCose(-8).orElseThrow());
        assertEquals(SignatureAlgorithm.RS256, AlgorithmRegistry.byCose(-257).orElseThrow());
        assertEquals(SignatureAlgorithm.PS256, AlgorithmRegistry.byCose(-37).orElseThrow());
        assertEquals(SignatureAlgorithm.ES256K, AlgorithmRegistry.byCose(-47).orElseThrow());
        assertTrue(AlgorithmRegistry.byJose("HS256").isEmpty());
    }

    @Test
    void legacySuitesAndCryptosuitesMapToOneAlgorithm() {
        // the same table that mosip.certify.credential-config.credential-signing-alg-values-supported holds today
        assertEquals(SignatureAlgorithm.RS256, AlgorithmRegistry.bySuite("RsaSignature2018").orElseThrow());
        assertEquals(SignatureAlgorithm.EdDSA, AlgorithmRegistry.bySuite("Ed25519Signature2018").orElseThrow());
        assertEquals(SignatureAlgorithm.EdDSA, AlgorithmRegistry.bySuite("Ed25519Signature2020").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256K, AlgorithmRegistry.bySuite("EcdsaKoblitzSignature2016").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256K, AlgorithmRegistry.bySuite("EcdsaSecp256k1Signature2019").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256, AlgorithmRegistry.bySuite("EcdsaSecp256r1Signature2019").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256, AlgorithmRegistry.bySuite("ecdsa-rdfc-2019").orElseThrow());
        assertEquals(SignatureAlgorithm.ES256, AlgorithmRegistry.bySuite("ecdsa-jcs-2019").orElseThrow());
        assertEquals(SignatureAlgorithm.EdDSA, AlgorithmRegistry.bySuite("eddsa-rdfc-2022").orElseThrow());
        assertEquals(SignatureAlgorithm.EdDSA, AlgorithmRegistry.bySuite("eddsa-jcs-2022").orElseThrow());
        assertTrue(AlgorithmRegistry.bySuite("nope").isEmpty());
        assertTrue(AlgorithmRegistry.isLegacyLdSuite("Ed25519Signature2020"));
        assertFalse(AlgorithmRegistry.isLegacyLdSuite("eddsa-rdfc-2022"));
        assertTrue(AlgorithmRegistry.isDataIntegrityCryptosuite("eddsa-rdfc-2022"));
        assertEquals(2, AlgorithmRegistry.cryptosuitesFor(SignatureAlgorithm.EdDSA).size());
        assertEquals(2, AlgorithmRegistry.ldSuitesFor(SignatureAlgorithm.EdDSA).size());
    }

    @Test
    void jcaNamesAndSignatureFormats() {
        assertEquals("SHA256withECDSA", SignatureAlgorithm.ES256.jcaName());
        assertEquals(64, SignatureAlgorithm.ES256.concatLength());
        assertEquals(96, SignatureAlgorithm.ES384.concatLength());
        assertEquals(132, SignatureAlgorithm.ES512.concatLength());
        assertEquals(SignatureAlgorithm.SignatureFormat.PSS, SignatureAlgorithm.PS256.format());
        assertEquals(SignatureAlgorithm.SignatureFormat.RAW, SignatureAlgorithm.EdDSA.format());
        assertTrue(SignatureAlgorithm.RS256.isRsa());
        assertTrue(SignatureAlgorithm.ES256K.isEc());
    }
}
