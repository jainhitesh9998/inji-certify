package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.oid4vci.Oid4vciProperties;
import io.mosip.certify.spi.ProofValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Key attestation JWTs (OpenID4VCI 1.0 Appendix D) against configured attesters: a JWK Set, or an x5c chain to a PEM trust anchor. */
class KeyAttestationValidatorTest {

    static final Instant NOW = Instant.parse("2026-09-19T10:00:00Z");
    final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    final ECKey attester = generate("wp-1");
    final ECKey holder = generate(null);
    final KeyAttestationValidator validator = new KeyAttestationValidator(new Oid4vciProperties.KeyAttestation(
            Map.of("wallet-provider", new Oid4vciProperties.Attester(new JWKSet(attester.toPublicJWK()).toString(), null)), Duration.ofSeconds(60)), clock);

    @Test
    void verifiesAnAttestationFromAConfiguredJwkSet() throws Exception {
        KeyAttestationValidator.KeyAttestation attested = validator.validate(attestation(attester, "key-attestation+jwt", NOW.plusSeconds(300), List.of("iso_18045_high"), "n-1"),
                List.of("ES256"), Map.of("key_storage", List.of("iso_18045_high")), true);
        assertEquals(1, attested.attestedKeys().size());
        assertTrue(attested.attests(holder));
        assertEquals("n-1", attested.nonce());
        assertEquals(List.of("iso_18045_high"), attested.keyStorage());
    }

    @Test
    void refusesTheWrongTypAlgorithmSignerAndExpiry() throws Exception {
        assertRefused(attestation(attester, "JWT", NOW.plusSeconds(300), List.of("iso_18045_high"), null), List.of("ES256"), null, true, "typ");
        assertRefused(attestation(attester, "key-attestation+jwt", NOW.plusSeconds(300), List.of("iso_18045_high"), null), List.of("EdDSA"), null, true, "alg");
        assertRefused(attestation(generate("wp-1"), "key-attestation+jwt", NOW.plusSeconds(300), List.of("iso_18045_high"), null), List.of("ES256"), null, true, "trusted attester");
        assertRefused(attestation(attester, "key-attestation+jwt", NOW.minusSeconds(120), List.of("iso_18045_high"), null), List.of("ES256"), null, true, "expired");
        assertRefused(attestation(attester, "key-attestation+jwt", null, List.of("iso_18045_high"), null), List.of("ES256"), null, true, "exp");
        // exp is optional with the attestation proof type
        validator.validate(attestation(attester, "key-attestation+jwt", null, List.of("iso_18045_high"), null), List.of("ES256"), null, false);
    }

    @Test
    void checksTheAcceptedAttackPotentialResistance() throws Exception {
        String attestation = attestation(attester, "key-attestation+jwt", NOW.plusSeconds(300), List.of("iso_18045_basic"), null);
        assertRefused(attestation, List.of("ES256"), Map.of("key_storage", List.of("iso_18045_high", "iso_18045_moderate")), true, "key_storage");
        assertRefused(attestation, List.of("ES256"), Map.of("user_authentication", List.of("iso_18045_high")), true, "user_authentication");
        // an empty requirement only asks for an attestation
        validator.validate(attestation, List.of("ES256"), Map.of(), true);
        validator.validate(attestation, List.of("ES256"), Map.of("key_storage", List.of("iso_18045_basic")), true);
    }

    @Test
    void refusesAttestationsWithoutKeysOrWithPrivateKeys() throws Exception {
        JWTClaimsSet none = new JWTClaimsSet.Builder().issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300))).claim("attested_keys", List.of()).build();
        assertRefused(sign(attester, "key-attestation+jwt", none), List.of("ES256"), null, true, "attested_keys");
        JWTClaimsSet secret = new JWTClaimsSet.Builder().issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))
                .claim("attested_keys", List.of(holder.toJSONObject())).build();
        assertRefused(sign(attester, "key-attestation+jwt", secret), List.of("ES256"), null, true, "private");
    }

    @Test
    void verifiesAnX5cChainToAConfiguredTrustAnchor() throws Exception {
        ECKey ca = generate("ca");
        ECKey leaf = generate("leaf");
        X509Certificate caCertificate = certificate(ca, ca, "CN=Wallet Provider CA", true);
        X509Certificate leafCertificate = certificate(leaf, ca, "CN=Wallet Provider Attester", false);
        KeyAttestationValidator anchored = new KeyAttestationValidator(new Oid4vciProperties.KeyAttestation(
                Map.of("wallet-provider", new Oid4vciProperties.Attester(null, pem(caCertificate))), Duration.ofSeconds(60)), clock);
        JWTClaimsSet claims = claims(NOW.plusSeconds(300), List.of("iso_18045_high"), null);
        SignedJWT chained = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("key-attestation+jwt"))
                .x509CertChain(List.of(Base64.encode(leafCertificate.getEncoded()))).build(), claims);
        chained.sign(new ECDSASigner(leaf));
        assertTrue(anchored.validate(chained.serialize(), List.of("ES256"), null, true).attests(holder));

        X509Certificate stray = certificate(leaf, leaf, "CN=Self-signed", true);
        SignedJWT selfSigned = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("key-attestation+jwt"))
                .x509CertChain(List.of(Base64.encode(stray.getEncoded()))).build(), claims);
        selfSigned.sign(new ECDSASigner(leaf));
        ProofValidationException refused = assertThrows(ProofValidationException.class, () -> anchored.validate(selfSigned.serialize(), List.of("ES256"), null, true));
        assertEquals("invalid_proof", refused.getErrorCode());
        // an x5c attestation against a deployment that only trusts a JWK Set
        ProofValidationException noAnchor = assertThrows(ProofValidationException.class, () -> validator.validate(chained.serialize(), List.of("ES256"), null, true));
        assertEquals("invalid_proof", noAnchor.getErrorCode());
    }

    private void assertRefused(String attestation, List<String> algorithms, Map<String, Object> required, boolean expRequired, String reason) {
        ProofValidationException e = assertThrows(ProofValidationException.class, () -> validator.validate(attestation, algorithms, required, expRequired), reason);
        assertEquals("invalid_proof", e.getErrorCode(), reason);
        assertTrue(e.getMessage().toLowerCase().contains(reason.toLowerCase()), reason + " but was: " + e.getMessage());
    }

    private String attestation(ECKey signer, String typ, Instant expiresAt, List<String> keyStorage, String nonce) throws Exception {
        return sign(signer, typ, claims(expiresAt, keyStorage, nonce));
    }

    private JWTClaimsSet claims(Instant expiresAt, List<String> keyStorage, String nonce) {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("https://wallet-provider.example").issueTime(Date.from(NOW))
                .claim("attested_keys", List.of(holder.toPublicJWK().toJSONObject())).claim("key_storage", keyStorage);
        if (expiresAt != null) {
            claims.expirationTime(Date.from(expiresAt));
        }
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }
        return claims.build();
    }

    private static String sign(ECKey signer, String typ, JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ)).keyID(signer.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(signer));
        return jwt.serialize();
    }

    private static X509Certificate certificate(ECKey subject, ECKey issuer, String subjectName, boolean ca) throws Exception {
        String issuerName = issuer == subject ? subjectName : "CN=Wallet Provider CA";
        KeyPair subjectPair = subject.toKeyPair();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuerName), BigInteger.valueOf(System.nanoTime()),
                Date.from(NOW.minusSeconds(3600)), Date.from(NOW.plusSeconds(86400)), new X500Name(subjectName), subjectPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.toKeyPair().getPrivate())));
    }

    private static String pem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()) + "\n-----END CERTIFICATE-----\n";
    }

    static ECKey generate(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
