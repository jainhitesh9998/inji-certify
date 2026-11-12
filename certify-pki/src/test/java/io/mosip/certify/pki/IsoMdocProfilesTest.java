package io.mosip.certify.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Annex B builders produce certificates and CRLs the validator accepts, and cap what Annex B caps. */
class IsoMdocProfilesTest {

    @Test
    void aGeneratedIacaDsAndCrlPassTheValidator() throws Exception {
        Fixture fixture = new Fixture();

        assertEquals(List.of(), AnnexBValidator.validateIaca(fixture.iaca));
        assertEquals(List.of(), AnnexBValidator.validateDs(fixture.ds, fixture.iaca));
        assertEquals(List.of(), AnnexBValidator.validateCrl(fixture.crl(), fixture.iaca));

        assertTrue(fixture.iaca.getSubjectX500Principal().equals(fixture.iaca.getIssuerX500Principal()), "self-signed");
        assertEquals(0, fixture.iaca.getBasicConstraints(), "CA pathLen 0");
        assertEquals(-1, fixture.ds.getBasicConstraints(), "no basicConstraints on a DS");
        assertEquals(List.of(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE), fixture.ds.getExtendedKeyUsage());
    }

    @Test
    void theDslInheritsCountryStateAndIssuerAltNameFromTheIaca() {
        Fixture fixture = new Fixture();
        assertEquals("IN", Certificates.attribute(fixture.ds.getSubjectX500Principal(), BCStyle.C));
        assertEquals("Karnataka", Certificates.attribute(fixture.ds.getSubjectX500Principal(), BCStyle.ST));
        assertEquals("Lorem Ipsum Demo DSC", Certificates.attribute(fixture.ds.getSubjectX500Principal(), BCStyle.CN));
        assertEquals(Certificates.issuerAltNames(fixture.iaca), Certificates.issuerAltNames(fixture.ds));
        assertEquals(List.of(Fixture.CRL_URI), Certificates.crlDistributionPointUris(fixture.ds));
        assertEquals(fixture.iaca.getSubjectX500Principal(), fixture.ds.getIssuerX500Principal());
        assertArrayEquals(Certificates.keyIdentifier(fixture.iaca), Certificates.authorityKeyIdentifier(fixture.ds));
    }

    @Test
    void validityIsCappedAtTheAnnexBLimits() {
        KeyPair keyPair = BadCerts.ec(256);
        X509Certificate longLivedIaca = IsoMdocProfiles.iaca(keyPair)
                .country("IN").commonName("Long lived").issuerAltUri("https://example.test/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(Instant.parse("2026-01-01T00:00:00Z"))
                .validity(Duration.ofDays(36_500))
                .build();
        assertEquals(IsoMdocProfiles.IACA_MAX_VALIDITY,
                Duration.between(longLivedIaca.getNotBefore().toInstant(), longLivedIaca.getNotAfter().toInstant()));

        KeyPair dsKeyPair = BadCerts.ec(256);
        X509Certificate longLivedDs = IsoMdocProfiles.ds(dsKeyPair, longLivedIaca, keyPair)
                .commonName("Long lived DSC")
                .notBefore(Instant.parse("2026-01-01T00:00:00Z"))
                .validity(Duration.ofDays(1_000))
                .build();
        assertEquals(IsoMdocProfiles.DS_MAX_VALIDITY,
                Duration.between(longLivedDs.getNotBefore().toInstant(), longLivedDs.getNotAfter().toInstant()));
    }

    @Test
    void everyCurveSignsWithTheMatchingEcdsaAlgorithm() {
        assertEquals("SHA256withECDSA", signatureAlgorithm(256));
        assertEquals("SHA384withECDSA", signatureAlgorithm(384));
        assertEquals("SHA512withECDSA", signatureAlgorithm(521));
    }

    private static String signatureAlgorithm(int bits) {
        Fixture fixture = new Fixture(bits);
        assertEquals(List.of(), AnnexBValidator.validateIaca(fixture.iaca));
        assertEquals(List.of(), AnnexBValidator.validateDs(fixture.ds, fixture.iaca));
        return fixture.iaca.getSigAlgName();
    }

    @Test
    void aDocumentSignerForThePublicKeyOfACsrIsBuiltFromThatKey() throws Exception {
        Fixture fixture = new Fixture();
        KeyPair externalKeyPair = BadCerts.ec(256);
        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=External DSC"), externalKeyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BadCerts.BC)
                        .build(externalKeyPair.getPrivate()));

        Csr csr = Csr.parse(request.getEncoded());
        assertEquals("CN=External DSC", csr.subject().getName());
        assertArrayEquals(externalKeyPair.getPublic().getEncoded(), csr.publicKey().getEncoded());

        X509Certificate certificate = IsoMdocProfiles.ds(csr.publicKey(), fixture.iaca, fixture.iacaKeyPair)
                .commonName("External DSC")
                .build();
        assertArrayEquals(externalKeyPair.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
        assertEquals(List.of(), AnnexBValidator.validateDs(certificate, fixture.iaca));
    }

    @Test
    void theCrlCarriesTheRevokedSerialAndItsReason() {
        Fixture fixture = new Fixture();
        Instant revokedAt = Instant.parse("2026-02-03T04:05:06Z");
        X509CRL crl = fixture.crl(BigInteger.valueOf(42), revokedAt);

        assertEquals(42, crl.getRevokedCertificate(BigInteger.valueOf(42)).getSerialNumber().intValue());
        assertEquals(2, crl.getVersion(), "X.509 v2");
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, fixture.iaca));
    }

    @Test
    void mandatoryInputsAreRefusedWithTheRuleThatNeedsThem() {
        KeyPair keyPair = BadCerts.ec(256);
        assertRule("IACA_SUBJECT_COUNTRY_MISSING", () -> IsoMdocProfiles.iaca(keyPair)
                .commonName("No country").issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_COUNTRY_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("India")
                .commonName("Bad country").issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_CN_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_ISSUER_ALT_NAME_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("No alt name").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_CRL_DP_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("No CRL DP").issuerAltUri("https://example.test").build());

        Fixture fixture = new Fixture();
        assertRule("DS_SUBJECT_CN_MISSING", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair).build());
        assertRule("IACA_KEY_MISMATCH", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, BadCerts.ec(256))
                .commonName("Wrong IACA key").build());
    }

    private static void assertRule(String ruleId, Runnable action) {
        PkiException exception = assertThrows(PkiException.class, action::run);
        assertTrue(exception.getMessage().startsWith(ruleId + ":"),
                () -> "expected " + ruleId + ", got " + exception.getMessage());
    }

    @Test
    void serialsArePositiveShortAndRandom() {
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            BigInteger serial = Serials.random();
            assertTrue(Serials.fits(serial), "positive and at most 20 octets: " + serial);
            assertTrue(serial.bitLength() >= 63, "at least 63 random bits: " + serial.bitLength());
            assertTrue(seen.add(serial), "serials do not repeat");
        }
        assertTrue(Serials.fits(BigInteger.ONE));
        assertTrue(!Serials.fits(BigInteger.ONE.shiftLeft(160)), "21 octets is too long");
        assertTrue(!Serials.fits(BigInteger.valueOf(-1)), "a negative serial is refused");
    }

    @Test
    void aCsrWithABrokenSignatureIsRefused() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);
        byte[] der = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Corrupt"),
                keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BadCerts.BC).build(keyPair.getPrivate()))
                .getEncoded();
        der[der.length - 1] ^= 0xff;

        PkiException exception = assertThrows(PkiException.class, () -> Csr.parse(der));
        assertTrue(exception.getMessage().startsWith("CSR_SIGNATURE_INVALID"), exception.getMessage());
        assertThrows(PkiException.class, () -> Csr.parse("not a request".getBytes()));
        assertThrows(PkiException.class, () -> Csr.parse(new byte[0]));
    }

    @Test
    void pemRoundTripsCertificatesKeysCsrsAndCrls() throws Exception {
        Fixture fixture = new Fixture();
        X509CRL crl = fixture.crl();

        List<X509Certificate> chain = Pem.readCertificates(Pem.writeCertificates(List.of(fixture.ds, fixture.iaca)));
        assertEquals(2, chain.size());
        assertEquals(fixture.ds, chain.get(0));
        assertEquals(fixture.iaca, chain.get(1));
        assertEquals(fixture.ds, Pem.readCertificate(Pem.writeCertificate(fixture.ds)));
        assertEquals(crl, Pem.readCrl(Pem.writeCrl(crl)));

        KeyPair keyPair = BadCerts.ec(256);
        java.security.PrivateKey readBack = Pem.readPrivateKey(Pem.writePrivateKey(keyPair.getPrivate()));
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
        signer.initSign(readBack);
        signer.update("pem".getBytes());
        byte[] signature = signer.sign();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update("pem".getBytes());
        assertTrue(verifier.verify(signature), "the private key read back signs for the same key pair");
        assertArrayEquals(keyPair.getPublic().getEncoded(), Pem.readPublicKey(Pem.writePublicKey(keyPair.getPublic())).getEncoded());

        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Pem CSR"),
                keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BadCerts.BC).build(keyPair.getPrivate()));
        Csr csr = Pem.readCsr(Pem.writeCsr(request));
        assertEquals("CN=Pem CSR", csr.subject().getName());
        assertThrows(PkiException.class, () -> Pem.readCertificate(Pem.writeCrl(crl)));
        assertThrows(PkiException.class, () -> Pem.readCrl(Pem.writeCertificate(fixture.iaca)));
    }

    @Test
    void aCrlWithNextUpdateBeforeThisUpdateIsRefused() {
        Fixture fixture = new Fixture();
        Instant now = Instant.now();
        PkiException exception = assertThrows(PkiException.class, () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .thisUpdate(now)
                .nextUpdate(now.minus(Duration.ofDays(1)))
                .build());
        assertTrue(exception.getMessage().startsWith("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE"), exception.getMessage());
    }
}
