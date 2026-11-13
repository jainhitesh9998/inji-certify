package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Annex B builders produce certificates and CRLs the validator accepts, and refuse what the profile cannot hold. */
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
        assertEquals(3, fixture.iaca.getVersion(), "v3");
        assertEquals(3, fixture.ds.getVersion(), "v3");
    }

    @Test
    void theDsInheritsCountryStateAndIssuerAltNameFromTheIaca() {
        Fixture fixture = new Fixture();
        assertEquals("IN", Certificates.attribute(Certificates.subject(fixture.ds), BCStyle.C));
        assertEquals("Karnataka", Certificates.attribute(Certificates.subject(fixture.ds), BCStyle.ST));
        assertEquals("Lorem Ipsum Demo DSC", Certificates.attribute(Certificates.subject(fixture.ds), BCStyle.CN));
        assertEquals(Certificates.issuerAltNames(fixture.iaca), Certificates.issuerAltNames(fixture.ds));
        assertEquals(List.of(Fixture.CRL_URI), Certificates.crlDistributionPointUris(fixture.ds));
        assertArrayEquals(Certificates.der(Certificates.subject(fixture.iaca)),
                Certificates.der(Certificates.issuer(fixture.ds)),
                "the DS issuer is the IACA subject DER, byte for byte");
        assertArrayEquals(Certificates.keyIdentifier(fixture.iaca), Certificates.authorityKeyIdentifier(fixture.ds));
    }

    /**
     * A subject value with a comma is the case RFC 4514 escaping breaks: copying it through a string would turn
     * {@code Foo, Bar} into {@code Foo\, Bar} and the DS subject would no longer equal the IACA's.
     */
    @Test
    void aDsCopiesTheIacaCountryAndStateWithoutReEncodingThem() throws Exception {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").state("Foo, Bar").organization("Lorem, Ipsum Demo")
                .commonName("Lorem Ipsum Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .build();
        X509Certificate ds = IsoMdocProfiles.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .commonName("Lorem Ipsum Demo DSC, 2026")
                .build();

        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca));
        assertEquals(List.of(), AnnexBValidator.validateDs(ds, iaca));

        ASN1Encodable iacaState = onlyValue(iaca, BCStyle.ST);
        ASN1Encodable dsState = onlyValue(ds, BCStyle.ST);
        assertEquals(iacaState.getClass(), dsState.getClass(), "the state keeps its ASN.1 string type");
        assertArrayEquals(iacaState.toASN1Primitive().getEncoded(), dsState.toASN1Primitive().getEncoded(),
                "the state keeps its bytes");
        assertEquals("Foo, Bar", Certificates.string(dsState), "the value is not escaped");

        ASN1Encodable iacaCountry = onlyValue(iaca, BCStyle.C);
        ASN1Encodable dsCountry = onlyValue(ds, BCStyle.C);
        assertArrayEquals(iacaCountry.toASN1Primitive().getEncoded(), dsCountry.toASN1Primitive().getEncoded(),
                "the country keeps its bytes");
        assertEquals("Lorem Ipsum Demo DSC, 2026",
                Certificates.attribute(Certificates.subject(ds), BCStyle.CN));
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

    /** This module allows P-256/384/521 only (decision log, 2026-11-13); brainpool and explicit parameters are refused, not written. */
    @Test
    void keysOutsideTheCurveAllowlistAreRefused() {
        Fixture fixture = new Fixture();
        KeyPair brainpool = BadCerts.brainpool();
        assertRule("IACA_KEY_INVALID", () -> iaca(brainpool));
        assertRule("DS_KEY_INVALID", () -> IsoMdocProfiles.ds(brainpool, fixture.iaca, fixture.iacaKeyPair)
                .commonName("Brainpool DSC").build());

        KeyPair explicit = BadCerts.ec(256);
        SubjectPublicKeyInfo explicitSpki = BadCerts.explicitParameters(explicit.getPublic());
        assertRule("DS_KEY_INVALID", () -> IsoMdocProfiles.ds(BadCerts.explicitParametersKey(explicit), fixture.iaca,
                fixture.iacaKeyPair).commonName("Explicit DSC").build());
        assertRule("IACA_KEY_INVALID", () -> IsoMdocProfiles.iaca(new KeyPair(
                BadCerts.explicitParametersKey(explicit), explicit.getPrivate()))
                .country("IN").commonName("Explicit IACA").issuerAltUri("https://example.test")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("CSR_KEY_INVALID", () -> Csr.parse(csr(explicit, explicitSpki, "SHA256withECDSA")));

        // a compressed point cannot survive a JCA PublicKey (every encoder writes it uncompressed), so it is refused
        // where it can arrive: a CSR's subjectPublicKeyInfo and a certificate under validation
    }

    /** A CSR's point must decode to a finite point on its curve; the proof of possession is not even tried otherwise. */
    @Test
    void aCsrWhosePointIsNotOnTheCurveIsRefused() {
        KeyPair keyPair = BadCerts.ec(256);
        assertRule("CSR_KEY_INVALID", () -> Csr.parse(csr(keyPair, BadCerts.zeroPoint(), "SHA256withECDSA")));
        assertRule("CSR_KEY_INVALID", () -> Csr.parse(csr(keyPair,
                BadCerts.p256Point(BigInteger.ONE, BigInteger.ONE), "SHA256withECDSA")));
        assertRule("CSR_KEY_INVALID", () -> Csr.parse(csr(keyPair,
                BadCerts.p256Point(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), BigInteger.ONE), "SHA256withECDSA")));
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

    /** A CSR is untrusted input: its signature algorithm must be ECDSA/SHA-2 and match the key it carries. */
    @Test
    void aCsrOutsideTheProfileIsRefused() {
        KeyPair keyPair = BadCerts.ec(256);
        assertRule("CSR_SIGNATURE_ALGORITHM_INVALID",
                () -> Csr.parse(csr(keyPair, BadCerts.spki(keyPair.getPublic()), "SHA1withECDSA")));
        assertRule("CSR_SIGNATURE_ALGORITHM_INVALID", () -> Csr.parse(BadCerts.csrWithSignatureAlgorithm(
                csr(keyPair, BadCerts.spki(keyPair.getPublic()), "SHA256withECDSA"),
                "1.2.840.113549.1.1.1", "SHA256withECDSA", keyPair.getPrivate())));
        assertRule("CSR_SIGNATURE_ALGORITHM_MISMATCH",
                () -> Csr.parse(csr(keyPair, BadCerts.spki(keyPair.getPublic()), "SHA384withECDSA")));
        KeyPair compressed = BadCerts.bcEc(256);
        assertRule("CSR_KEY_INVALID",
                () -> Csr.parse(csr(compressed, BadCerts.compressed(compressed), "SHA256withECDSA")));
    }

    @Test
    void validityBeyondTheAnnexBLimitsIsRefused() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        assertRule("IACA_VALIDITY_TOO_LONG", () -> iaca(iacaKeyPair, Duration.ofDays(36_500)));
        assertRule("IACA_VALIDITY_INVALID", () -> iaca(iacaKeyPair, Duration.ZERO));
        assertRule("IACA_VALIDITY_INVALID", () -> iaca(iacaKeyPair, Duration.ofDays(-1)));
        assertRule("IACA_VALIDITY_INVALID", () -> iaca(iacaKeyPair, Duration.ofSeconds(1)));
        assertRule("IACA_VALIDITY_INVALID", () -> iaca(iacaKeyPair, IsoMdocProfiles.MIN_VALIDITY.minusSeconds(1)));
        X509Certificate shortest = iaca(iacaKeyPair, IsoMdocProfiles.MIN_VALIDITY);
        assertTrue(shortest.getNotAfter().after(shortest.getNotBefore()));
        assertEquals(List.of(), AnnexBValidator.validateIaca(shortest));

        Fixture fixture = new Fixture();
        assertRule("DS_VALIDITY_TOO_LONG", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("Long lived DSC").validity(Duration.ofDays(1_000)).build());
        assertRule("DS_VALIDITY_INVALID", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("No validity").validity(Duration.ZERO).build());
        assertRule("DS_VALIDITY_INVALID", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("One second").validity(Duration.ofSeconds(1)).build());
    }

    /**
     * A Document Signer clamped to the end of its IACA is refused when what remains is shorter than the minimum: the
     * builder does not silently issue a certificate valid for seconds.
     */
    @Test
    void aDsClampedBelowTheMinimumIsRefused() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        Instant start = Instant.parse("2026-01-01T00:00:00Z");
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").commonName("Two hour IACA")
                .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(start).validity(Duration.ofHours(2))
                .build();

        assertRule("DS_VALIDITY_OUTSIDE_IACA", () -> IsoMdocProfiles.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .commonName("Ten second DSC").notBefore(iaca.getNotAfter().toInstant().minusSeconds(9)).build());
        assertRule("DS_VALIDITY_OUTSIDE_IACA", () -> IsoMdocProfiles.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .commonName("Late DSC").notBefore(start.plus(Duration.ofHours(3))).build());

        X509Certificate ds = IsoMdocProfiles.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .commonName("Clamped DSC").notBefore(start.plus(Duration.ofMinutes(30))).build();
        assertEquals(iaca.getNotAfter(), ds.getNotAfter(), "clamped to the IACA");
        assertEquals(List.of(), AnnexBValidator.validateDs(ds, iaca));
    }

    @Test
    void theValidityIsAnInclusiveSpan() {
        KeyPair keyPair = BadCerts.ec(256);
        Instant start = Instant.parse("2026-01-01T00:00:00Z");
        X509Certificate iaca = IsoMdocProfiles.iaca(keyPair)
                .country("IN").commonName("Inclusive IACA")
                .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(start).validity(Duration.ofDays(30))
                .build();
        assertEquals(start, iaca.getNotBefore().toInstant());
        assertEquals(start.plus(Duration.ofDays(30)).minusSeconds(1), iaca.getNotAfter().toInstant(),
                "RFC 5280 4.1.2.5: notAfter is inclusive, so a 30 day span ends one second early");
        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca));
    }

    /** A DS cannot outlive its IACA: the builder caps the end and moves a too-early start forward to the IACA's. */
    @Test
    void theDsValidityIsClampedToTheIaca() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        Instant start = Instant.parse("2026-01-01T00:00:00Z");
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").commonName("Short IACA")
                .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(start).validity(Duration.ofDays(90))
                .build();

        X509Certificate ds = IsoMdocProfiles.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .commonName("Clamped DSC").notBefore(start.minus(Duration.ofDays(10))).build();
        assertEquals(iaca.getNotBefore(), ds.getNotBefore(), "the DS starts no earlier than the IACA");
        assertEquals(iaca.getNotAfter(), ds.getNotAfter(), "the DS ends no later than the IACA");
        assertEquals(List.of(), AnnexBValidator.validateDs(ds, iaca));
    }

    @Test
    void theDsBuilderValidatesTheIacaItIsGiven() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate brokenIaca = BadCerts.iaca(iacaKeyPair).without(Extension.extendedKeyUsage)
                .with(Extension.basicConstraints, true,
                        new org.bouncycastle.asn1.x509.BasicConstraints(true))
                .build();
        PkiException exception = assertThrows(PkiException.class, () -> IsoMdocProfiles
                .ds(BadCerts.ec(256), brokenIaca, iacaKeyPair).commonName("DSC under a broken IACA").build());
        assertTrue(exception.getMessage().startsWith("DS_IACA_INVALID:"), exception.getMessage());
    }

    @Test
    void theCrlCarriesTheRevokedSerialAndNoEntryExtensions() {
        Fixture fixture = new Fixture();
        Instant revokedAt = Instant.parse("2026-02-03T04:05:06Z");
        X509CRL crl = fixture.crl(BigInteger.valueOf(42), revokedAt);

        assertEquals(42, crl.getRevokedCertificate(BigInteger.valueOf(42)).getSerialNumber().intValue());
        assertTrue(!crl.getRevokedCertificate(BigInteger.valueOf(42)).hasExtensions(),
                "the profile (as read, to be confirmed) allows no CRL entry extensions");
        assertEquals(2, crl.getVersion(), "X.509 v2");
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, fixture.iaca));
    }

    @Test
    void aCrlWithoutACrlNumberOrWithAReversedNextUpdateIsRefused() {
        Fixture fixture = new Fixture();
        assertRule("CRL_NUMBER_MISSING", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair).build());
        assertRule("CRL_NUMBER_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.valueOf(-1)).build());
        assertRule("CRL_NUMBER_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE.shiftLeft(160)).build());
        assertRule("CRL_ENTRY_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE).revoke(BigInteger.valueOf(-1), Instant.now()));

        Instant now = Instant.now();
        assertRule("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE)
                .thisUpdate(now)
                .nextUpdate(now.minus(Duration.ofDays(1)))
                .build());
    }

    @Test
    void mandatoryAndMalformedInputIsRefusedWithTheRuleThatNeedsIt() {
        KeyPair keyPair = BadCerts.ec(256);
        assertRule("IACA_SUBJECT_COUNTRY_MISSING", () -> IsoMdocProfiles.iaca(keyPair)
                .commonName("No country").issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_COUNTRY_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("XX")
                .commonName("Bad country").issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_CN_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_CN_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN").commonName("  ")
                .issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_ISSUER_ALT_NAME_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("No alt name").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_ISSUER_ALT_NAME_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("Relative URI").issuerAltUri("mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_ISSUER_ALT_NAME_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("Scheme only").issuerAltUri("https:")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_ISSUER_ALT_NAME_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("Not an email").issuerAltEmail("not an address")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_CRL_DP_MISSING", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("No CRL DP").issuerAltUri("https://example.test").build());
        assertRule("IACA_CRL_DP_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("Bad CRL DP").issuerAltUri("https://example.test")
                .crlDistributionPoint("ldap://example.test/iaca.crl").build());
        assertRule("IACA_CRL_DP_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("Bad CRL DP").issuerAltUri("https://example.test")
                .crlDistributionPoint("not a uri").build());
        assertRule("IACA_SUBJECT_CN_TOO_LONG", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("C".repeat(65)).issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_STATE_EMPTY", () -> IsoMdocProfiles.iaca(keyPair).country("IN").state("")
                .commonName("Empty state").issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("IACA_SUBJECT_ORGANIZATION_EMPTY", () -> IsoMdocProfiles.iaca(keyPair).country("IN").organization(" ")
                .commonName("Blank organization").issuerAltUri("https://example.test")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertEquals(List.of(), AnnexBValidator.validateIaca(IsoMdocProfiles.iaca(keyPair).country("IN")
                .commonName("C".repeat(64)).issuerAltUri("https://example.test").crlDistributionPoint(Fixture.CRL_URI)
                .build()), "64 characters is RFC 5280's ub-common-name");

        Fixture fixture = new Fixture();
        assertRule("DS_SUBJECT_CN_MISSING", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair).build());
        assertRule("DS_CRL_DP_INVALID", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("Bad CRL DP").crlDistributionPoint("file:///tmp/iaca.crl").build());
        assertRule("DS_SUBJECT_CN_TOO_LONG", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("D".repeat(65)).build());
        assertRule("IACA_KEY_MISMATCH", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, BadCerts.ec(256))
                .commonName("Wrong IACA key").build());
    }

    /** The issuerAltName contact may be any absolute URI, a mailto: address included; the DS copies it unchanged. */
    @Test
    void anIssuerAltNameMayBeAMailtoUri() {
        KeyPair keyPair = BadCerts.ec(256);
        X509Certificate iaca = IsoMdocProfiles.iaca(keyPair).country("IN").commonName("Mailto IACA")
                .issuerAltUri("mailto:pki@credentials.example.test").crlDistributionPoint(Fixture.CRL_URI).build();
        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca));
        X509Certificate ds = IsoMdocProfiles.ds(BadCerts.ec(256), iaca, keyPair).commonName("Mailto DSC").build();
        assertEquals(List.of(), AnnexBValidator.validateDs(ds, iaca));
    }

    @Test
    void theCrlBuilderRefusesWhatTheValidatorWouldReport() {
        Fixture fixture = new Fixture();
        // inside the IACA validity and not ahead of now by more than the clock skew
        Instant thisUpdate = fixture.iaca.getNotBefore().toInstant().plusSeconds(60);
        BigInteger serial = BigInteger.valueOf(99);
        assertRule("CRL_ENTRY_DUPLICATE", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .revoke(serial, thisUpdate.minusSeconds(60)).revoke(serial, thisUpdate.minusSeconds(30)));
        assertRule("CRL_ENTRY_DATE_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .thisUpdate(thisUpdate).revoke(serial, thisUpdate.plusSeconds(1)));
        // thisUpdate moved before an entry after the entry was added
        assertRule("CRL_ENTRY_DATE_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE).revoke(serial, thisUpdate).thisUpdate(thisUpdate.minusSeconds(1)).build());
        assertRule("CRL_NUMBER_INVALID", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE.shiftLeft(159)).build());
        assertRule("CRL_NEXT_UPDATE_AFTER_IACA", () -> CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(BigInteger.ONE).nextUpdate(fixture.iaca.getNotAfter().toInstant().plusSeconds(1)).build());

        // an IACA without cRLSign cannot sign a CRL
        KeyPair keyPair = BadCerts.ec(256);
        X509Certificate noCrlSign = BadCerts.iaca(keyPair)
                .with(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign))
                .build();
        assertRule("CRL_IACA_INVALID", () -> CrlBuilder.forIaca(noCrlSign, keyPair));
    }

    /**
     * thisUpdate may be back-dated, but not before the IACA exists and not ahead of the instant the CRL is built by more
     * than the validator's clock skew: the builder refuses both, with the rule the validator reports.
     */
    @Test
    void theCrlBuilderRefusesAThisUpdateInTheFutureOrBeforeTheIaca() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").commonName("Back-dated IACA")
                .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(now.minus(Duration.ofDays(10))).validity(Duration.ofDays(400))
                .build();

        X509CRL backDated = CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE)
                .thisUpdate(now.minus(Duration.ofDays(1))).build();
        assertEquals(List.of(), AnnexBValidator.validateCrl(backDated, iaca));
        X509CRL atTheSkew = CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE)
                .thisUpdate(now.plus(AnnexBValidator.CLOCK_SKEW).minusSeconds(5)).build();
        assertEquals(List.of(), AnnexBValidator.validateCrl(atTheSkew, iaca));

        assertRule("CRL_THIS_UPDATE_IN_FUTURE", () -> CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE)
                .thisUpdate(now.plus(Duration.ofMinutes(10))).build());
        assertRule("CRL_THIS_UPDATE_BEFORE_IACA", () -> CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE)
                .thisUpdate(iaca.getNotBefore().toInstant().minusSeconds(1)).build());
    }

    /** A Document Signer certified for the IACA's own public key would let the IACA key sign documents (M-07 review). */
    @Test
    void aDocumentSignerForTheIacaKeyIsRefused() {
        Fixture fixture = new Fixture();
        assertRule("DS_KEY_IS_IACA_KEY", () -> IsoMdocProfiles.ds(fixture.iacaKeyPair.getPublic(), fixture.iaca,
                fixture.iacaKeyPair).commonName("Same Key DSC").build());
        assertRule("DS_KEY_IS_IACA_KEY", () -> IsoMdocProfiles.ds(fixture.iacaKeyPair, fixture.iaca,
                fixture.iacaKeyPair).commonName("Same Key DSC").build());
    }

    /**
     * Every builder verifies the signature it produced under the public key a verifier will use, so a key pair whose
     * private key belongs to another key is refused rather than turned into a certificate or CRL nobody can verify.
     */
    @Test
    void aKeyPairWhosePrivateKeyBelongsToAnotherKeyIsRefused() {
        Fixture fixture = new Fixture();
        KeyPair unrelated = BadCerts.ec(256);
        KeyPair mismatched = new KeyPair(fixture.iacaKeyPair.getPublic(), unrelated.getPrivate());

        assertRule("IACA_KEYPAIR_MISMATCH", () -> IsoMdocProfiles.iaca(mismatched)
                .country("IN").commonName("Mismatched IACA").issuerAltUri("https://example.test/iaca")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        assertRule("DS_SIGNER_KEY_MISMATCH", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, mismatched)
                .commonName("Mismatched DSC").build());
        assertRule("CRL_SIGNER_KEY_MISMATCH", () -> CrlBuilder.forIaca(fixture.iaca, mismatched)
                .crlNumber(BigInteger.ONE).build());

        // a private key on another curve, and one the ECDSA algorithm cannot use at all
        KeyPair p384 = BadCerts.ec(384);
        assertRule("IACA_KEYPAIR_MISMATCH", () -> IsoMdocProfiles.iaca(new KeyPair(fixture.iacaKeyPair.getPublic(),
                        p384.getPrivate()))
                .country("IN").commonName("Other curve IACA").issuerAltUri("https://example.test/iaca")
                .crlDistributionPoint(Fixture.CRL_URI).build());
        KeyPair rsa = rsa();
        assertRule("DS_SIGNER_KEY_MISMATCH", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca,
                new KeyPair(fixture.iacaKeyPair.getPublic(), rsa.getPrivate())).commonName("RSA signed DSC").build());
        assertRule("CRL_SIGNER_KEY_MISMATCH", () -> CrlBuilder.forIaca(fixture.iaca,
                new KeyPair(fixture.iacaKeyPair.getPublic(), rsa.getPrivate())).crlNumber(BigInteger.ONE).build());
    }

    /**
     * An IACA the JDK can construct but the strict DER read cannot (its issuer country is a primitive SET) is refused by
     * both builders with their named rule, not with a provider exception.
     */
    @Test
    void theBuildersRefuseAnIacaTheyCannotRead() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate unreadable = BadCerts.jdkCertificate(BadCerts.patch(BadCerts.encoded(BadCerts.iaca(iacaKeyPair)
                        .serial(BigInteger.ONE.shiftLeft(70).add(BigInteger.valueOf(0x5eed))).build()),
                new byte[] {0x13, 0x02, 0x49, 0x4e}, new byte[] {0x11, 0x02, 0x49, 0x4e}));
        assertRule("DS_IACA_INVALID", () -> IsoMdocProfiles.ds(BadCerts.ec(256), unreadable, iacaKeyPair)
                .commonName("DSC under an unreadable IACA").build());
        assertRule("CRL_IACA_INVALID", () -> CrlBuilder.forIaca(unreadable, iacaKeyPair));
    }

    private static KeyPair rsa() {
        try {
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Without an explicit validity the IACA is valid for exactly 20 calendar years, notAfter inclusive, whatever the
     * number of leap days: 7305 days would overrun the cap across 2100, which is not a leap year.
     */
    @Test
    void theDefaultIacaValidityIsTwentyCalendarYears() {
        KeyPair keyPair = BadCerts.ec(256);
        for (String start : List.of("2097-01-01T00:00:00Z", "2026-11-13T00:00:00Z", "2028-02-29T12:00:00Z")) {
            Instant notBefore = Instant.parse(start);
            X509Certificate iaca = IsoMdocProfiles.iaca(keyPair).country("IN").commonName("Default validity IACA")
                    .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                    .notBefore(notBefore).build();
            assertEquals(notBefore.atZone(java.time.ZoneOffset.UTC).plusYears(20).toInstant().minusSeconds(1),
                    iaca.getNotAfter().toInstant(), start);
            assertEquals(List.of(), AnnexBValidator.validateIaca(iaca), start);
        }
    }

    /**
     * issuerAltName: https, http, mailto and urn URIs only, http(s) with a host and without userinfo; a builder email
     * needs a dotted domain whose last label is not numeric. The validator keeps the plain mailbox syntax.
     */
    @Test
    void theIssuerAltNameAndCrlLocationsAreChecked() {
        KeyPair keyPair = BadCerts.ec(256);
        for (String uri : List.of("https://credentials.example.test/iaca", "HTTP://credentials.example.test/iaca",
                "mailto:pki@credentials.example.test", "urn:example:mdl:iaca")) {
            X509Certificate iaca = IsoMdocProfiles.iaca(keyPair).country("IN").commonName("Scheme IACA")
                    .issuerAltUri(uri).crlDistributionPoint(Fixture.CRL_URI).build();
            assertEquals(List.of(), AnnexBValidator.validateIaca(iaca), uri);
        }
        for (String uri : List.of("ldap://ldap.example.test/iaca", "javascript:alert(1)", "file:///etc/iaca",
                "https:opaque", "https://user@credentials.example.test/iaca", "https://credentials.example.test:99999/iaca")) {
            assertRule("IACA_ISSUER_ALT_NAME_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                    .commonName("Scheme IACA").issuerAltUri(uri).crlDistributionPoint(Fixture.CRL_URI).build());
        }
        for (String email : List.of("pki@localhost", "pki@123.456", "pki@example.123")) {
            assertRule("IACA_ISSUER_ALT_NAME_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN")
                    .commonName("Email IACA").issuerAltEmail(email).crlDistributionPoint(Fixture.CRL_URI).build());
        }
        X509Certificate dotted = IsoMdocProfiles.iaca(keyPair).country("IN").commonName("Email IACA")
                .issuerAltEmail("pki@example.test").crlDistributionPoint(Fixture.CRL_URI).build();
        assertEquals(List.of(), AnnexBValidator.validateIaca(dotted));
        for (String crl : List.of("https://user@credentials.example.test/iaca.crl",
                "https://credentials.example.test:99999/iaca.crl", "https://credentials.example.test:65536/iaca.crl")) {
            assertRule("IACA_CRL_DP_INVALID", () -> IsoMdocProfiles.iaca(keyPair).country("IN").commonName("CRL IACA")
                    .issuerAltUri("https://example.test/iaca").crlDistributionPoint(crl).build());
        }
        X509Certificate port = IsoMdocProfiles.iaca(keyPair).country("IN").commonName("CRL IACA")
                .issuerAltUri("https://example.test/iaca")
                .crlDistributionPoint("https://credentials.example.test:65535/iaca.crl").build();
        assertEquals(List.of(), AnnexBValidator.validateIaca(port));
    }

    /** Without an explicit nextUpdate, the CRL is due again in 30 days or when the IACA expires, whichever is sooner. */
    @Test
    void theDefaultNextUpdateDoesNotOutliveTheIaca() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").commonName("Ten day IACA")
                .issuerAltUri("https://example.test/iaca").crlDistributionPoint(Fixture.CRL_URI)
                .validity(Duration.ofDays(10))
                .build();
        X509CRL crl = CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE).build();
        assertEquals(iaca.getNotAfter(), crl.getNextUpdate());
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, iaca));
    }

    @Test
    void serialsAreRefusedOutsideRfc5280AndAnnexB() {
        KeyPair keyPair = BadCerts.ec(256);
        assertRule("IACA_SERIAL_NOT_POSITIVE", () -> iaca(keyPair, Serials.random(), BigInteger.valueOf(-1)));
        assertRule("IACA_SERIAL_TOO_SHORT", () -> iaca(keyPair, Serials.random(), BigInteger.valueOf(1_000)));
        assertRule("IACA_SERIAL_TOO_LONG", () -> iaca(keyPair, Serials.random(), BigInteger.ONE.shiftLeft(160)));

        Fixture fixture = new Fixture();
        assertRule("DS_SERIAL_NOT_POSITIVE", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("Bad serial").serial(BigInteger.ZERO).build());
        assertRule("DS_SERIAL_TOO_SHORT", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("Short serial").serial(BigInteger.valueOf(7)).build());
        assertRule("DS_SERIAL_TOO_LONG", () -> IsoMdocProfiles.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .commonName("Long serial").serial(BigInteger.ONE.shiftLeft(160)).build());
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
        assertSigns(readBack, keyPair.getPublic());
        assertArrayEquals(keyPair.getPublic().getEncoded(), Pem.readPublicKey(Pem.writePublicKey(keyPair.getPublic())).getEncoded());

        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Pem CSR"),
                keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BadCerts.BC).build(keyPair.getPrivate()));
        Csr csr = Pem.readCsr(Pem.writeCsr(request));
        assertEquals("CN=Pem CSR", csr.subject().getName());
        assertThrows(PkiException.class, () -> Pem.readCertificate(Pem.writeCrl(crl)));
        assertThrows(PkiException.class, () -> Pem.readCrl(Pem.writeCertificate(fixture.iaca)));
    }

    private static void assertSigns(java.security.PrivateKey privateKey, java.security.PublicKey publicKey)
            throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update("pem".getBytes());
        byte[] signature = signer.sign();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update("pem".getBytes());
        assertTrue(verifier.verify(signature), "the private key read back signs for the same key pair");
    }

    // ------------------------------------------------------------------ helpers

    private static X509Certificate iaca(KeyPair keyPair) {
        return IsoMdocProfiles.iaca(keyPair)
                .country("IN").commonName("Lorem Ipsum Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .build();
    }

    private static X509Certificate iaca(KeyPair keyPair, Duration validity) {
        return IsoMdocProfiles.iaca(keyPair)
                .country("IN").commonName("Lorem Ipsum Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .notBefore(Instant.parse("2026-01-01T00:00:00Z"))
                .validity(validity)
                .build();
    }

    private static X509Certificate iaca(KeyPair keyPair, BigInteger serial, BigInteger value) {
        return IsoMdocProfiles.iaca(keyPair)
                .country("IN").commonName("Lorem Ipsum Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .serial(value)
                .build();
    }

    private static byte[] csr(KeyPair keyPair, SubjectPublicKeyInfo spki, String signatureAlgorithm) {
        try {
            return new PKCS10CertificationRequestBuilder(new X500Name("CN=CSR"), spki)
                    .build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BadCerts.BC)
                            .build(keyPair.getPrivate()))
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ASN1Encodable onlyValue(X509Certificate certificate, org.bouncycastle.asn1.ASN1ObjectIdentifier type) {
        List<ASN1Encodable> values = new ArrayList<>();
        for (RDN rdn : Certificates.subject(certificate).getRDNs(type)) {
            values.add(rdn.getFirst().getValue());
        }
        assertEquals(1, values.size(), "expected exactly one " + type);
        return values.get(0);
    }

    private static void assertRule(String ruleId, Runnable action) {
        PkiException exception = assertThrows(PkiException.class, action::run);
        assertTrue(exception.getMessage().startsWith(ruleId + ":"),
                () -> "expected " + ruleId + ", got " + exception.getMessage());
    }

    /** Guards the DER string type the DS must copy: a UTF8String state stays a UTF8String. */
    @Test
    void aUtf8StateKeepsItsType() {
        assertEquals(DERUTF8String.class, new DERUTF8String("Foo, Bar").getClass());
        assertNotEquals(null, Certificates.string(new DERUTF8String("Foo, Bar")));
    }
}
