package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One certificate or CRL per Annex B rule: everything else conforms, one property is broken, and the validator must
 * report that rule and nothing else. The objects are built with plain BouncyCastle because the production builders
 * refuse invalid input.
 *
 * <p>Which rules exist is asserted at the end: {@link #everyRuleHasANegativeTest} compares the rule ids the suite
 * exercises with the ids the validator can emit, so a new rule cannot be added without the test that proves it fires.
 */
class AnnexBValidatorNegativeTest {

    private record Row(String ruleId, Set<String> allowed, X509Certificate certificate) {}

    private record DsRow(String ruleId, Set<String> allowed, X509Certificate certificate, X509Certificate iaca) {}

    private record CrlObject(String ruleId, Set<String> allowed, X509CRL crl) {}

    private record CrlRow(String ruleId, Set<String> allowed, X509CRL crl, X509Certificate iaca) {}

    private static void assertReports(String ruleId, Set<String> allowed, List<AnnexBValidator.Violation> violations) {
        Set<String> reported = violations.stream().map(AnnexBValidator.Violation::ruleId).collect(Collectors.toSet());
        assertTrue(reported.contains(ruleId), () -> "expected " + ruleId + ", got " + violations);
        assertEquals(allowed, reported, () -> "unexpected violations: " + violations);
    }

    @TestFactory
    Stream<DynamicTest> iacaRules() {
        return iacaRows().map(row -> DynamicTest.dynamicTest(row.ruleId(),
                () -> assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateIaca(row.certificate()))));
    }

    private static Stream<Row> iacaRows() {
        KeyPair keyPair = BadCerts.ec(256);
        KeyPair other = BadCerts.ec(256);
        Instant now = Instant.now();
        return Stream.of(
                // a version 1 certificate cannot carry extensions, so the rules that require them report as well
                new Row("IACA_VERSION_INVALID", Set.of("IACA_VERSION_INVALID", "IACA_SKI_MISSING",
                        "IACA_KEY_USAGE_MISSING", "IACA_BASIC_CONSTRAINTS_MISSING", "IACA_ISSUER_ALT_NAME_MISSING",
                        "IACA_CRL_DP_MISSING"), BadCerts.iaca(keyPair).buildV1()),
                new Row("IACA_SERIAL_NOT_POSITIVE", Set.of("IACA_SERIAL_NOT_POSITIVE"),
                        BadCerts.iaca(keyPair).serial(BigInteger.valueOf(-9)).build()),
                new Row("IACA_SERIAL_TOO_LONG", Set.of("IACA_SERIAL_TOO_LONG"),
                        BadCerts.iaca(keyPair).serial(BigInteger.ONE.shiftLeft(160)).build()),
                new Row("IACA_SERIAL_TOO_SHORT", Set.of("IACA_SERIAL_TOO_SHORT"),
                        BadCerts.iaca(keyPair).serial(BigInteger.valueOf(1)).build()),
                new Row("IACA_SUBJECT_COUNTRY_MISSING", Set.of("IACA_SUBJECT_COUNTRY_MISSING"),
                        BadCerts.iaca(keyPair).subject(BadCerts.name(null, null, "Bad IACA"))
                                .issuer(BadCerts.name(null, null, "Bad IACA")).build()),
                new Row("IACA_SUBJECT_COUNTRY_INVALID", Set.of("IACA_SUBJECT_COUNTRY_INVALID"),
                        BadCerts.iaca(keyPair, "IND", null).build()),
                new Row("IACA_SUBJECT_COUNTRY_NOT_PRINTABLE", Set.of("IACA_SUBJECT_COUNTRY_NOT_PRINTABLE"),
                        BadCerts.iaca(keyPair).subject(BadCerts.utf8CountryName("IN", "Karnataka", "Bad IACA"))
                                .issuer(BadCerts.utf8CountryName("IN", "Karnataka", "Bad IACA")).build()),
                new Row("IACA_SUBJECT_COUNTRY_DUPLICATE", Set.of("IACA_SUBJECT_COUNTRY_DUPLICATE"),
                        BadCerts.iaca(keyPair)
                                .subject(BadCerts.duplicateAttributeName("IN", null, "Bad IACA", BCStyle.C))
                                .issuer(BadCerts.duplicateAttributeName("IN", null, "Bad IACA", BCStyle.C)).build()),
                new Row("IACA_SUBJECT_STATE_DUPLICATE", Set.of("IACA_SUBJECT_STATE_DUPLICATE"),
                        BadCerts.iaca(keyPair).subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad IACA", BCStyle.ST))
                                .issuer(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad IACA", BCStyle.ST)).build()),
                new Row("IACA_SUBJECT_CN_MISSING", Set.of("IACA_SUBJECT_CN_MISSING"),
                        BadCerts.iaca(keyPair).subject(BadCerts.name("IN", null, null))
                                .issuer(BadCerts.name("IN", null, null)).build()),
                new Row("IACA_NOT_SELF_SIGNED", Set.of("IACA_NOT_SELF_SIGNED"),
                        BadCerts.iaca(keyPair).issuer(BadCerts.name("IN", null, "Another IACA")).build()),
                new Row("IACA_ISSUER_ALT_NAME_MISSING", Set.of("IACA_ISSUER_ALT_NAME_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.issuerAlternativeName).build()),
                new Row("IACA_ISSUER_ALT_NAME_CRITICAL", Set.of("IACA_ISSUER_ALT_NAME_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.issuerAlternativeName, true).build()),
                new Row("IACA_ISSUER_ALT_NAME_INVALID", Set.of("IACA_ISSUER_ALT_NAME_INVALID"),
                        BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                                BadCerts.dnsIssuerAltNames("credentials.example.test")).build()),
                new Row("IACA_CRL_DP_MISSING", Set.of("IACA_CRL_DP_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.cRLDistributionPoints).build()),
                new Row("IACA_CRL_DP_INVALID", Set.of("IACA_CRL_DP_INVALID"),
                        BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                                BadCerts.crlDistributionPoint(BadCerts.withReasons(BadCerts.CRL_URI))).build()),
                new Row("IACA_CRL_DP_CRITICAL", Set.of("IACA_CRL_DP_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.cRLDistributionPoints, true).build()),
                new Row("IACA_SKI_MISSING", Set.of("IACA_SKI_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.subjectKeyIdentifier).build()),
                new Row("IACA_SKI_MISMATCH", Set.of("IACA_SKI_MISMATCH"),
                        BadCerts.iaca(keyPair).with(Extension.subjectKeyIdentifier, false,
                                new SubjectKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                new Row("IACA_SKI_CRITICAL", Set.of("IACA_SKI_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.subjectKeyIdentifier, true).build()),
                new Row("IACA_AKI_MISMATCH", Set.of("IACA_AKI_MISMATCH"),
                        BadCerts.iaca(keyPair).with(Extension.authorityKeyIdentifier, false,
                                new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                new Row("IACA_AKI_CRITICAL", Set.of("IACA_AKI_CRITICAL"),
                        BadCerts.iaca(keyPair).with(Extension.authorityKeyIdentifier, true,
                                new AuthorityKeyIdentifier(BadCerts.keyId(keyPair.getPublic()))).build()),
                new Row("IACA_KEY_USAGE_MISSING", Set.of("IACA_KEY_USAGE_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.keyUsage).build()),
                new Row("IACA_KEY_USAGE_NOT_CRITICAL", Set.of("IACA_KEY_USAGE_NOT_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.keyUsage, false).build()),
                new Row("IACA_KEY_USAGE_EXTRA", Set.of("IACA_KEY_USAGE_EXTRA"),
                        BadCerts.iaca(keyPair).with(Extension.keyUsage, true,
                                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature)).build()),
                new Row("IACA_UNKNOWN_CRITICAL_EXTENSION", Set.of("IACA_UNKNOWN_CRITICAL_EXTENSION"),
                        BadCerts.iaca(keyPair).with(new ASN1ObjectIdentifier("1.2.3.4"), true,
                                org.bouncycastle.asn1.DERNull.INSTANCE).build()),
                new Row("IACA_BASIC_CONSTRAINTS_MISSING", Set.of("IACA_BASIC_CONSTRAINTS_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.basicConstraints).build()),
                new Row("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", Set.of("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.basicConstraints, false).build()),
                new Row("IACA_PATHLEN", Set.of("IACA_PATHLEN"),
                        BadCerts.iaca(keyPair).with(Extension.basicConstraints, true, new BasicConstraints(true)).build()),
                new Row("IACA_VALIDITY_REVERSED", Set.of("IACA_VALIDITY_REVERSED"),
                        BadCerts.iaca(keyPair).notBefore(Date.from(now.plus(Duration.ofDays(2))))
                                .notAfter(Date.from(now.plus(Duration.ofDays(1)))).build()),
                new Row("IACA_VALIDITY_TOO_LONG", Set.of("IACA_VALIDITY_TOO_LONG"),
                        BadCerts.iaca(keyPair).notAfter(Date.from(now.plus(Duration.ofDays(7_310)))).build()),
                new Row("IACA_SIGNATURE_ALGORITHM_INVALID", Set.of("IACA_SIGNATURE_ALGORITHM_INVALID"),
                        BadCerts.iaca(keyPair).signatureAlgorithm("SHA1withECDSA").build()),
                new Row("IACA_SIGNATURE_ALGORITHM_MISMATCH", Set.of("IACA_SIGNATURE_ALGORITHM_MISMATCH"),
                        BadCerts.iaca(keyPair).signatureAlgorithm("SHA384withECDSA").build()),
                new Row("IACA_ALGORITHM_IDENTIFIER_MISMATCH", Set.of("IACA_ALGORITHM_IDENTIFIER_MISMATCH"),
                        BadCerts.iaca(keyPair).buildInnerAlgorithmMismatch())
        );
    }

    /** Keys outside the Annex B allowlist: a compressed point, explicit parameters, brainpool. */
    @TestFactory
    Stream<DynamicTest> iacaKeyRules() {
        return iacaKeyRows().map(row -> DynamicTest.dynamicTest("IACA_KEY_INVALID " + row.certificate().getSigAlgName(),
                () -> assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateIaca(row.certificate()))));
    }

    private static Stream<Row> iacaKeyRows() {
        KeyPair compressed = BadCerts.bcEc(256);
        KeyPair explicit = BadCerts.ec(256);
        KeyPair brainpool = BadCerts.brainpool();
        return Stream.of(
                new Row("IACA_KEY_INVALID", Set.of("IACA_KEY_INVALID"),
                        BadCerts.iaca(compressed).subjectPublicKeyInfo(BadCerts.compressed(compressed)).build()),
                new Row("IACA_KEY_INVALID", Set.of("IACA_KEY_INVALID"),
                        BadCerts.iaca(explicit).subjectPublicKeyInfo(BadCerts.explicitParameters(explicit.getPublic())).build()),
                new Row("IACA_KEY_INVALID", Set.of("IACA_KEY_INVALID"),
                        BadCerts.iaca(brainpool).build())
        );
    }

    @TestFactory
    Stream<DynamicTest> dsRules() {
        return dsRows().map(row -> DynamicTest.dynamicTest(row.ruleId(), () ->
                assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateDs(row.certificate(), row.iaca()))));
    }

    private static Stream<DsRow> dsRows() {
        Fixture fixture = new Fixture();
        KeyPair subject = BadCerts.ec(256);
        KeyPair other = BadCerts.ec(256);
        Instant now = Instant.now();
        return Stream.of(
                new Row("DS_VERSION_INVALID", Set.of("DS_VERSION_INVALID", "DS_SKI_MISSING", "DS_AKI_MISSING",
                        "DS_KEY_USAGE_MISSING", "DS_EKU_MISSING", "DS_ISSUER_ALT_NAME_MISSING",
                        "DS_CRL_DP_MISSING"), BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).buildV1()),
                new Row("DS_SERIAL_TOO_LONG", Set.of("DS_SERIAL_TOO_LONG"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .serial(BigInteger.ONE.shiftLeft(160)).build()),
                new Row("DS_SERIAL_TOO_SHORT", Set.of("DS_SERIAL_TOO_SHORT"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).serial(BigInteger.TEN).build()),
                new Row("DS_ISSUER_MISMATCH", Set.of("DS_ISSUER_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .issuer(BadCerts.name("IN", "Karnataka", "Another IACA")).build()),
                new Row("DS_SIGNATURE_INVALID", Set.of("DS_SIGNATURE_INVALID"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).signedBy(other.getPrivate()).build()),
                new Row("DS_SERIAL_NOT_POSITIVE", Set.of("DS_SERIAL_NOT_POSITIVE"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).serial(BigInteger.valueOf(-5)).build()),
                new Row("DS_SUBJECT_COUNTRY_MISSING", Set.of("DS_SUBJECT_COUNTRY_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name(null, "Karnataka", "Bad DSC")).build()),
                new Row("DS_SUBJECT_COUNTRY_DUPLICATE", Set.of("DS_SUBJECT_COUNTRY_DUPLICATE"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad DSC", BCStyle.C)).build()),
                new Row("DS_SUBJECT_STATE_DUPLICATE", Set.of("DS_SUBJECT_STATE_DUPLICATE"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad DSC", BCStyle.ST))
                                .build()),
                new Row("DS_COUNTRY_MISMATCH", Set.of("DS_COUNTRY_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name("DE", "Karnataka", "Bad DSC")).build()),
                new Row("DS_SUBJECT_COUNTRY_NOT_PRINTABLE", Set.of("DS_SUBJECT_COUNTRY_NOT_PRINTABLE"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.utf8CountryName("IN", "Karnataka", "Bad DSC")).build()),
                new Row("DS_STATE_MISMATCH", Set.of("DS_STATE_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name("IN", "Maharashtra", "Bad DSC")).build()),
                new Row("DS_SUBJECT_CN_MISSING", Set.of("DS_SUBJECT_CN_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name("IN", "Karnataka", null)).build()),
                new Row("DS_AKI_MISSING", Set.of("DS_AKI_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .without(Extension.authorityKeyIdentifier).build()),
                new Row("DS_AKI_MISMATCH", Set.of("DS_AKI_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.authorityKeyIdentifier, false,
                                        new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                new Row("DS_AKI_CRITICAL", Set.of("DS_AKI_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .critical(Extension.authorityKeyIdentifier, true).build()),
                new Row("DS_SKI_MISSING", Set.of("DS_SKI_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .without(Extension.subjectKeyIdentifier).build()),
                new Row("DS_SKI_MISMATCH", Set.of("DS_SKI_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.subjectKeyIdentifier, false,
                                        new SubjectKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                new Row("DS_KEY_USAGE_MISSING", Set.of("DS_KEY_USAGE_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).without(Extension.keyUsage).build()),
                new Row("DS_KEY_USAGE_NOT_CRITICAL", Set.of("DS_KEY_USAGE_NOT_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).critical(Extension.keyUsage, false).build()),
                new Row("DS_KEY_USAGE_EXTRA", Set.of("DS_KEY_USAGE_EXTRA"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.keyUsage, true,
                                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign)).build()),
                new Row("DS_EKU_MISSING", Set.of("DS_EKU_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).without(Extension.extendedKeyUsage).build()),
                new Row("DS_EKU_NOT_CRITICAL", Set.of("DS_EKU_NOT_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).critical(Extension.extendedKeyUsage, false).build()),
                new Row("DS_EKU_INVALID", Set.of("DS_EKU_INVALID"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[] {
                                        KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)),
                                        KeyPurposeId.id_kp_serverAuth})).build()),
                new Row("DS_ISSUER_ALT_NAME_MISSING", Set.of("DS_ISSUER_ALT_NAME_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .without(Extension.issuerAlternativeName).build()),
                new Row("DS_ISSUER_ALT_NAME_MISMATCH", Set.of("DS_ISSUER_ALT_NAME_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.issuerAlternativeName, false,
                                        BadCerts.issuerAltNames("https://other.example.test/iaca")).build()),
                new Row("DS_ISSUER_ALT_NAME_CRITICAL", Set.of("DS_ISSUER_ALT_NAME_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .critical(Extension.issuerAlternativeName, true).build()),
                new Row("DS_CRL_DP_MISSING", Set.of("DS_CRL_DP_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .without(Extension.cRLDistributionPoints).build()),
                new Row("DS_CRL_DP_INVALID", Set.of("DS_CRL_DP_INVALID"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.cRLDistributionPoints, false,
                                        BadCerts.crlDistributionPoint(BadCerts.withCrlIssuer(BadCerts.CRL_URI))).build()),
                new Row("DS_CRL_DP_CRITICAL", Set.of("DS_CRL_DP_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .critical(Extension.cRLDistributionPoints, true).build()),
                new Row("DS_VALIDITY_REVERSED", Set.of("DS_VALIDITY_REVERSED"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .notAfter(Date.from(now.minus(Duration.ofDays(10)))).build()),
                new Row("DS_VALIDITY_TOO_LONG", Set.of("DS_VALIDITY_TOO_LONG"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .notAfter(Date.from(now.plus(Duration.ofDays(458)))).build()),
                new Row("DS_BASIC_CONSTRAINTS_PRESENT", Set.of("DS_BASIC_CONSTRAINTS_PRESENT"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.basicConstraints, true, new BasicConstraints(false)).build()),
                new Row("DS_IS_CA", Set.of("DS_BASIC_CONSTRAINTS_PRESENT", "DS_IS_CA"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.basicConstraints, true, new BasicConstraints(0)).build()),
                new Row("DS_UNKNOWN_CRITICAL_EXTENSION", Set.of("DS_UNKNOWN_CRITICAL_EXTENSION"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(new ASN1ObjectIdentifier("1.2.3.4"), true, org.bouncycastle.asn1.DERNull.INSTANCE).build()),
                new Row("DS_SIGNATURE_ALGORITHM_MISMATCH", Set.of("DS_SIGNATURE_ALGORITHM_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .signatureAlgorithm("SHA384withECDSA").build()),
                new Row("DS_ALGORITHM_IDENTIFIER_MISMATCH", Set.of("DS_ALGORITHM_IDENTIFIER_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).buildInnerAlgorithmMismatch())
        ).map(row -> new DsRow(row.ruleId(), row.allowed(), row.certificate(), fixture.iaca));
    }

    /**
     * A Document Signer that runs past the end of a short-lived IACA: the only way to break that rule alone, since a
     * requested validity beyond 457 days is refused by the builder and by {@code DS_VALIDITY_TOO_LONG}.
     */
    @Test
    void aDocumentSignerThatOutlivesItsIacaIsReported() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN").state("Karnataka").commonName("Short lived IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(Fixture.CRL_URI)
                .validity(Duration.ofDays(90))
                .build();
        X509Certificate ds = BadCerts.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .notAfter(Date.from(iaca.getNotAfter().toInstant().plus(Duration.ofDays(1))))
                .build();
        assertReports("DS_VALIDITY_OUTSIDE_IACA", Set.of("DS_VALIDITY_OUTSIDE_IACA"),
                AnnexBValidator.validateDs(ds, iaca));
    }

    /** A DS country that is not an ISO 3166 code, with an IACA that carries the same value so only that rule fires. */
    @Test
    void aDocumentSignerCountryOutsideIso3166IsReported() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate iaca = BadCerts.iaca(iacaKeyPair, "IND", null).build();
        X509Certificate ds = BadCerts.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .subject(BadCerts.name("IND", null, "Bad DSC")).build();
        assertReports("DS_SUBJECT_COUNTRY_INVALID", Set.of("DS_SUBJECT_COUNTRY_INVALID"),
                AnnexBValidator.validateDs(ds, iaca));
    }

    @Test
    void aDocumentSignerKeyOutsideTheAllowlistIsReported() {
        Fixture fixture = new Fixture();
        KeyPair compressed = BadCerts.bcEc(256);
        X509Certificate certificate = BadCerts.ds(compressed, fixture.iaca, fixture.iacaKeyPair)
                .subjectPublicKeyInfo(BadCerts.compressed(compressed))
                .with(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(BadCerts.keyId(BadCerts.compressed(compressed))))
                .build();
        assertReports("DS_KEY_INVALID", Set.of("DS_KEY_INVALID"), AnnexBValidator.validateDs(certificate, fixture.iaca));

        KeyPair explicit = BadCerts.ec(256);
        X509Certificate explicitCertificate = BadCerts.ds(explicit, fixture.iaca, fixture.iacaKeyPair)
                .subjectPublicKeyInfo(BadCerts.explicitParameters(explicit.getPublic()))
                .build();
        assertReports("DS_KEY_INVALID", Set.of("DS_KEY_INVALID"),
                AnnexBValidator.validateDs(explicitCertificate, fixture.iaca));
    }

    @TestFactory
    Stream<DynamicTest> crlRules() {
        return crlRows().map(row -> DynamicTest.dynamicTest(row.ruleId(), () ->
                assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateCrl(row.crl(), row.iaca()))));
    }

    private static Stream<CrlRow> crlRows() {
        Fixture fixture = new Fixture();
        KeyPair other = BadCerts.ec(256);
        Date now = new Date();
        Date later = new Date(now.getTime() + Duration.ofDays(30).toMillis());
        return Stream.of(
                new CrlObject("CRL_ISSUER_MISMATCH", Set.of("CRL_ISSUER_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).issuer(new org.bouncycastle.asn1.x500.X500Name("CN=Another IACA")).build()),
                new CrlObject("CRL_SIGNATURE_INVALID", Set.of("CRL_SIGNATURE_INVALID"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).signedBy(other.getPrivate()).build()),
                // a version 1 CRL keeps the extension list it was given, so only the version and the missing
                // nextUpdate report
                new CrlObject("CRL_VERSION_INVALID", Set.of("CRL_VERSION_INVALID", "CRL_NEXT_UPDATE_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).withoutNextUpdate().buildV1()),
                new CrlObject("CRL_AKI_MISSING", Set.of("CRL_AKI_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).without(Extension.authorityKeyIdentifier).build()),
                new CrlObject("CRL_AKI_MISMATCH", Set.of("CRL_AKI_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.authorityKeyIdentifier, false,
                                        new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                new CrlObject("CRL_AKI_CRITICAL", Set.of("CRL_AKI_CRITICAL"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).critical(Extension.authorityKeyIdentifier, true).build()),
                new CrlObject("CRL_NUMBER_MISSING", Set.of("CRL_NUMBER_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).without(Extension.cRLNumber).build()),
                new CrlObject("CRL_NUMBER_CRITICAL", Set.of("CRL_NUMBER_CRITICAL"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).critical(Extension.cRLNumber, true).build()),
                new CrlObject("CRL_NUMBER_INVALID", Set.of("CRL_NUMBER_INVALID"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE.shiftLeft(160))).build()),
                new CrlObject("CRL_EXTENSION_UNEXPECTED", Set.of("CRL_EXTENSION_UNEXPECTED"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.freshestCRL, false, BadCerts.crlDistributionPoint(BadCerts.CRL_URI)).build()),
                new CrlObject("CRL_ENTRY_EXTENSION_PRESENT", Set.of("CRL_ENTRY_EXTENSION_PRESENT"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).revokeWithReason(BigInteger.valueOf(42)).build()),
                new CrlObject("CRL_NEXT_UPDATE_MISSING", Set.of("CRL_NEXT_UPDATE_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).withoutNextUpdate().build()),
                new CrlObject("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", Set.of("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).thisUpdate(later).nextUpdate(now).build()),
                new CrlObject("CRL_SIGNATURE_ALGORITHM_INVALID", Set.of("CRL_SIGNATURE_ALGORITHM_INVALID"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).signatureAlgorithm("SHA1withECDSA").build()),
                new CrlObject("CRL_SIGNATURE_ALGORITHM_MISMATCH", Set.of("CRL_SIGNATURE_ALGORITHM_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).signatureAlgorithm("SHA384withECDSA").build()),
                new CrlObject("CRL_ALGORITHM_IDENTIFIER_MISMATCH", Set.of("CRL_ALGORITHM_IDENTIFIER_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).buildInnerAlgorithmMismatch())
        ).map(row -> new CrlRow(row.ruleId(), row.allowed(), row.crl(), fixture.iaca));
    }

    /** A revoked entry must not carry a reason code: Annex B Table B.9 prohibits entry extensions. */
    @Test
    void aCrlEntryWithAReasonIsReportedAndTheBuilderNeverWritesOne() {
        Fixture fixture = new Fixture();
        X509CRL crl = fixture.crl(BigInteger.valueOf(7), Instant.now());
        assertTrue(crl.getRevokedCertificate(BigInteger.valueOf(7)).getRevocationReason() == null,
                "the production CRL builder writes no reason code");
        assertReports("CRL_ENTRY_EXTENSION_PRESENT", Set.of("CRL_ENTRY_EXTENSION_PRESENT"),
                AnnexBValidator.validateCrl(BadCerts.crl(fixture.iaca, fixture.iacaKeyPair)
                        .revokeWithReason(BigInteger.valueOf(7)).build(), fixture.iaca));
    }

    @Test
    void aDocumentSignerIsCheckedAgainstItsOwnIaca() {
        Fixture fixture = new Fixture();
        KeyPair otherKey = BadCerts.ec(256);
        X509Certificate otherIaca = IsoMdocProfiles.iaca(otherKey)
                .country("IN")
                .commonName("Another IACA")
                .issuerAltUri("https://other.example.test/iaca")
                .crlDistributionPoint("https://other.example.test/iaca.crl")
                .build();

        List<AnnexBValidator.Violation> violations = AnnexBValidator.validateDs(fixture.ds, otherIaca);
        Set<String> reported = violations.stream().map(AnnexBValidator.Violation::ruleId).collect(Collectors.toSet());
        assertTrue(reported.contains("DS_ISSUER_MISMATCH"), () -> "reported " + violations);
        assertTrue(reported.contains("DS_SIGNATURE_INVALID"), () -> "reported " + violations);
    }

    @Test
    void ruleIdsAreSortedAndDeduplicated() {
        List<AnnexBValidator.Violation> violations = List.of(
                new AnnexBValidator.Violation("DS_EKU_MISSING", "b"),
                new AnnexBValidator.Violation("DS_EKU_MISSING", "a"),
                new AnnexBValidator.Violation("DS_AKI_MISSING", "c"));
        assertEquals(List.of("DS_AKI_MISSING", "DS_EKU_MISSING"), AnnexBValidator.ruleIds(violations));
    }

    /** Every rule the validator can emit is exercised above; a new rule without a negative test fails here. */
    @Test
    void everyRuleHasANegativeTest() {
        Set<String> expected = new HashSet<>(List.of(
                // IACA
                "IACA_VERSION_INVALID", "IACA_SERIAL_NOT_POSITIVE", "IACA_SERIAL_TOO_LONG", "IACA_SERIAL_TOO_SHORT",
                "IACA_SUBJECT_COUNTRY_MISSING", "IACA_SUBJECT_COUNTRY_INVALID", "IACA_SUBJECT_COUNTRY_NOT_PRINTABLE",
                "IACA_SUBJECT_COUNTRY_DUPLICATE", "IACA_SUBJECT_STATE_DUPLICATE", "IACA_SUBJECT_CN_MISSING",
                "IACA_NOT_SELF_SIGNED", "IACA_ISSUER_ALT_NAME_MISSING", "IACA_ISSUER_ALT_NAME_CRITICAL",
                "IACA_ISSUER_ALT_NAME_INVALID", "IACA_CRL_DP_MISSING", "IACA_CRL_DP_INVALID", "IACA_CRL_DP_CRITICAL",
                "IACA_SKI_MISSING", "IACA_SKI_MISMATCH", "IACA_SKI_CRITICAL", "IACA_AKI_MISMATCH", "IACA_AKI_CRITICAL",
                "IACA_KEY_USAGE_MISSING", "IACA_KEY_USAGE_NOT_CRITICAL", "IACA_KEY_USAGE_EXTRA",
                "IACA_UNKNOWN_CRITICAL_EXTENSION", "IACA_BASIC_CONSTRAINTS_MISSING",
                "IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", "IACA_PATHLEN", "IACA_VALIDITY_REVERSED",
                "IACA_VALIDITY_TOO_LONG", "IACA_SIGNATURE_ALGORITHM_INVALID", "IACA_SIGNATURE_ALGORITHM_MISMATCH",
                "IACA_ALGORITHM_IDENTIFIER_MISMATCH", "IACA_KEY_INVALID",
                // DS
                "DS_VERSION_INVALID", "DS_SERIAL_NOT_POSITIVE", "DS_SERIAL_TOO_LONG", "DS_SERIAL_TOO_SHORT",
                "DS_SUBJECT_COUNTRY_MISSING", "DS_SUBJECT_COUNTRY_INVALID", "DS_SUBJECT_COUNTRY_NOT_PRINTABLE",
                "DS_SUBJECT_COUNTRY_DUPLICATE", "DS_SUBJECT_STATE_DUPLICATE", "DS_SUBJECT_CN_MISSING",
                "DS_ISSUER_MISMATCH", "DS_SIGNATURE_INVALID", "DS_COUNTRY_MISMATCH",
                "DS_STATE_MISMATCH", "DS_AKI_MISSING", "DS_AKI_MISMATCH",
                "DS_AKI_CRITICAL", "DS_SKI_MISSING", "DS_SKI_MISMATCH", "DS_KEY_USAGE_MISSING",
                "DS_KEY_USAGE_NOT_CRITICAL", "DS_KEY_USAGE_EXTRA", "DS_EKU_MISSING", "DS_EKU_NOT_CRITICAL",
                "DS_EKU_INVALID", "DS_ISSUER_ALT_NAME_MISSING", "DS_ISSUER_ALT_NAME_MISMATCH",
                "DS_ISSUER_ALT_NAME_CRITICAL", "DS_CRL_DP_MISSING", "DS_CRL_DP_INVALID", "DS_CRL_DP_CRITICAL",
                "DS_VALIDITY_REVERSED", "DS_VALIDITY_TOO_LONG", "DS_VALIDITY_OUTSIDE_IACA",
                "DS_BASIC_CONSTRAINTS_PRESENT", "DS_IS_CA", "DS_UNKNOWN_CRITICAL_EXTENSION",
                "DS_SIGNATURE_ALGORITHM_MISMATCH", "DS_ALGORITHM_IDENTIFIER_MISMATCH", "DS_KEY_INVALID",
                // CRL
                "CRL_ISSUER_MISMATCH", "CRL_SIGNATURE_INVALID", "CRL_VERSION_INVALID", "CRL_AKI_MISSING",
                "CRL_AKI_MISMATCH", "CRL_AKI_CRITICAL", "CRL_NUMBER_MISSING", "CRL_NUMBER_CRITICAL",
                "CRL_NUMBER_INVALID", "CRL_EXTENSION_UNEXPECTED", "CRL_ENTRY_EXTENSION_PRESENT",
                "CRL_NEXT_UPDATE_MISSING", "CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "CRL_SIGNATURE_ALGORITHM_INVALID",
                "CRL_SIGNATURE_ALGORITHM_MISMATCH", "CRL_ALGORITHM_IDENTIFIER_MISMATCH"));
        Set<String> exercised = new HashSet<>();
        iacaRows().forEach(row -> exercised.addAll(row.allowed()));
        iacaKeyRows().forEach(row -> exercised.addAll(row.allowed()));
        dsRows().forEach(row -> exercised.addAll(row.allowed()));
        crlRows().forEach(row -> exercised.addAll(row.allowed()));
        // rules proved by a standalone test rather than a row, because each needs its own IACA
        exercised.add("DS_KEY_INVALID");
        exercised.add("DS_SUBJECT_COUNTRY_INVALID");
        exercised.add("DS_VALIDITY_OUTSIDE_IACA");
        assertEquals(expected, exercised, "rules without a negative test, or tests for rules that no longer exist");
    }
}
