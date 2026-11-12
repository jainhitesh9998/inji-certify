package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One certificate or CRL per Annex B rule: everything else conforms, one property is broken, and the validator must
 * report that rule and nothing else. The certificates are built with plain BouncyCastle because the production
 * builders refuse invalid input.
 */
class AnnexBValidatorNegativeTest {

    private record Row(String ruleId, Set<String> allowed, X509Certificate certificate) {}

    private record CrlRow(String ruleId, Set<String> allowed, X509CRL crl) {}

    private static void assertReports(String ruleId, Set<String> allowed, List<AnnexBValidator.Violation> violations) {
        Set<String> reported = violations.stream().map(AnnexBValidator.Violation::ruleId).collect(Collectors.toSet());
        assertTrue(reported.contains(ruleId), () -> "expected " + ruleId + ", got " + violations);
        assertEquals(allowed, reported, () -> "unexpected violations: " + violations);
    }

    @TestFactory
    Stream<DynamicTest> iacaRules() {
        KeyPair keyPair = BadCerts.ec(256);
        Instant now = Instant.now();
        return Stream.of(
                new Row("IACA_SERIAL_NOT_POSITIVE", Set.of("IACA_SERIAL_NOT_POSITIVE"),
                        BadCerts.iaca(keyPair).serial(BigInteger.valueOf(-9)).build()),
                new Row("SERIAL_TOO_LONG", Set.of("SERIAL_TOO_LONG"),
                        BadCerts.iaca(keyPair).serial(BigInteger.ONE.shiftLeft(160)).build()),
                new Row("IACA_SUBJECT_COUNTRY_MISSING", Set.of("IACA_SUBJECT_COUNTRY_MISSING"),
                        BadCerts.iaca(keyPair).subject(BadCerts.name(null, null, "Bad IACA"))
                                .issuer(BadCerts.name(null, null, "Bad IACA")).build()),
                new Row("IACA_SUBJECT_COUNTRY_INVALID", Set.of("IACA_SUBJECT_COUNTRY_INVALID"),
                        BadCerts.iaca(keyPair, "IND", null).build()),
                new Row("IACA_SUBJECT_CN_MISSING", Set.of("IACA_SUBJECT_CN_MISSING"),
                        BadCerts.iaca(keyPair).subject(BadCerts.name("IN", null, null))
                                .issuer(BadCerts.name("IN", null, null)).build()),
                new Row("IACA_NOT_SELF_SIGNED", Set.of("IACA_NOT_SELF_SIGNED"),
                        BadCerts.iaca(keyPair).issuer(BadCerts.name("IN", null, "Another IACA")).build()),
                new Row("IACA_ISSUER_ALT_NAME_MISSING", Set.of("IACA_ISSUER_ALT_NAME_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.issuerAlternativeName).build()),
                new Row("IACA_ISSUER_ALT_NAME_CRITICAL", Set.of("IACA_ISSUER_ALT_NAME_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.issuerAlternativeName, true).build()),
                new Row("IACA_CRL_DP_MISSING", Set.of("IACA_CRL_DP_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.cRLDistributionPoints).build()),
                new Row("IACA_SKI_MISSING", Set.of("IACA_SKI_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.subjectKeyIdentifier).build()),
                new Row("IACA_KEY_USAGE_MISSING", Set.of("IACA_KEY_USAGE_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.keyUsage).build()),
                new Row("IACA_KEY_USAGE_NOT_CRITICAL", Set.of("IACA_KEY_USAGE_NOT_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.keyUsage, false).build()),
                new Row("IACA_BASIC_CONSTRAINTS_MISSING", Set.of("IACA_BASIC_CONSTRAINTS_MISSING"),
                        BadCerts.iaca(keyPair).without(Extension.basicConstraints).build()),
                new Row("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", Set.of("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL"),
                        BadCerts.iaca(keyPair).critical(Extension.basicConstraints, false).build()),
                new Row("IACA_PATHLEN", Set.of("IACA_PATHLEN"),
                        BadCerts.iaca(keyPair).with(Extension.basicConstraints, true, new BasicConstraints(true)).build()),
                new Row("IACA_VALIDITY_TOO_LONG", Set.of("IACA_VALIDITY_TOO_LONG"),
                        BadCerts.iaca(keyPair).notAfter(Date.from(now.plus(Duration.ofDays(7_306)))).build()),
                new Row("IACA_SIGNATURE_ALGORITHM_INVALID", Set.of("IACA_SIGNATURE_ALGORITHM_INVALID"),
                        BadCerts.iaca(keyPair).signatureAlgorithm("SHA1withECDSA").build()),
                new Row("IACA_SIGNATURE_ALGORITHM_MISMATCH", Set.of("IACA_SIGNATURE_ALGORITHM_MISMATCH"),
                        BadCerts.iaca(keyPair).signatureAlgorithm("SHA384withECDSA").build())
        ).map(row -> DynamicTest.dynamicTest(row.ruleId(),
                () -> assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateIaca(row.certificate()))));
    }

    @TestFactory
    Stream<DynamicTest> dsRules() {
        Fixture fixture = new Fixture();
        KeyPair subject = BadCerts.ec(256);
        KeyPair other = BadCerts.ec(256);
        Instant now = Instant.now();
        return Stream.of(
                new Row("DS_ISSUER_MISMATCH", Set.of("DS_ISSUER_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .issuer(BadCerts.name("IN", "Karnataka", "Another IACA")).build()),
                new Row("DS_SIGNATURE_INVALID", Set.of("DS_SIGNATURE_INVALID"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).signedBy(other.getPrivate()).build()),
                new Row("DS_COUNTRY_MISSING", Set.of("DS_COUNTRY_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name(null, "Karnataka", "Bad DSC")).build()),
                new Row("DS_COUNTRY_MISMATCH", Set.of("DS_COUNTRY_MISMATCH"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .subject(BadCerts.name("DE", "Karnataka", "Bad DSC")).build()),
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
                new Row("DS_SKI_MISSING", Set.of("DS_SKI_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .without(Extension.subjectKeyIdentifier).build()),
                new Row("DS_KEY_USAGE_MISSING", Set.of("DS_KEY_USAGE_MISSING"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).without(Extension.keyUsage).build()),
                new Row("DS_KEY_USAGE_NOT_CRITICAL", Set.of("DS_KEY_USAGE_NOT_CRITICAL"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair).critical(Extension.keyUsage, false).build()),
                new Row("DS_KEY_USAGE_EXTRA", Set.of("DS_KEY_USAGE_EXTRA"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign)).build()),
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
                new Row("DS_VALIDITY_TOO_LONG", Set.of("DS_VALIDITY_TOO_LONG"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .notAfter(Date.from(now.plus(Duration.ofDays(458)))).build()),
                new Row("DS_BASIC_CONSTRAINTS_PRESENT", Set.of("DS_BASIC_CONSTRAINTS_PRESENT"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.basicConstraints, true, new BasicConstraints(false)).build()),
                new Row("DS_IS_CA", Set.of("DS_BASIC_CONSTRAINTS_PRESENT", "DS_IS_CA"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .with(Extension.basicConstraints, true, new BasicConstraints(0)).build()),
                new Row("SERIAL_TOO_LONG", Set.of("SERIAL_TOO_LONG"),
                        BadCerts.ds(subject, fixture.iaca, fixture.iacaKeyPair)
                                .serial(BigInteger.ONE.shiftLeft(160)).build())
        ).map(row -> DynamicTest.dynamicTest(row.ruleId(), () ->
                assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateDs(row.certificate(), fixture.iaca))));
    }

    @TestFactory
    Stream<DynamicTest> crlRules() {
        Fixture fixture = new Fixture();
        KeyPair other = BadCerts.ec(256);
        Date thisUpdate = Date.from(Instant.now());
        Date nextUpdate = Date.from(Instant.now().plus(Duration.ofDays(30)));
        byte[] iacaKeyId = Certificates.keyIdentifier(fixture.iaca);
        return Stream.of(
                new CrlRow("CRL_ISSUER_MISMATCH", Set.of("CRL_ISSUER_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, "CN=Another IACA", iacaKeyId, true,
                                thisUpdate, nextUpdate)),
                new CrlRow("CRL_SIGNATURE_INVALID", Set.of("CRL_SIGNATURE_INVALID"),
                        BadCerts.crl(fixture.iaca, other, null, iacaKeyId, true, thisUpdate, nextUpdate)),
                new CrlRow("CRL_VERSION_INVALID",
                        Set.of("CRL_VERSION_INVALID", "CRL_AKI_MISSING", "CRL_NUMBER_MISSING", "CRL_NEXT_UPDATE_MISSING"),
                        BadCerts.v1Crl(fixture.iaca, fixture.iacaKeyPair, thisUpdate)),
                new CrlRow("CRL_AKI_MISSING", Set.of("CRL_AKI_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, null, null, true, thisUpdate, nextUpdate)),
                new CrlRow("CRL_AKI_MISMATCH", Set.of("CRL_AKI_MISMATCH"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, null,
                                BadCerts.keyId(other.getPublic()), true, thisUpdate, nextUpdate)),
                new CrlRow("CRL_NUMBER_MISSING", Set.of("CRL_NUMBER_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, null, iacaKeyId, false, thisUpdate, nextUpdate)),
                new CrlRow("CRL_NEXT_UPDATE_MISSING", Set.of("CRL_NEXT_UPDATE_MISSING"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, null, iacaKeyId, true, thisUpdate, null)),
                new CrlRow("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", Set.of("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE"),
                        BadCerts.crl(fixture.iaca, fixture.iacaKeyPair, null, iacaKeyId, true, thisUpdate,
                                Date.from(Instant.now().minus(Duration.ofDays(1)))))
        ).map(row -> DynamicTest.dynamicTest(row.ruleId(), () ->
                assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateCrl(row.crl(), fixture.iaca))));
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
}
