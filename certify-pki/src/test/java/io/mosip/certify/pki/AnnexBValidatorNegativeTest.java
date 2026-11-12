package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestMethodOrder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One certificate or CRL per rule: everything else conforms, one property is broken, and the validator must report that
 * rule and nothing else (or, where breaking one property necessarily breaks others, exactly the listed set). The objects
 * are built with plain BouncyCastle because the production builders refuse invalid input.
 *
 * <p>Coverage is recorded, not declared: {@link #assertReports} records the rule a negative test targeted once its
 * assertions pass, and {@link #everyRuleHasANegativeTest}, which runs last, compares the recorded rules with
 * {@link AnnexBValidator#RULES}. A rule without a passing negative test, or a test for a rule that is no longer
 * published, fails the build.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AnnexBValidatorNegativeTest {

    /** The rules whose negative test passed in this run, recorded by {@link #assertReports}. */
    private static final Set<String> ASSERTED = ConcurrentHashMap.newKeySet();

    /** DER NULL, where an extension expects something else. */
    private static final byte[] NULL = {0x05, 0x00};

    /** A PrintableString {@code IN}, and the same octets under the primitive SET tag no string type uses. */
    private static final byte[] COUNTRY_IN = {0x13, 0x02, 0x49, 0x4e};
    private static final byte[] SET_IN = {0x11, 0x02, 0x49, 0x4e};

    /** The keyUsage extension's OID and critical flag, and the same with the flag as BOOLEAN 01 instead of FF. */
    private static final byte[] KEY_USAGE_CRITICAL = {0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, (byte) 0xff};
    private static final byte[] KEY_USAGE_BER_TRUE = {0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0x01};

    /** A notBefore whose UTCTime is known, and the same UTCTime with a letter in the minutes: {@code 2611010000t0Z}. */
    private static final Instant UTC_START = Instant.parse("2026-11-01T00:00:00Z");
    private static final byte[] UTC_START_DER = "261101000000Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] UTC_START_BROKEN = "2611010000t0Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    /** UTF8Strings whose contents are not UTF-8: C3 28 (a lead octet without its continuation) and FF 5A. */
    private static final ASN1Primitive BAD_UTF8_CN = primitive(new byte[] {0x0c, 0x02, (byte) 0xc3, 0x28});
    private static final ASN1Primitive BAD_UTF8_FF5A = primitive(new byte[] {0x0c, 0x02, (byte) 0xff, 0x5a});

    private static ASN1Primitive primitive(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Row(String ruleId, Set<String> allowed, X509Certificate certificate) {}

    private record DsRow(String ruleId, Set<String> allowed, X509Certificate certificate, X509Certificate iaca) {}

    private record CrlRow(String ruleId, Set<String> allowed, X509CRL crl, X509Certificate iaca) {}

    private static void assertReports(String ruleId, Set<String> allowed, List<AnnexBValidator.Violation> violations) {
        Set<String> reported = violations.stream().map(AnnexBValidator.Violation::ruleId).collect(Collectors.toSet());
        assertTrue(reported.contains(ruleId), () -> "expected " + ruleId + ", got " + violations);
        assertEquals(allowed, reported, () -> "unexpected violations: " + violations);
        ASSERTED.add(ruleId);
    }

    private static void assertConforms(List<AnnexBValidator.Violation> violations) {
        assertEquals(List.of(), violations);
    }

    private static Row row(String ruleId, X509Certificate certificate) {
        return new Row(ruleId, Set.of(ruleId), certificate);
    }

    // ------------------------------------------------------------------ IACA

    @TestFactory
    Stream<DynamicTest> iacaRules() {
        return iacaRows().map(row -> DynamicTest.dynamicTest(row.ruleId(),
                () -> assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateIaca(row.certificate()))));
    }

    private static Stream<Row> iacaRows() {
        KeyPair keyPair = BadCerts.ec(256);
        KeyPair other = BadCerts.ec(256);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant start = now.minus(Duration.ofDays(1));
        BigInteger fixedSerial = BigInteger.ONE.shiftLeft(70).add(BigInteger.valueOf(0x5eed));
        return Stream.of(
                // the issuer country's PrintableString tag (0x13) turned into a primitive SET (0x11): the JDK keeps the
                // value as raw octets, BouncyCastle's X500Name refuses it (the reviewers' fuzz finding)
                row("IACA_ENCODING_INVALID", BadCerts.jdkCertificate(BadCerts.patch(
                        BadCerts.encoded(BadCerts.iaca(keyPair).serial(fixedSerial).build()),
                        COUNTRY_IN, SET_IN))),
                // a notBefore UTCTime with a letter in it: BouncyCastle's provider constructs the certificate and
                // decodes the date only when it is first read
                row("IACA_ENCODING_INVALID", BadCerts.bcCertificate(BadCerts.patch(
                        BadCerts.encoded(BadCerts.iaca(keyPair).serial(fixedSerial).notBefore(Date.from(UTC_START)).build()),
                        UTC_START_DER, UTC_START_BROKEN))),
                // a common name whose UTF8String is not UTF-8 (C3 28), properly self-signed
                row("IACA_SUBJECT_ENCODING_INVALID", BadCerts.iaca(keyPair)
                        .subject(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.CN, BAD_UTF8_CN))
                        .issuer(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.CN, BAD_UTF8_CN)).buildJdk()),
                // a directoryName whose CN is a UTF8String FF 5A: decoding the name is part of reading the extension
                row("IACA_ISSUER_ALT_NAME_MALFORMED", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.directoryName,
                                BadCerts.rdns(BCStyle.CN, BAD_UTF8_FF5A)))).build()),
                // a version 1 certificate cannot carry extensions, so the rules that require them report as well
                new Row("IACA_VERSION_INVALID", Set.of("IACA_VERSION_INVALID", "IACA_SKI_MISSING",
                        "IACA_KEY_USAGE_MISSING", "IACA_BASIC_CONSTRAINTS_MISSING", "IACA_ISSUER_ALT_NAME_MISSING",
                        "IACA_CRL_DP_MISSING"), BadCerts.iaca(keyPair).buildV1()),
                row("IACA_SERIAL_NOT_POSITIVE", BadCerts.iaca(keyPair).serial(BigInteger.valueOf(-9)).build()),
                row("IACA_SERIAL_TOO_LONG", BadCerts.iaca(keyPair).serial(BigInteger.ONE.shiftLeft(160)).build()),
                row("IACA_SERIAL_TOO_SHORT", BadCerts.iaca(keyPair).serial(BigInteger.valueOf(1)).build()),
                // 55 bits: one below the validator's heuristic floor
                row("IACA_SERIAL_TOO_SHORT", BadCerts.iaca(keyPair)
                        .serial(BigInteger.ONE.shiftLeft(55).subtract(BigInteger.ONE)).build()),
                row("IACA_SUBJECT_COUNTRY_MISSING", BadCerts.iaca(keyPair).subject(BadCerts.name(null, null, "Bad IACA"))
                        .issuer(BadCerts.name(null, null, "Bad IACA")).build()),
                row("IACA_SUBJECT_COUNTRY_INVALID", BadCerts.iaca(keyPair, "IND", null).build()),
                row("IACA_SUBJECT_COUNTRY_NOT_PRINTABLE", BadCerts.iaca(keyPair)
                        .subject(BadCerts.utf8CountryName("IN", "Karnataka", "Bad IACA"))
                        .issuer(BadCerts.utf8CountryName("IN", "Karnataka", "Bad IACA")).build()),
                row("IACA_SUBJECT_COUNTRY_DUPLICATE", BadCerts.iaca(keyPair)
                        .subject(BadCerts.duplicateAttributeName("IN", null, "Bad IACA", BCStyle.C))
                        .issuer(BadCerts.duplicateAttributeName("IN", null, "Bad IACA", BCStyle.C)).build()),
                row("IACA_SUBJECT_STATE_DUPLICATE", BadCerts.iaca(keyPair)
                        .subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad IACA", BCStyle.ST))
                        .issuer(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad IACA", BCStyle.ST)).build()),
                row("IACA_SUBJECT_CN_MISSING", BadCerts.iaca(keyPair).subject(BadCerts.name("IN", null, null))
                        .issuer(BadCerts.name("IN", null, null)).build()),
                row("IACA_SUBJECT_ENCODING_INVALID", BadCerts.iaca(keyPair)
                        .subject(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.O,
                                new DERBMPString("Lorem Ipsum Demo"), BCStyle.CN, new DERUTF8String("Bad IACA")))
                        .issuer(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.O,
                                new DERBMPString("Lorem Ipsum Demo"), BCStyle.CN, new DERUTF8String("Bad IACA"))).build()),
                row("IACA_SUBJECT_ENCODING_INVALID", BadCerts.iaca(keyPair)
                        .subject(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.SERIALNUMBER,
                                new DERUTF8String("42"), BCStyle.CN, new DERUTF8String("Bad IACA")))
                        .issuer(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.SERIALNUMBER,
                                new DERUTF8String("42"), BCStyle.CN, new DERUTF8String("Bad IACA"))).build()),
                row("IACA_NOT_SELF_SIGNED", BadCerts.iaca(keyPair).issuer(BadCerts.name("IN", null, "Another IACA")).build()),
                // the keyUsage critical flag re-encoded as BOOLEAN 01 (BER true, not DER) after signing: the JDK keeps
                // those octets and the signature over them fails (BouncyCastle's provider would re-encode the object to
                // DER on construction, which gives back the original certificate)
                row("IACA_NOT_SELF_SIGNED", BadCerts.jdkCertificate(BadCerts.patch(BadCerts.encoded(
                        BadCerts.iaca(keyPair).serial(fixedSerial).build()), KEY_USAGE_CRITICAL, KEY_USAGE_BER_TRUE))),
                row("IACA_ISSUER_ALT_NAME_MISSING", BadCerts.iaca(keyPair).without(Extension.issuerAlternativeName).build()),
                row("IACA_ISSUER_ALT_NAME_CRITICAL", BadCerts.iaca(keyPair).critical(Extension.issuerAlternativeName, true).build()),
                row("IACA_ISSUER_ALT_NAME_INVALID", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        BadCerts.dnsIssuerAltNames("credentials.example.test")).build()),
                row("IACA_ISSUER_ALT_NAME_INVALID", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        BadCerts.issuerAltNames("mdoc/iaca")).build()),
                row("IACA_ISSUER_ALT_NAME_INVALID", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.rfc822Name, "pki at example.test"))).build()),
                // only https, http, mailto and urn URIs (decision log, 2026-11-13)
                row("IACA_ISSUER_ALT_NAME_INVALID", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        BadCerts.issuerAltNames("ldap://ldap.example.test/cn=IACA")).build()),
                row("IACA_ISSUER_ALT_NAME_INVALID", BadCerts.iaca(keyPair).with(Extension.issuerAlternativeName, false,
                        BadCerts.issuerAltNames("https://user@credentials.example.test/iaca")).build()),
                // a GeneralName with tag [9], which does not exist
                row("IACA_ISSUER_ALT_NAME_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.issuerAlternativeName, false,
                        new byte[] {0x30, 0x03, (byte) 0x89, 0x01, 0x41}).build()),
                row("IACA_CRL_DP_MISSING", BadCerts.iaca(keyPair).without(Extension.cRLDistributionPoints).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(BadCerts.withReasons(BadCerts.CRL_URI))).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint("ldap://ldap.example.test/cn=IACA?certificateRevocationList")).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint("not a uri")).build()),
                // the remaining CRL_DP_INVALID branches: no point, a relative name, no name, an empty fullName, a
                // dNSName, userinfo and a port out of range
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint()).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(new DistributionPoint(new DistributionPointName(
                                DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER,
                                new RDN(BCStyle.CN, new DERUTF8String("iaca.crl")).toASN1Primitive()), null, null))).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(new DistributionPoint(null, null,
                                BadCerts.issuerAltNames(BadCerts.CRL_URI)))).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(new DistributionPoint(
                                new DistributionPointName(new GeneralNames(new GeneralName[0])), null, null))).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(new DistributionPoint(new DistributionPointName(
                                BadCerts.dnsIssuerAltNames("credentials.example.test")), null, null))).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint("https://user@credentials.example.test/iaca.crl")).build()),
                row("IACA_CRL_DP_INVALID", BadCerts.iaca(keyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint("https://credentials.example.test:99999/iaca.crl")).build()),
                // a SEQUENCE OF DistributionPoint holding a NULL
                row("IACA_CRL_DP_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.cRLDistributionPoints, false,
                        new byte[] {0x30, 0x02, 0x05, 0x00}).build()),
                row("IACA_CRL_DP_CRITICAL", BadCerts.iaca(keyPair).critical(Extension.cRLDistributionPoints, true).build()),
                row("IACA_SKI_MISSING", BadCerts.iaca(keyPair).without(Extension.subjectKeyIdentifier).build()),
                row("IACA_SKI_MISMATCH", BadCerts.iaca(keyPair).with(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                row("IACA_SKI_CRITICAL", BadCerts.iaca(keyPair).critical(Extension.subjectKeyIdentifier, true).build()),
                row("IACA_SKI_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.subjectKeyIdentifier, false, NULL).build()),
                // an OCTET STRING followed by a trailing octet
                row("IACA_SKI_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.subjectKeyIdentifier, false,
                        new byte[] {0x04, 0x01, 0x07, 0x00}).build()),
                row("IACA_AKI_MISMATCH", BadCerts.iaca(keyPair).with(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build()),
                row("IACA_AKI_CRITICAL", BadCerts.iaca(keyPair).with(Extension.authorityKeyIdentifier, true,
                        new AuthorityKeyIdentifier(BadCerts.keyId(keyPair.getPublic()))).build()),
                // an AuthorityKeyIdentifier with a context tag [5], which does not exist
                row("IACA_AKI_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.authorityKeyIdentifier, false,
                        new byte[] {0x30, 0x03, (byte) 0x85, 0x01, 0x00}).build()),
                row("IACA_KEY_USAGE_MISSING", BadCerts.iaca(keyPair).without(Extension.keyUsage).build()),
                row("IACA_KEY_USAGE_NOT_CRITICAL", BadCerts.iaca(keyPair).critical(Extension.keyUsage, false).build()),
                row("IACA_KEY_USAGE_EXTRA", BadCerts.iaca(keyPair).with(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature)).build()),
                // BouncyCastle refuses to load such a certificate and the JDK refuses it when the extension is
                // critical; non-critical, the JDK keeps the raw octets
                row("IACA_KEY_USAGE_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.keyUsage, false, NULL).buildJdk()),
                row("IACA_UNKNOWN_CRITICAL_EXTENSION", BadCerts.iaca(keyPair).with(new ASN1ObjectIdentifier("1.2.3.4"),
                        true, DERNull.INSTANCE).build()),
                // extendedKeyUsage belongs to the Document Signer profile, not the IACA's
                row("IACA_UNKNOWN_CRITICAL_EXTENSION", BadCerts.iaca(keyPair).with(Extension.extendedKeyUsage, true,
                        BadCerts.documentSignerEku()).build()),
                row("IACA_BASIC_CONSTRAINTS_MISSING", BadCerts.iaca(keyPair).without(Extension.basicConstraints).build()),
                row("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", BadCerts.iaca(keyPair).critical(Extension.basicConstraints, false).build()),
                row("IACA_BASIC_CONSTRAINTS_MALFORMED", BadCerts.iaca(keyPair).withRaw(Extension.basicConstraints, false,
                        new byte[] {0x04, 0x00}).buildJdk()),
                row("IACA_PATHLEN", BadCerts.iaca(keyPair).with(Extension.basicConstraints, true, new BasicConstraints(true)).build()),
                row("IACA_VALIDITY_REVERSED", BadCerts.iaca(keyPair).notBefore(Date.from(now.plus(Duration.ofDays(2))))
                        .notAfter(Date.from(now.plus(Duration.ofDays(1)))).build()),
                row("IACA_VALIDITY_TOO_LONG", BadCerts.iaca(keyPair).notAfter(Date.from(now.plus(Duration.ofDays(7_310)))).build()),
                // one second past 20 calendar years
                row("IACA_VALIDITY_TOO_LONG", BadCerts.iaca(keyPair).notBefore(Date.from(start))
                        .notAfter(Date.from(twentyYears(start).plusSeconds(1))).build()),
                row("IACA_SIGNATURE_ALGORITHM_INVALID", BadCerts.iaca(keyPair).signatureAlgorithm("SHA1withECDSA").build()),
                row("IACA_SIGNATURE_ALGORITHM_INVALID", BadCerts.iaca(keyPair).buildWithAlgorithmParameters()),
                row("IACA_SIGNATURE_ALGORITHM_MISMATCH", BadCerts.iaca(keyPair).signatureAlgorithm("SHA384withECDSA").build()),
                row("IACA_ALGORITHM_IDENTIFIER_MISMATCH", BadCerts.iaca(keyPair).buildInnerAlgorithmMismatch())
        );
    }

    /**
     * Keys outside the allowlist: a compressed point, explicit parameters, brainpool, and P-256 encodings that do not
     * decode to a finite point on the curve. The subject key identifier is recomputed over each encoding.
     */
    @TestFactory
    Stream<DynamicTest> iacaKeyRules() {
        return iacaKeyRows().map(row -> DynamicTest.dynamicTest("IACA_KEY_INVALID " + row.ruleId(),
                () -> assertReports("IACA_KEY_INVALID", row.allowed(), AnnexBValidator.validateIaca(row.certificate()))));
    }

    private static Stream<Row> iacaKeyRows() {
        KeyPair compressed = BadCerts.bcEc(256);
        KeyPair explicit = BadCerts.ec(256);
        KeyPair brainpool = BadCerts.brainpool();
        KeyPair signer = BadCerts.ec(256);
        Set<String> allowed = Set.of("IACA_KEY_INVALID");
        return Stream.of(
                new Row("compressed point", allowed,
                        BadCerts.iaca(compressed).subjectPublicKeyInfo(BadCerts.compressed(compressed)).build()),
                new Row("explicit parameters", allowed,
                        BadCerts.iaca(explicit).subjectPublicKeyInfo(BadCerts.explicitParameters(explicit.getPublic())).build()),
                new Row("brainpool", allowed, BadCerts.iaca(brainpool).build()),
                new Row("point (0, 0)", allowed, withKey(BadCerts.iaca(signer), BadCerts.zeroPoint()).build()),
                new Row("point off the curve", allowed,
                        withKey(BadCerts.iaca(signer), BadCerts.p256Point(BigInteger.ONE, BigInteger.ONE)).build()),
                new Row("x outside the field", allowed, withKey(BadCerts.iaca(signer),
                        BadCerts.p256Point(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), BigInteger.ONE)).build())
        );
    }

    private static BadCerts.Cert withKey(BadCerts.Cert cert, SubjectPublicKeyInfo spki) {
        return cert.subjectPublicKeyInfo(spki)
                .with(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(BadCerts.keyId(spki)));
    }

    private static Instant twentyYears(Instant start) {
        return start.atZone(ZoneOffset.UTC).plusYears(20).toInstant();
    }

    // ------------------------------------------------------------------ DS

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
        Instant iacaStart = fixture.iaca.getNotBefore().toInstant();
        KeyPair dnsIacaKeyPair = BadCerts.ec(256);
        X509Certificate dnsIaca = BadCerts.iaca(dnsIacaKeyPair).with(Extension.issuerAlternativeName, false,
                BadCerts.dnsIssuerAltNames("credentials.example.test")).build();
        X509Certificate iaca = fixture.iaca;
        KeyPair iacaKeyPair = fixture.iacaKeyPair;
        BigInteger fixedSerial = BigInteger.ONE.shiftLeft(70).add(BigInteger.valueOf(0x5eed));
        X509Certificate unreadableIaca = BadCerts.jdkCertificate(BadCerts.patch(
                BadCerts.encoded(BadCerts.iaca(iacaKeyPair, "IN", "Karnataka").serial(fixedSerial).build()),
                COUNTRY_IN, SET_IN));
        return Stream.of(
                // the issuer country of the DS turned into a primitive SET, as for the IACA row
                ds("DS_ENCODING_INVALID", BadCerts.jdkCertificate(BadCerts.patch(BadCerts.encoded(
                        BadCerts.ds(subject, iaca, iacaKeyPair).serial(fixedSerial).build()), COUNTRY_IN, SET_IN)), iaca),
                ds("DS_SUBJECT_ENCODING_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.ST,
                                new DERUTF8String("Karnataka"), BCStyle.CN, BAD_UTF8_CN)).buildJdk(), iaca),
                // a conforming DS checked against an IACA that cannot be read: the IACA is reported, the checks
                // against it are skipped
                new DsRow("IACA_ENCODING_INVALID", Set.of("IACA_ENCODING_INVALID"),
                        BadCerts.ds(subject, iaca, iacaKeyPair).build(), unreadableIaca),
                new DsRow("DS_VERSION_INVALID", Set.of("DS_VERSION_INVALID", "DS_SKI_MISSING", "DS_AKI_MISSING",
                        "DS_KEY_USAGE_MISSING", "DS_EKU_MISSING", "DS_ISSUER_ALT_NAME_MISSING",
                        "DS_CRL_DP_MISSING"), BadCerts.ds(subject, iaca, iacaKeyPair).buildV1(), iaca),
                ds("DS_SERIAL_TOO_LONG", BadCerts.ds(subject, iaca, iacaKeyPair).serial(BigInteger.ONE.shiftLeft(160)).build(), iaca),
                ds("DS_SERIAL_TOO_SHORT", BadCerts.ds(subject, iaca, iacaKeyPair).serial(BigInteger.TEN).build(), iaca),
                ds("DS_SERIAL_NOT_POSITIVE", BadCerts.ds(subject, iaca, iacaKeyPair).serial(BigInteger.valueOf(-5)).build(), iaca),
                ds("DS_ISSUER_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .issuer(BadCerts.name("IN", "Karnataka", "Another IACA")).build(), iaca),
                ds("DS_SIGNATURE_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).signedBy(other.getPrivate()).build(), iaca),
                ds("DS_SIGNATURE_INVALID", BadCerts.jdkCertificate(BadCerts.patch(BadCerts.encoded(
                        BadCerts.ds(subject, iaca, iacaKeyPair).serial(fixedSerial).build()),
                        KEY_USAGE_CRITICAL, KEY_USAGE_BER_TRUE)), iaca),
                ds("DS_SUBJECT_COUNTRY_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.name(null, "Karnataka", "Bad DSC")).build(), iaca),
                ds("DS_SUBJECT_COUNTRY_DUPLICATE", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad DSC", BCStyle.C)).build(), iaca),
                ds("DS_SUBJECT_STATE_DUPLICATE", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.duplicateAttributeName("IN", "Karnataka", "Bad DSC", BCStyle.ST)).build(), iaca),
                ds("DS_COUNTRY_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.name("DE", "Karnataka", "Bad DSC")).build(), iaca),
                ds("DS_SUBJECT_COUNTRY_NOT_PRINTABLE", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.utf8CountryName("IN", "Karnataka", "Bad DSC")).build(), iaca),
                ds("DS_STATE_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.name("IN", "Maharashtra", "Bad DSC")).build(), iaca),
                ds("DS_SUBJECT_CN_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.name("IN", "Karnataka", null)).build(), iaca),
                ds("DS_SUBJECT_ENCODING_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .subject(BadCerts.rdns(BCStyle.C, new DERPrintableString("IN"), BCStyle.ST,
                                new DERUTF8String("Karnataka"), BCStyle.CN, new DERBMPString("Bad DSC"))).build(), iaca),
                ds("DS_AKI_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.authorityKeyIdentifier).build(), iaca),
                ds("DS_AKI_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build(), iaca),
                ds("DS_AKI_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.authorityKeyIdentifier, true).build(), iaca),
                ds("DS_AKI_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.authorityKeyIdentifier, false,
                        new byte[] {0x30, 0x03, (byte) 0x85, 0x01, 0x00}).build(), iaca),
                ds("DS_SKI_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.subjectKeyIdentifier).build(), iaca),
                ds("DS_SKI_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(BadCerts.keyId(other.getPublic()))).build(), iaca),
                ds("DS_SKI_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.subjectKeyIdentifier, true).build(), iaca),
                ds("DS_SKI_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.subjectKeyIdentifier, false, NULL).build(), iaca),
                ds("DS_KEY_USAGE_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.keyUsage).build(), iaca),
                ds("DS_KEY_USAGE_NOT_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.keyUsage, false).build(), iaca),
                ds("DS_KEY_USAGE_EXTRA", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign)).build(), iaca),
                ds("DS_KEY_USAGE_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.keyUsage, false, NULL).buildJdk(), iaca),
                ds("DS_EKU_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.extendedKeyUsage).build(), iaca),
                ds("DS_EKU_NOT_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.extendedKeyUsage, false).build(), iaca),
                ds("DS_EKU_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.extendedKeyUsage, true,
                        new ExtendedKeyUsage(new KeyPurposeId[] {
                                KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)),
                                KeyPurposeId.id_kp_serverAuth})).build(), iaca),
                // an INTEGER where a KeyPurposeId OID belongs
                ds("DS_EKU_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.extendedKeyUsage, true,
                        new byte[] {0x30, 0x03, 0x02, 0x01, 0x01}).build(), iaca),
                ds("DS_ISSUER_ALT_NAME_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.issuerAlternativeName).build(), iaca),
                ds("DS_ISSUER_ALT_NAME_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.issuerAlternativeName, false,
                        BadCerts.issuerAltNames("https://other.example.test/iaca")).build(), iaca),
                ds("DS_ISSUER_ALT_NAME_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.issuerAlternativeName, true).build(), iaca),
                // a dNSName copied from an IACA that carries the same one, so only the GeneralName type is wrong
                ds("DS_ISSUER_ALT_NAME_INVALID", BadCerts.ds(subject, dnsIaca, dnsIacaKeyPair).build(), dnsIaca),
                ds("DS_ISSUER_ALT_NAME_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.issuerAlternativeName, false,
                        new byte[] {0x30, 0x03, (byte) 0x89, 0x01, 0x41}).build(), iaca),
                ds("DS_CRL_DP_MISSING", BadCerts.ds(subject, iaca, iacaKeyPair).without(Extension.cRLDistributionPoints).build(), iaca),
                ds("DS_CRL_DP_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint(BadCerts.withCrlIssuer(BadCerts.CRL_URI))).build(), iaca),
                ds("DS_CRL_DP_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.cRLDistributionPoints, false,
                        BadCerts.crlDistributionPoint("ldap://ldap.example.test/cn=IACA")).build(), iaca),
                ds("DS_CRL_DP_CRITICAL", BadCerts.ds(subject, iaca, iacaKeyPair).critical(Extension.cRLDistributionPoints, true).build(), iaca),
                ds("DS_CRL_DP_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.cRLDistributionPoints, false,
                        new byte[] {0x30, 0x02, 0x05, 0x00}).build(), iaca),
                ds("DS_VALIDITY_REVERSED", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .notAfter(Date.from(now.minus(Duration.ofDays(10)))).build(), iaca),
                ds("DS_VALIDITY_TOO_LONG", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .notAfter(Date.from(now.plus(Duration.ofDays(458)))).build(), iaca),
                // one second past 457 days, endpoints compared directly
                ds("DS_VALIDITY_TOO_LONG", BadCerts.ds(subject, iaca, iacaKeyPair)
                        .notAfter(Date.from(iacaStart.plus(Duration.ofDays(457)).plusSeconds(1))).build(), iaca),
                ds("DS_BASIC_CONSTRAINTS_MALFORMED", BadCerts.ds(subject, iaca, iacaKeyPair).withRaw(Extension.basicConstraints, false,
                        new byte[] {0x04, 0x00}).buildJdk(), iaca),
                ds("DS_IS_CA", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.basicConstraints, true,
                        new BasicConstraints(0)).build(), iaca),
                ds("DS_IS_CA", BadCerts.ds(subject, iaca, iacaKeyPair).with(Extension.basicConstraints, false,
                        new BasicConstraints(true)).build(), iaca),
                ds("DS_UNKNOWN_CRITICAL_EXTENSION", BadCerts.ds(subject, iaca, iacaKeyPair).with(new ASN1ObjectIdentifier("1.2.3.4"),
                        true, DERNull.INSTANCE).build(), iaca),
                ds("DS_SIGNATURE_ALGORITHM_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).signatureAlgorithm("SHA1withECDSA").build(), iaca),
                ds("DS_SIGNATURE_ALGORITHM_INVALID", BadCerts.ds(subject, iaca, iacaKeyPair).buildWithAlgorithmParameters(), iaca),
                ds("DS_SIGNATURE_ALGORITHM_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair).signatureAlgorithm("SHA384withECDSA").build(), iaca),
                ds("DS_ALGORITHM_IDENTIFIER_MISMATCH", BadCerts.ds(subject, iaca, iacaKeyPair).buildInnerAlgorithmMismatch(), iaca),
                // P-256 with the point 04 || 64 zero octets, subject key identifier recomputed, signed by the IACA
                ds("DS_KEY_INVALID", withKey(BadCerts.ds(subject, iaca, iacaKeyPair), BadCerts.zeroPoint()).build(), iaca),
                ds("DS_KEY_INVALID", withKey(BadCerts.ds(subject, iaca, iacaKeyPair),
                        BadCerts.p256Point(BigInteger.ONE, BigInteger.TWO)).build(), iaca)
        );
    }

    private static DsRow ds(String ruleId, X509Certificate certificate, X509Certificate iaca) {
        return new DsRow(ruleId, Set.of(ruleId), certificate, iaca);
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
        assertReports("DS_VALIDITY_OUTSIDE_IACA", Set.of("DS_VALIDITY_OUTSIDE_IACA"), AnnexBValidator.validateDs(ds, iaca));
    }

    /** A DS country that is not an ISO 3166 code, with an IACA that carries the same value so only that rule fires. */
    @Test
    void aDocumentSignerCountryOutsideIso3166IsReported() {
        KeyPair iacaKeyPair = BadCerts.ec(256);
        X509Certificate iaca = BadCerts.iaca(iacaKeyPair, "IND", null).build();
        X509Certificate ds = BadCerts.ds(BadCerts.ec(256), iaca, iacaKeyPair)
                .subject(BadCerts.name("IND", null, "Bad DSC")).build();
        assertReports("DS_SUBJECT_COUNTRY_INVALID", Set.of("DS_SUBJECT_COUNTRY_INVALID"), AnnexBValidator.validateDs(ds, iaca));
    }

    @Test
    void aDocumentSignerKeyOutsideTheAllowlistIsReported() {
        Fixture fixture = new Fixture();
        KeyPair compressed = BadCerts.bcEc(256);
        X509Certificate certificate = withKey(BadCerts.ds(compressed, fixture.iaca, fixture.iacaKeyPair),
                BadCerts.compressed(compressed)).build();
        assertReports("DS_KEY_INVALID", Set.of("DS_KEY_INVALID"), AnnexBValidator.validateDs(certificate, fixture.iaca));

        KeyPair explicit = BadCerts.ec(256);
        X509Certificate explicitCertificate = BadCerts.ds(explicit, fixture.iaca, fixture.iacaKeyPair)
                .subjectPublicKeyInfo(BadCerts.explicitParameters(explicit.getPublic()))
                .build();
        assertReports("DS_KEY_INVALID", Set.of("DS_KEY_INVALID"), AnnexBValidator.validateDs(explicitCertificate, fixture.iaca));
    }

    /** The IACA a DS is checked against may itself be malformed; the DS rules that depend on it report, none throw. */
    @Test
    void aMalformedIacaExtensionDoesNotThrowWhileCheckingADocumentSigner() {
        Fixture fixture = new Fixture();
        X509Certificate iaca = BadCerts.iaca(fixture.iacaKeyPair)
                .subject(BadCerts.name("IN", "Karnataka", "Bad IACA")).issuer(BadCerts.name("IN", "Karnataka", "Bad IACA"))
                .withRaw(Extension.subjectKeyIdentifier, false, NULL)
                .withRaw(Extension.issuerAlternativeName, false, NULL).build();
        // built under the well-formed fixture IACA (same key), then pointed at the malformed one
        X509Certificate ds = BadCerts.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .issuer(BadCerts.name("IN", "Karnataka", "Bad IACA")).build();
        assertEquals(List.of("DS_AKI_MISMATCH", "DS_ISSUER_ALT_NAME_MISMATCH"),
                AnnexBValidator.ruleIds(AnnexBValidator.validateDs(ds, iaca)));
        assertEquals(List.of("IACA_ISSUER_ALT_NAME_MALFORMED", "IACA_SKI_MALFORMED"),
                AnnexBValidator.ruleIds(AnnexBValidator.validateIaca(iaca)));
    }

    // ------------------------------------------------------------------ CRL

    @TestFactory
    Stream<DynamicTest> crlRules() {
        return crlRows().map(row -> DynamicTest.dynamicTest(row.ruleId(), () ->
                assertReports(row.ruleId(), row.allowed(), AnnexBValidator.validateCrl(row.crl(), row.iaca()))));
    }

    private static Stream<CrlRow> crlRows() {
        Fixture fixture = new Fixture();
        X509Certificate iaca = fixture.iaca;
        KeyPair other = BadCerts.ec(256);
        Instant now = Instant.now();
        X509Certificate unreadableIaca = BadCerts.jdkCertificate(BadCerts.patch(BadCerts.encoded(
                BadCerts.iaca(fixture.iacaKeyPair, "IN", "Karnataka")
                        .serial(BigInteger.ONE.shiftLeft(70).add(BigInteger.valueOf(0x5eed))).build()), COUNTRY_IN, SET_IN));
        return Stream.of(
                crl("CRL_ENCODING_INVALID", BadCerts.jdkCrl(BadCerts.patch(BadCerts.encoded(
                        BadCerts.crl(iaca, fixture.iacaKeyPair).build()), COUNTRY_IN, SET_IN)), iaca),
                // the entry date of a revoked serial with a letter in it, constructed by BouncyCastle's provider
                crl("CRL_ENCODING_INVALID", BadCerts.bcCrl(BadCerts.patch(BadCerts.encoded(
                        BadCerts.crl(iaca, fixture.iacaKeyPair).revokeAt(BigInteger.valueOf(42), Date.from(UTC_START))
                                .build()), UTC_START_DER, UTC_START_BROKEN)), iaca),
                crl("CRL_THIS_UPDATE_BEFORE_IACA", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .thisUpdate(Date.from(iaca.getNotBefore().toInstant().minusSeconds(1))).build(), iaca),
                new CrlRow("IACA_ENCODING_INVALID", Set.of("IACA_ENCODING_INVALID"),
                        BadCerts.crl(iaca, fixture.iacaKeyPair).build(), unreadableIaca),
                crl("CRL_ISSUER_MISMATCH", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .issuer(new org.bouncycastle.asn1.x500.X500Name("CN=Another IACA")).build(), iaca),
                crl("CRL_SIGNATURE_INVALID", BadCerts.crl(iaca, fixture.iacaKeyPair).signedBy(other.getPrivate()).build(), iaca),
                // a version 1 CRL keeps the extension list it was given, so only the version and the missing
                // nextUpdate report
                new CrlRow("CRL_VERSION_INVALID", Set.of("CRL_VERSION_INVALID", "CRL_NEXT_UPDATE_MISSING"),
                        BadCerts.crl(iaca, fixture.iacaKeyPair).withoutNextUpdate().buildV1(), iaca),
                crl("CRL_AKI_MISSING", BadCerts.crl(iaca, fixture.iacaKeyPair).without(Extension.authorityKeyIdentifier).build(), iaca),
                crl("CRL_AKI_MISMATCH", BadCerts.crl(iaca, fixture.iacaKeyPair).with(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(BadCerts.keyId(other.getPublic()))).build(), iaca),
                crl("CRL_AKI_CRITICAL", BadCerts.crl(iaca, fixture.iacaKeyPair).critical(Extension.authorityKeyIdentifier, true).build(), iaca),
                crl("CRL_AKI_MALFORMED", BadCerts.crl(iaca, fixture.iacaKeyPair).withRaw(Extension.authorityKeyIdentifier, false,
                        new byte[] {0x30, 0x03, (byte) 0x85, 0x01, 0x00}).build(), iaca),
                crl("CRL_NUMBER_MISSING", BadCerts.crl(iaca, fixture.iacaKeyPair).without(Extension.cRLNumber).build(), iaca),
                crl("CRL_NUMBER_CRITICAL", BadCerts.crl(iaca, fixture.iacaKeyPair).critical(Extension.cRLNumber, true).build(), iaca),
                crl("CRL_NUMBER_INVALID", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .with(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE.shiftLeft(160))).build(), iaca),
                // 2^159 needs 21 DER content octets
                crl("CRL_NUMBER_INVALID", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .with(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE.shiftLeft(159))).build(), iaca),
                // an OCTET STRING where the INTEGER belongs
                crl("CRL_NUMBER_MALFORMED", BadCerts.crl(iaca, fixture.iacaKeyPair).withRaw(Extension.cRLNumber, false,
                        new byte[] {0x04, 0x01, 0x01}).build(), iaca),
                crl("CRL_EXTENSION_UNEXPECTED", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .with(Extension.freshestCRL, false, BadCerts.crlDistributionPoint(BadCerts.CRL_URI)).build(), iaca),
                crl("CRL_ENTRY_EXTENSION_PRESENT", BadCerts.crl(iaca, fixture.iacaKeyPair).revokeWithReason(BigInteger.valueOf(42)).build(), iaca),
                crl("CRL_NEXT_UPDATE_MISSING", BadCerts.crl(iaca, fixture.iacaKeyPair).withoutNextUpdate().build(), iaca),
                crl("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .thisUpdate(Date.from(iaca.getNotBefore().toInstant()))
                        .nextUpdate(Date.from(iaca.getNotBefore().toInstant().minus(Duration.ofDays(2)))).build(), iaca),
                crl("CRL_NEXT_UPDATE_AFTER_IACA", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .nextUpdate(Date.from(iaca.getNotAfter().toInstant().plus(Duration.ofDays(1)))).build(), iaca),
                crl("CRL_THIS_UPDATE_IN_FUTURE", BadCerts.crl(iaca, fixture.iacaKeyPair)
                        .thisUpdate(Date.from(now.plus(Duration.ofMinutes(10)))).build(), iaca),
                crl("CRL_SIGNATURE_ALGORITHM_INVALID", BadCerts.crl(iaca, fixture.iacaKeyPair).signatureAlgorithm("SHA1withECDSA").build(), iaca),
                crl("CRL_SIGNATURE_ALGORITHM_INVALID", BadCerts.crl(iaca, fixture.iacaKeyPair).buildWithAlgorithmParameters(), iaca),
                crl("CRL_SIGNATURE_ALGORITHM_MISMATCH", BadCerts.crl(iaca, fixture.iacaKeyPair).signatureAlgorithm("SHA384withECDSA").build(), iaca),
                crl("CRL_ALGORITHM_IDENTIFIER_MISMATCH", BadCerts.crl(iaca, fixture.iacaKeyPair).buildInnerAlgorithmMismatch(), iaca)
        );
    }

    private static CrlRow crl(String ruleId, X509CRL crl, X509Certificate iaca) {
        return new CrlRow(ruleId, Set.of(ruleId), crl, iaca);
    }

    /** A revoked entry must not carry a reason code, and the production builder never writes one. */
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

    /** thisUpdate is judged against the validation instant the caller passes, with {@link AnnexBValidator#CLOCK_SKEW}. */
    @Test
    void aCrlThisUpdateIsJudgedAgainstTheValidationInstant() {
        Fixture fixture = new Fixture();
        Instant at = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509CRL crl = BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).thisUpdate(Date.from(at.plus(Duration.ofMinutes(4))))
                .build();
        assertConforms(AnnexBValidator.validateCrl(crl, fixture.iaca, at));
        assertReports("CRL_THIS_UPDATE_IN_FUTURE", Set.of("CRL_THIS_UPDATE_IN_FUTURE"),
                AnnexBValidator.validateCrl(crl, fixture.iaca, at.minus(Duration.ofMinutes(2))));
        assertConforms(AnnexBValidator.validateCrl(crl, fixture.iaca, at.plus(Duration.ofDays(1))));
    }

    // ------------------------------------------------------------------ what conforms

    @Test
    void theBaselinesTheRowsMutateConform() {
        Fixture fixture = new Fixture();
        KeyPair keyPair = BadCerts.ec(256);
        assertConforms(AnnexBValidator.validateIaca(BadCerts.iaca(keyPair).build()));
        assertConforms(AnnexBValidator.validateDs(BadCerts.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair).build(),
                fixture.iaca));
        assertConforms(AnnexBValidator.validateCrl(BadCerts.crl(fixture.iaca, fixture.iacaKeyPair).build(), fixture.iaca));
    }

    /** basicConstraints {@code CA:false} on a Document Signer is accepted, critical or not (decision log, 2026-11-13). */
    @Test
    void aDocumentSignerMayCarryBasicConstraintsCaFalse() {
        Fixture fixture = new Fixture();
        for (boolean critical : new boolean[] {true, false}) {
            X509Certificate ds = BadCerts.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                    .with(Extension.basicConstraints, critical, new BasicConstraints(false)).build();
            assertConforms(AnnexBValidator.validateDs(ds, fixture.iaca));
        }
    }

    /** The caps compare the endpoints: exactly 457 days and exactly 20 calendar years are accepted. */
    @Test
    void validityAtTheCapIsAccepted() {
        Fixture fixture = new Fixture();
        Instant iacaStart = fixture.iaca.getNotBefore().toInstant();
        X509Certificate ds = BadCerts.ds(BadCerts.ec(256), fixture.iaca, fixture.iacaKeyPair)
                .notAfter(Date.from(iacaStart.plus(Duration.ofDays(457)))).build();
        assertConforms(AnnexBValidator.validateDs(ds, fixture.iaca));

        Instant start = Instant.parse("2027-02-28T12:00:00Z");
        X509Certificate iaca = BadCerts.iaca(BadCerts.ec(256)).notBefore(Date.from(start))
                .notAfter(Date.from(twentyYears(start))).build();
        assertConforms(AnnexBValidator.validateIaca(iaca));
    }

    /** A 56 bit serial passes the validator's heuristic, though the builders never write one that short. */
    @Test
    void aFiftySixBitSerialPassesTheValidator() {
        assertConforms(AnnexBValidator.validateIaca(BadCerts.iaca(BadCerts.ec(256))
                .serial(BigInteger.ONE.shiftLeft(55)).build()));
    }

    @Test
    void theLargestCrlNumberIsAccepted() {
        Fixture fixture = new Fixture();
        BigInteger largest = BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE);
        assertConforms(AnnexBValidator.validateCrl(BadCerts.crl(fixture.iaca, fixture.iacaKeyPair)
                .with(Extension.cRLNumber, false, new CRLNumber(largest)).build(), fixture.iaca));
        assertConforms(AnnexBValidator.validateCrl(CrlBuilder.forIaca(fixture.iaca, fixture.iacaKeyPair)
                .crlNumber(largest).build(), fixture.iaca));
    }

    /** issuerAltName contact: an absolute URI of any scheme, or an rfc822 mailbox. */
    @Test
    void anIssuerAltNameMayBeAnyAbsoluteUriOrAMailbox() {
        KeyPair keyPair = BadCerts.ec(256);
        for (GeneralNames names : List.of(
                BadCerts.issuerAltNames("mailto:pki@example.test"),
                BadCerts.issuerAltNames("https://credentials.example.test/mdoc/iaca"),
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, "pki.office+mdl@credentials.example.test")))) {
            assertConforms(AnnexBValidator.validateIaca(BadCerts.iaca(keyPair)
                    .with(Extension.issuerAlternativeName, false, names).build()));
        }
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

    /**
     * Runs last. Every rule {@link AnnexBValidator#RULES} publishes must have been the target of a negative test that
     * passed in this run, and every targeted rule must be published. Run the whole class: on its own this test sees
     * no recorded rules.
     */
    @Test
    @Order(Integer.MAX_VALUE)
    void everyRuleHasANegativeTest() {
        Set<String> untested = new TreeSet<>(AnnexBValidator.RULES);
        untested.removeAll(ASSERTED);
        Set<String> unpublished = new TreeSet<>(ASSERTED);
        unpublished.removeAll(AnnexBValidator.RULES);
        assertTrue(untested.isEmpty(), () -> "rules without a passing negative test: " + untested);
        assertTrue(unpublished.isEmpty(), () -> "negative tests for rules the validator does not publish: " + unpublished);
    }
}
