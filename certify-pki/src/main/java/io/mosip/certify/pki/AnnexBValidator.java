package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * Checks a certificate or CRL against the ISO/IEC 18013-5:2021 Annex B profiles as this module implements them. Every
 * failure carries a stable rule identifier a caller can refuse an issuance on, and a message naming the object and the
 * property it misses. Where the module applies its own choice rather than the standard's text (the curve allowlist,
 * the serial heuristic, the accepted {@code CA:false} on a Document Signer, the CRL date rules), the decision log
 * ({@code docs/design/12-risks-and-decisions.md}, 2026-11-13) says so.
 *
 * <p>The validator is deliberately independent of the builders: it re-derives every profile property from the DER, so a
 * certificate an operator obtained elsewhere is held to the same rules as one {@link IsoMdocProfiles} wrote. It never
 * throws on a malformed extension: an extension whose DER cannot be read is reported as {@code *_<EXTENSION>_MALFORMED}
 * and none of its other properties are assessed.
 *
 * <p>Rule identifiers are {@code <PROFILE>_<PROPERTY>}: {@code IACA_*}, {@code DS_*}, {@code CRL_*}. {@link #RULES} lists
 * every identifier the validator can emit; a violation list is unordered and {@link #ruleIds} returns the distinct
 * identifiers in a stable order.
 */
public final class AnnexBValidator {

    /** One named rule failure. {@code ruleId} is one of {@link #RULES} and does not change between releases; messages may. */
    public record Violation(String ruleId, String message) {
        public Violation {
            Objects.requireNonNull(ruleId, "ruleId");
            Objects.requireNonNull(message, "message");
        }

        @Override
        public String toString() {
            return ruleId + ": " + message;
        }
    }

    /** Rules both certificate profiles emit, once as {@code IACA_<rule>} and once as {@code DS_<rule>}. */
    private static final List<String> CERTIFICATE_RULES = List.of(
            "VERSION_INVALID",
            "SERIAL_NOT_POSITIVE", "SERIAL_TOO_SHORT", "SERIAL_TOO_LONG",
            "SUBJECT_COUNTRY_MISSING", "SUBJECT_COUNTRY_DUPLICATE", "SUBJECT_COUNTRY_NOT_PRINTABLE",
            "SUBJECT_COUNTRY_INVALID", "SUBJECT_STATE_DUPLICATE", "SUBJECT_CN_MISSING", "SUBJECT_ENCODING_INVALID",
            "ISSUER_ALT_NAME_MISSING", "ISSUER_ALT_NAME_INVALID", "ISSUER_ALT_NAME_CRITICAL", "ISSUER_ALT_NAME_MALFORMED",
            "CRL_DP_MISSING", "CRL_DP_INVALID", "CRL_DP_CRITICAL", "CRL_DP_MALFORMED",
            "SKI_MISSING", "SKI_MISMATCH", "SKI_CRITICAL", "SKI_MALFORMED",
            "AKI_MISMATCH", "AKI_CRITICAL", "AKI_MALFORMED",
            "UNKNOWN_CRITICAL_EXTENSION",
            "KEY_INVALID",
            "KEY_USAGE_MISSING", "KEY_USAGE_EXTRA", "KEY_USAGE_NOT_CRITICAL", "KEY_USAGE_MALFORMED",
            "BASIC_CONSTRAINTS_MALFORMED",
            "VALIDITY_REVERSED", "VALIDITY_TOO_LONG",
            "SIGNATURE_ALGORITHM_INVALID", "SIGNATURE_ALGORITHM_MISMATCH", "ALGORITHM_IDENTIFIER_MISMATCH");

    private static final List<String> IACA_RULES = List.of(
            "IACA_NOT_SELF_SIGNED",
            "IACA_BASIC_CONSTRAINTS_MISSING", "IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", "IACA_PATHLEN");

    private static final List<String> DS_RULES = List.of(
            "DS_ISSUER_MISMATCH", "DS_SIGNATURE_INVALID",
            "DS_AKI_MISSING",
            "DS_COUNTRY_MISMATCH", "DS_STATE_MISMATCH",
            "DS_ISSUER_ALT_NAME_MISMATCH",
            "DS_EKU_MISSING", "DS_EKU_INVALID", "DS_EKU_NOT_CRITICAL", "DS_EKU_MALFORMED",
            "DS_IS_CA",
            "DS_VALIDITY_OUTSIDE_IACA");

    private static final List<String> CRL_RULES = List.of(
            "CRL_ISSUER_MISMATCH", "CRL_SIGNATURE_INVALID",
            "CRL_SIGNATURE_ALGORITHM_INVALID", "CRL_SIGNATURE_ALGORITHM_MISMATCH", "CRL_ALGORITHM_IDENTIFIER_MISMATCH",
            "CRL_VERSION_INVALID",
            "CRL_AKI_MISSING", "CRL_AKI_MISMATCH", "CRL_AKI_CRITICAL", "CRL_AKI_MALFORMED",
            "CRL_NUMBER_MISSING", "CRL_NUMBER_INVALID", "CRL_NUMBER_CRITICAL", "CRL_NUMBER_MALFORMED",
            "CRL_EXTENSION_UNEXPECTED", "CRL_ENTRY_EXTENSION_PRESENT",
            "CRL_NEXT_UPDATE_MISSING", "CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "CRL_NEXT_UPDATE_AFTER_IACA",
            "CRL_THIS_UPDATE_IN_FUTURE");

    /**
     * Every rule identifier the validator can emit, sorted. A violation with any other identifier is a programming
     * error and fails loudly; the test suite proves each identifier here with a negative test.
     */
    public static final SortedSet<String> RULES = rules();

    /**
     * The shortest serial the validator accepts. Annex B asks for at least 63 bits of CSPRNG output, but entropy cannot
     * be measured from one serial: a serial drawn from 63 random bits is shorter than 56 bits with probability 2^-7.
     * The validator therefore flags only serials shorter than 56 bits as a heuristic, while the builders always write
     * {@value Serials#MIN_BITS} bits or more.
     */
    public static final int MIN_SERIAL_BITS = 56;

    /** How far a CRL's thisUpdate may lie after the validation instant before it is reported as in the future. */
    public static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private static final List<String> COUNTRIES = List.of(Locale.getISOCountries());

    /**
     * Extensions each profile defines. One of these marked critical is judged by its own rule (or allowed); any other
     * extension marked critical is reported as {@code *_UNKNOWN_CRITICAL_EXTENSION}.
     */
    private static final Map<String, Set<String>> PROFILE_EXTENSIONS = Map.of(
            "IACA", Set.of(
                    Extension.subjectKeyIdentifier.getId(),
                    Extension.authorityKeyIdentifier.getId(),
                    Extension.keyUsage.getId(),
                    Extension.basicConstraints.getId(),
                    Extension.issuerAlternativeName.getId(),
                    Extension.cRLDistributionPoints.getId()),
            "DS", Set.of(
                    Extension.subjectKeyIdentifier.getId(),
                    Extension.authorityKeyIdentifier.getId(),
                    Extension.keyUsage.getId(),
                    Extension.extendedKeyUsage.getId(),
                    Extension.basicConstraints.getId(),
                    Extension.issuerAlternativeName.getId(),
                    Extension.cRLDistributionPoints.getId()));

    /** Directory string attributes RFC 5280 section 4.1.2.4 requires as PrintableString or UTF8String. */
    private static final Map<ASN1ObjectIdentifier, String> DIRECTORY_STRINGS = Map.of(
            BCStyle.CN, "common name (CN)",
            BCStyle.O, "organization (O)",
            BCStyle.OU, "organizational unit (OU)",
            BCStyle.ST, "state (ST)",
            BCStyle.L, "locality (L)");

    private AnnexBValidator() {}

    /** IACA profile, ISO/IEC 18013-5:2021 Annex B. An empty list means the certificate conforms. */
    public static List<Violation> validateIaca(X509Certificate iaca) {
        Report report = new Report("IACA");
        version(report, iaca);
        serial(report, iaca);
        subject(report, iaca);
        issuerAltName(report, iaca);
        crlDistributionPoint(report, iaca);
        Ext<byte[]> ski = subjectKeyIdentifier(report, iaca);
        Ext<AuthorityKeyIdentifier> aki = authorityKeyIdentifier(report, iaca);
        if (aki.parsed() && aki.value().getKeyIdentifier() != null && ski.parsed()
                && !Arrays.equals(aki.value().getKeyIdentifier(), ski.value())) {
            report.add("IACA_AKI_MISMATCH", "the authority key identifier is not the subject key identifier");
        }
        unknownCriticalExtension(report, iaca);

        SubjectPublicKeyInfo iacaKey = Certificates.subjectPublicKeyInfo(iaca);
        key(report, iacaKey);
        X500Name subject = Certificates.name(iaca.getSubjectX500Principal());
        X500Name issuer = Certificates.name(iaca.getIssuerX500Principal());
        if (!Arrays.equals(Certificates.der(subject), Certificates.der(issuer))) {
            report.add("IACA_NOT_SELF_SIGNED", "the IACA subject and issuer differ");
        } else if (Certificates.keyProblem(iacaKey) == null && !Certificates.signedBy(iaca, iaca.getPublicKey())) {
            report.add("IACA_NOT_SELF_SIGNED", "the IACA certificate is not signed by its own key");
        }

        keyUsage(report, iaca, (1 << 5) | (1 << 6), "keyCertSign and cRLSign");
        iacaBasicConstraints(report, iaca);
        Instant notBefore = iaca.getNotBefore().toInstant();
        validity(report, iaca, notBefore.atZone(ZoneOffset.UTC).plusYears(20).toInstant(), "20 calendar years");
        signature(report, iaca, curveOf(iacaKey));
        return report.violations();
    }

    /** Document Signer profile of ISO/IEC 18013-5:2021 Annex B, checked against the IACA that issued it. */
    public static List<Violation> validateDs(X509Certificate ds, X509Certificate iaca) {
        Report report = new Report("DS");
        version(report, ds);
        serial(report, ds);
        subject(report, ds);
        List<GeneralName> dsIssuerAltNames = issuerAltName(report, ds);
        crlDistributionPoint(report, ds);
        subjectKeyIdentifier(report, ds);
        Ext<AuthorityKeyIdentifier> aki = authorityKeyIdentifier(report, ds);
        unknownCriticalExtension(report, ds);
        key(report, Certificates.subjectPublicKeyInfo(ds));
        keyUsage(report, ds, 1, "digitalSignature");
        extendedKeyUsage(report, ds);
        dsBasicConstraints(report, ds);

        if (!Arrays.equals(Certificates.der(Certificates.name(ds.getIssuerX500Principal())),
                Certificates.der(Certificates.name(iaca.getSubjectX500Principal())))) {
            report.add("DS_ISSUER_MISMATCH", "the DS issuer is not the IACA subject");
        }
        SubjectPublicKeyInfo iacaKey = Certificates.subjectPublicKeyInfo(iaca);
        if (Certificates.keyProblem(iacaKey) == null && !Certificates.signedBy(ds, iaca.getPublicKey())) {
            report.add("DS_SIGNATURE_INVALID", "the DS certificate is not signed by the IACA key");
        }

        if (!aki.malformed()) {
            byte[] declared = aki.parsed() ? aki.value().getKeyIdentifier() : null;
            byte[] iacaKeyId = keyIdentifierOf(iaca);
            if (declared == null) {
                report.add("DS_AKI_MISSING", "the DS certificate has no authority key identifier keyIdentifier");
            } else if (iacaKeyId == null) {
                report.add("DS_AKI_MISMATCH", "the IACA subject key identifier is malformed, so the DS authority key"
                        + " identifier cannot be matched to it");
            } else if (!Arrays.equals(declared, iacaKeyId)) {
                report.add("DS_AKI_MISMATCH", "the DS authority key identifier is not the IACA subject key identifier");
            }
        }

        String iacaCountry = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.C);
        String dsCountry = Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.C);
        if (dsCountry != null && iacaCountry != null && !dsCountry.equals(iacaCountry)) {
            report.add("DS_COUNTRY_MISMATCH", "the DS country " + dsCountry + " is not the IACA country " + iacaCountry);
        }
        String iacaState = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.ST);
        String dsState = Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.ST);
        if (iacaState != null && !iacaState.equals(dsState)) {
            report.add("DS_STATE_MISMATCH", "the DS state is not the IACA state " + iacaState);
        }

        if (dsIssuerAltNames != null && !dsIssuerAltNames.isEmpty()) {
            Ext<List<GeneralName>> iacaIssuerAltNames = read(iaca, Extension.issuerAlternativeName,
                    AnnexBValidator::generalNames);
            if (!iacaIssuerAltNames.parsed()) {
                report.add("DS_ISSUER_ALT_NAME_MISMATCH", "the IACA issuerAltName is absent or malformed, so the DS"
                        + " issuerAltName cannot be a copy of it");
            } else if (!tagged(dsIssuerAltNames).equals(tagged(iacaIssuerAltNames.value()))) {
                report.add("DS_ISSUER_ALT_NAME_MISMATCH", "the DS issuerAltName is not the IACA issuerAltName");
            }
        }

        Instant notBefore = ds.getNotBefore().toInstant();
        validity(report, ds, notBefore.plus(IsoMdocProfiles.DS_MAX_VALIDITY), IsoMdocProfiles.DS_MAX_VALIDITY.toDays()
                + " days");
        withinIacaValidity(report, ds, iaca);
        signature(report, ds, curveOf(iacaKey));
        return report.violations();
    }

    /** The v2 CRL an IACA publishes at its distribution point, judged at the current instant. */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca) {
        return validateCrl(crl, iaca, Instant.now());
    }

    /**
     * The v2 CRL an IACA publishes at its distribution point, judged at {@code at}: a thisUpdate more
     * than {@link #CLOCK_SKEW} after {@code at} is reported as {@code CRL_THIS_UPDATE_IN_FUTURE}.
     */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca, Instant at) {
        Objects.requireNonNull(at, "at");
        Report report = new Report("CRL");
        if (!Arrays.equals(Certificates.der(Certificates.name(crl.getIssuerX500Principal())),
                Certificates.der(Certificates.name(iaca.getSubjectX500Principal())))) {
            report.add("CRL_ISSUER_MISMATCH", "the CRL issuer is not the IACA subject");
        }
        try {
            crl.verify(iaca.getPublicKey());
        } catch (Exception e) {
            report.add("CRL_SIGNATURE_INVALID", "the CRL is not signed by the IACA key: " + e.getMessage());
        }
        crlSignature(report, crl, iaca);
        if (crl.getVersion() != 2) {
            report.add("CRL_VERSION_INVALID", "the CRL version is " + crl.getVersion()
                    + ", the profile requires an X.509 version 2 CRL");
        }

        Ext<AuthorityKeyIdentifier> aki = read(crl, Extension.authorityKeyIdentifier, AuthorityKeyIdentifier::getInstance);
        if (aki.malformed()) {
            report.add("CRL_AKI_MALFORMED", "the CRL authority key identifier cannot be read: " + aki.problem());
        } else {
            byte[] declared = aki.parsed() ? aki.value().getKeyIdentifier() : null;
            byte[] iacaKeyId = keyIdentifierOf(iaca);
            if (declared == null) {
                report.add("CRL_AKI_MISSING", "the CRL has no authority key identifier keyIdentifier");
            } else if (iacaKeyId == null || !Arrays.equals(declared, iacaKeyId)) {
                report.add("CRL_AKI_MISMATCH", "the CRL authority key identifier is not the IACA subject key identifier");
            }
            if (aki.present() && Certificates.critical(crl, Extension.authorityKeyIdentifier)) {
                report.add("CRL_AKI_CRITICAL", "the CRL authority key identifier is marked critical");
            }
        }
        crlNumber(report, crl);
        crlExtensions(report, crl);
        entryExtensions(report, crl);
        crlDates(report, crl, iaca, at);
        return report.violations();
    }

    /** Every distinct rule id in a stable order, for callers that report one code per failure. */
    public static List<String> ruleIds(List<Violation> violations) {
        return new ArrayList<>(new TreeSet<>(violations.stream().map(Violation::ruleId).toList()));
    }

    // ------------------------------------------------------------------ reporting

    /** The violations of one object; every rule id is checked against {@link #RULES}. */
    private static final class Report {

        private final String profile;
        private final List<Violation> violations = new ArrayList<>();

        Report(String profile) {
            this.profile = profile;
        }

        /** A violation of {@code <profile>_<rule>}, for the checks both certificate profiles share. */
        void fail(String rule, String message) {
            add(profile + "_" + rule, message);
        }

        void add(String ruleId, String message) {
            if (!RULES.contains(ruleId)) {
                throw new IllegalStateException("AnnexBValidator emits a rule it does not publish: " + ruleId);
            }
            violations.add(new Violation(ruleId, message));
        }

        List<Violation> violations() {
            return violations;
        }
    }

    private static SortedSet<String> rules() {
        SortedSet<String> rules = new TreeSet<>();
        for (String rule : CERTIFICATE_RULES) {
            rules.add("IACA_" + rule);
            rules.add("DS_" + rule);
        }
        rules.addAll(IACA_RULES);
        rules.addAll(DS_RULES);
        rules.addAll(CRL_RULES);
        return Collections.unmodifiableSortedSet(rules);
    }

    // ------------------------------------------------------------------ extension parsing

    /** An extension read from the DER: absent, parsed, or present but unreadable ({@link #malformed}). */
    private record Ext<T>(boolean present, T value, String problem) {

        boolean parsed() {
            return present && value != null;
        }

        boolean malformed() {
            return present && value == null;
        }
    }

    private static <T> Ext<T> read(X509Certificate certificate, ASN1ObjectIdentifier oid, Function<ASN1Primitive, T> parser) {
        return read(() -> certificate.getExtensionValue(oid.getId()), parser);
    }

    private static <T> Ext<T> read(X509CRL crl, ASN1ObjectIdentifier oid, Function<ASN1Primitive, T> parser) {
        return read(() -> crl.getExtensionValue(oid.getId()), parser);
    }

    /**
     * Reads one extension value: the OCTET STRING the JCA hands back, then exactly one DER object inside it (trailing
     * octets are an error), then the extension's own structure. Any failure makes the extension malformed.
     */
    private static <T> Ext<T> read(java.util.function.Supplier<byte[]> encoded, Function<ASN1Primitive, T> parser) {
        byte[] wrapped;
        try {
            wrapped = encoded.get();
        } catch (RuntimeException e) {
            return new Ext<>(true, null, describe(e));
        }
        if (wrapped == null) {
            return new Ext<>(false, null, null);
        }
        try {
            byte[] octets = ASN1OctetString.getInstance(wrapped).getOctets();
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(octets);
            if (primitive == null) {
                return new Ext<>(true, null, "the extension value is empty");
            }
            T value = parser.apply(primitive);
            return value == null ? new Ext<>(true, null, "the extension value is empty") : new Ext<>(true, value, null);
        } catch (Exception e) {
            return new Ext<>(true, null, describe(e));
        }
    }

    private static String describe(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    private static byte[] octetString(ASN1Primitive primitive) {
        return ASN1OctetString.getInstance(primitive).getOctets();
    }

    private static List<GeneralName> generalNames(ASN1Primitive primitive) {
        return List.of(GeneralNames.getInstance(primitive).getNames());
    }

    /** The RFC 5280 key usage bits, index 0 digitalSignature through 8 decipherOnly, as {@link X509Certificate#getKeyUsage}. */
    private static boolean[] keyUsageBits(ASN1Primitive primitive) {
        ASN1BitString bits = ASN1BitString.getInstance(primitive);
        byte[] bytes = bits.getBytes();
        boolean[] usage = new boolean[bytes.length * 8 - bits.getPadBits()];
        for (int i = 0; i < usage.length; i++) {
            usage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }
        return usage;
    }

    private static List<String> extendedKeyUsages(ASN1Primitive primitive) {
        List<String> purposes = new ArrayList<>();
        for (KeyPurposeId purpose : ExtendedKeyUsage.getInstance(primitive).getUsages()) {
            purposes.add(purpose.toOID().getId());
        }
        return purposes;
    }

    /** A CRL distribution point, read eagerly so that a malformed one fails here and not halfway through the checks. */
    private record Point(DistributionPointName name, List<GeneralName> names, boolean reasons, boolean crlIssuer) {}

    private static List<Point> distributionPoints(ASN1Primitive primitive) {
        List<Point> points = new ArrayList<>();
        for (DistributionPoint point : CRLDistPoint.getInstance(primitive).getDistributionPoints()) {
            DistributionPointName name = point.getDistributionPoint();
            List<GeneralName> names = name != null && name.getType() == DistributionPointName.FULL_NAME
                    ? List.of(GeneralNames.getInstance(name.getName()).getNames()) : List.of();
            points.add(new Point(name, names, point.getReasons() != null, point.getCRLIssuer() != null));
        }
        return points;
    }

    private static BigInteger integer(ASN1Primitive primitive) {
        return ASN1Integer.getInstance(primitive).getValue();
    }

    /** The IACA's declared subject key identifier, its RFC 5280 method 1 value when absent, null when malformed. */
    private static byte[] keyIdentifierOf(X509Certificate iaca) {
        Ext<byte[]> ski = read(iaca, Extension.subjectKeyIdentifier, AnnexBValidator::octetString);
        if (ski.malformed()) {
            return null;
        }
        return ski.parsed() ? ski.value() : Certificates.keyIdentifier(Certificates.subjectPublicKeyInfo(iaca));
    }

    // ------------------------------------------------------------------ shared certificate checks

    private static void version(Report report, X509Certificate certificate) {
        if (certificate.getVersion() != 3) {
            report.fail("VERSION_INVALID", "the certificate version is v" + certificate.getVersion()
                    + ", the profile requires a version 3 certificate");
        }
    }

    private static void serial(Report report, X509Certificate certificate) {
        BigInteger serial = certificate.getSerialNumber();
        if (serial == null || serial.signum() <= 0) {
            report.fail("SERIAL_NOT_POSITIVE", "the serial number is not a positive integer");
            return;
        }
        if (serial.bitLength() < MIN_SERIAL_BITS) {
            report.fail("SERIAL_TOO_SHORT", "the serial number has " + serial.bitLength() + " bits; Annex B asks for 63"
                    + " bits of CSPRNG output and this validator flags serials shorter than " + MIN_SERIAL_BITS);
        }
        if (Serials.octets(serial) > Serials.MAX_OCTETS) {
            report.fail("SERIAL_TOO_LONG", "the serial number is " + Serials.octets(serial)
                    + " DER content octets, RFC 5280 allows " + Serials.MAX_OCTETS);
        }
    }

    private static void subject(Report report, X509Certificate certificate) {
        X500Name subject = Certificates.name(certificate.getSubjectX500Principal());
        List<AttributeTypeAndValue> countries = Certificates.attributes(subject, BCStyle.C);
        if (countries.isEmpty()) {
            report.fail("SUBJECT_COUNTRY_MISSING", "the subject has no country (C)");
        } else if (countries.size() > 1) {
            report.fail("SUBJECT_COUNTRY_DUPLICATE", "the subject carries " + countries.size() + " country (C) attributes");
        } else {
            country(report, countries.get(0));
        }
        if (Certificates.attributes(subject, BCStyle.ST).size() > 1) {
            report.fail("SUBJECT_STATE_DUPLICATE", "the subject carries more than one state (ST)");
        }
        String commonName = Certificates.attribute(certificate.getSubjectX500Principal(), BCStyle.CN);
        if (commonName == null || commonName.isBlank()) {
            report.fail("SUBJECT_CN_MISSING", "the subject has no common name (CN)");
        }
        for (RDN rdn : subject.getRDNs()) {
            for (AttributeTypeAndValue attribute : rdn.getTypesAndValues()) {
                ASN1Encodable value = attribute.getValue();
                String label = DIRECTORY_STRINGS.get(attribute.getType());
                if (label != null && !(value instanceof ASN1PrintableString) && !(value instanceof ASN1UTF8String)) {
                    report.fail("SUBJECT_ENCODING_INVALID", "the " + label + " is a " + value.getClass().getSimpleName()
                            + "; RFC 5280 section 4.1.2.4 requires a PrintableString or a UTF8String");
                } else if (BCStyle.SERIALNUMBER.equals(attribute.getType()) && !(value instanceof ASN1PrintableString)) {
                    report.fail("SUBJECT_ENCODING_INVALID", "the serialNumber attribute is a "
                            + value.getClass().getSimpleName() + "; X.520 defines it as a PrintableString");
                }
            }
        }
    }

    private static void country(Report report, AttributeTypeAndValue country) {
        if (!(country.getValue() instanceof ASN1PrintableString)) {
            report.fail("SUBJECT_COUNTRY_NOT_PRINTABLE", "the country is a " + country.getValue().getClass().getSimpleName()
                    + "; X.520 countryName is a PrintableString");
        }
        String value = Certificates.string(country.getValue());
        if (!COUNTRIES.contains(value)) {
            report.fail("SUBJECT_COUNTRY_INVALID", "the country " + value + " is not an ISO 3166-1 alpha-2 code");
        }
    }

    /** The issuerAltName names, or null when the extension is absent or malformed. */
    private static List<GeneralName> issuerAltName(Report report, X509Certificate certificate) {
        Ext<List<GeneralName>> extension = read(certificate, Extension.issuerAlternativeName, AnnexBValidator::generalNames);
        if (extension.malformed()) {
            report.fail("ISSUER_ALT_NAME_MALFORMED", "the issuerAltName cannot be read: " + extension.problem());
            return null;
        }
        if (!extension.present() || extension.value().isEmpty()) {
            report.fail("ISSUER_ALT_NAME_MISSING", "the certificate has no issuerAltName URI or email");
            return extension.present() ? extension.value() : null;
        }
        for (GeneralName name : extension.value()) {
            int tag = name.getTagNo();
            String value = Certificates.generalNameValue(name);
            if (tag == GeneralName.uniformResourceIdentifier) {
                if (!Certificates.isAbsoluteUri(value)) {
                    report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName URI " + value + " is not an absolute URI");
                }
            } else if (tag == GeneralName.rfc822Name) {
                if (!Certificates.isMailbox(value)) {
                    report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName email " + value + " is not an rfc822 mailbox");
                }
            } else {
                report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName carries a GeneralName with tag " + tag
                        + "; the profile allows a URI or an rfc822Name");
            }
        }
        if (Certificates.critical(certificate, Extension.issuerAlternativeName)) {
            report.fail("ISSUER_ALT_NAME_CRITICAL", "the issuerAltName is marked critical");
        }
        return extension.value();
    }

    private static Set<String> tagged(List<GeneralName> names) {
        Set<String> values = new LinkedHashSet<>();
        for (GeneralName name : names) {
            values.add(name.getTagNo() + ":" + Certificates.generalNameValue(name));
        }
        return values;
    }

    private static void crlDistributionPoint(Report report, X509Certificate certificate) {
        Ext<List<Point>> extension = read(certificate, Extension.cRLDistributionPoints, AnnexBValidator::distributionPoints);
        if (extension.malformed()) {
            report.fail("CRL_DP_MALFORMED", "the CRL distribution point cannot be read: " + extension.problem());
            return;
        }
        if (!extension.present()) {
            report.fail("CRL_DP_MISSING", "the certificate has no CRL distribution point");
            return;
        }
        if (extension.value().isEmpty()) {
            report.fail("CRL_DP_INVALID", "the CRL distribution point extension names no distribution point");
        }
        for (Point point : extension.value()) {
            if (point.name() == null || point.name().getType() != DistributionPointName.FULL_NAME) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point is not a fullName");
                continue;
            }
            if (point.names().isEmpty()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point names no location");
            }
            for (GeneralName name : point.names()) {
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    report.fail("CRL_DP_INVALID", "the CRL distribution point carries a GeneralName with tag "
                            + name.getTagNo() + "; the profile allows URIs");
                } else if (!Certificates.isHttpUri(Certificates.generalNameValue(name))) {
                    report.fail("CRL_DP_INVALID", "the CRL distribution point " + Certificates.generalNameValue(name)
                            + " is not an absolute http or https URI");
                }
            }
            if (point.reasons()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point restricts the revocation reasons it covers");
            }
            if (point.crlIssuer()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point names a cRLIssuer; the IACA signs its own CRL");
            }
        }
        if (Certificates.critical(certificate, Extension.cRLDistributionPoints)) {
            report.fail("CRL_DP_CRITICAL", "the CRL distribution point is marked critical");
        }
    }

    private static Ext<byte[]> subjectKeyIdentifier(Report report, X509Certificate certificate) {
        Ext<byte[]> extension = read(certificate, Extension.subjectKeyIdentifier, AnnexBValidator::octetString);
        if (extension.malformed()) {
            report.fail("SKI_MALFORMED", "the subject key identifier cannot be read: " + extension.problem());
            return extension;
        }
        if (!extension.present()) {
            report.fail("SKI_MISSING", "the certificate has no subject key identifier");
            return extension;
        }
        SubjectPublicKeyInfo spki = Certificates.subjectPublicKeyInfo(certificate);
        if (Certificates.keyProblem(spki) == null && !Arrays.equals(extension.value(), Certificates.keyIdentifier(spki))) {
            report.fail("SKI_MISMATCH", "the subject key identifier is not the RFC 5280 method 1 SHA-1 of the public key");
        }
        if (Certificates.critical(certificate, Extension.subjectKeyIdentifier)) {
            report.fail("SKI_CRITICAL", "the subject key identifier is marked critical");
        }
        return extension;
    }

    /** The authorityKeyIdentifier, reported when malformed or critical; the key identifier is compared by the caller. */
    private static Ext<AuthorityKeyIdentifier> authorityKeyIdentifier(Report report, X509Certificate certificate) {
        Ext<AuthorityKeyIdentifier> extension = read(certificate, Extension.authorityKeyIdentifier,
                AuthorityKeyIdentifier::getInstance);
        if (extension.malformed()) {
            report.fail("AKI_MALFORMED", "the authority key identifier cannot be read: " + extension.problem());
            return extension;
        }
        if (extension.present() && Certificates.critical(certificate, Extension.authorityKeyIdentifier)) {
            report.fail("AKI_CRITICAL", "the authority key identifier is marked critical");
        }
        return extension;
    }

    private static void unknownCriticalExtension(Report report, X509Certificate certificate) {
        Set<String> critical = certificate.getCriticalExtensionOIDs();
        if (critical == null) {
            return;
        }
        Set<String> known = PROFILE_EXTENSIONS.get(report.profile);
        for (String oid : new TreeSet<>(critical)) {
            if (!known.contains(oid)) {
                report.fail("UNKNOWN_CRITICAL_EXTENSION", "the certificate marks critical an extension the "
                        + report.profile + " profile does not define: " + oid);
            }
        }
    }

    private static void key(Report report, SubjectPublicKeyInfo spki) {
        String problem = Certificates.keyProblem(spki);
        if (problem != null) {
            report.fail("KEY_INVALID", problem);
        }
    }

    /** keyUsage: exactly the {@code required} RFC 5280 bits ({@code 1 << index}), critical. */
    private static void keyUsage(Report report, X509Certificate certificate, int required, String names) {
        Ext<boolean[]> extension = read(certificate, Extension.keyUsage, AnnexBValidator::keyUsageBits);
        if (extension.malformed()) {
            report.fail("KEY_USAGE_MALFORMED", "the keyUsage extension cannot be read: " + extension.problem());
            return;
        }
        if (!extension.present()) {
            report.fail("KEY_USAGE_MISSING", "the certificate has no keyUsage extension");
            return;
        }
        boolean[] usage = extension.value();
        int actual = 0;
        boolean beyond = false;
        for (int bit = 0; bit < usage.length; bit++) {
            if (usage[bit]) {
                if (bit < 31) {
                    actual |= 1 << bit;
                } else {
                    beyond = true;
                }
            }
        }
        if ((actual & required) != required) {
            report.fail("KEY_USAGE_MISSING", "the keyUsage extension does not allow " + names);
        }
        if ((actual & ~required) != 0 || beyond) {
            report.fail("KEY_USAGE_EXTRA", "the keyUsage extension allows more than " + names);
        }
        if (!Certificates.critical(certificate, Extension.keyUsage)) {
            report.fail("KEY_USAGE_NOT_CRITICAL", "the keyUsage extension is not critical");
        }
    }

    private static void extendedKeyUsage(Report report, X509Certificate ds) {
        Ext<List<String>> extension = read(ds, Extension.extendedKeyUsage, AnnexBValidator::extendedKeyUsages);
        if (extension.malformed()) {
            report.add("DS_EKU_MALFORMED", "the extendedKeyUsage extension cannot be read: " + extension.problem());
            return;
        }
        if (!extension.present() || !extension.value().contains(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)) {
            report.add("DS_EKU_MISSING", "the DS extendedKeyUsage does not contain " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE);
        } else if (extension.value().size() > 1) {
            report.add("DS_EKU_INVALID", "the DS extendedKeyUsage carries purposes other than "
                    + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE);
        }
        if (extension.present() && !Certificates.critical(ds, Extension.extendedKeyUsage)) {
            report.add("DS_EKU_NOT_CRITICAL", "the extendedKeyUsage extension is not critical");
        }
    }

    /**
     * A Document Signer may carry basicConstraints {@code CA:false}, critical or not (decision log, 2026-11-13: the
     * 2021 profile lists none and the builder writes none, but an explicit end-entity marker is harmless); {@code CA:true}
     * is refused.
     */
    private static void dsBasicConstraints(Report report, X509Certificate ds) {
        Ext<BasicConstraints> extension = read(ds, Extension.basicConstraints, BasicConstraints::getInstance);
        if (extension.malformed()) {
            report.fail("BASIC_CONSTRAINTS_MALFORMED", "the basicConstraints extension cannot be read: "
                    + extension.problem());
        } else if (extension.parsed() && extension.value().isCA()) {
            report.add("DS_IS_CA", "the DS certificate is a CA certificate (basicConstraints CA:true)");
        }
    }

    private static void iacaBasicConstraints(Report report, X509Certificate iaca) {
        Ext<BasicConstraints> extension = read(iaca, Extension.basicConstraints, BasicConstraints::getInstance);
        if (extension.malformed()) {
            report.fail("BASIC_CONSTRAINTS_MALFORMED", "the basicConstraints extension cannot be read: "
                    + extension.problem());
            return;
        }
        if (!extension.parsed() || !extension.value().isCA()) {
            report.add("IACA_BASIC_CONSTRAINTS_MISSING",
                    "the IACA certificate is not marked as a CA in a basicConstraints extension");
            return;
        }
        if (!Certificates.critical(iaca, Extension.basicConstraints)) {
            report.add("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", "the basicConstraints extension is not critical");
        }
        BigInteger pathLength = extension.value().getPathLenConstraint();
        if (pathLength == null || pathLength.signum() != 0) {
            report.add("IACA_PATHLEN", "the IACA pathLenConstraint is " + (pathLength == null ? "absent" : pathLength)
                    + ", the IACA profile requires 0");
        }
    }

    /**
     * The validity endpoints compared directly: {@code notAfter} must be after {@code notBefore} and no later than
     * {@code limit} (decision log, 2026-11-13).
     */
    private static void validity(Report report, X509Certificate certificate, Instant limit, String cap) {
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant();
        if (!notAfter.isAfter(notBefore)) {
            report.fail("VALIDITY_REVERSED", "notAfter " + notAfter + " is not after notBefore " + notBefore);
            return;
        }
        if (notAfter.isAfter(limit)) {
            report.fail("VALIDITY_TOO_LONG", "notAfter " + notAfter + " is more than " + cap + " after notBefore "
                    + notBefore);
        }
    }

    private static void withinIacaValidity(Report report, X509Certificate ds, X509Certificate iaca) {
        Instant dsNotBefore = ds.getNotBefore().toInstant();
        Instant dsNotAfter = ds.getNotAfter().toInstant();
        Instant iacaNotBefore = iaca.getNotBefore().toInstant();
        Instant iacaNotAfter = iaca.getNotAfter().toInstant();
        if (dsNotBefore.isBefore(iacaNotBefore) || dsNotAfter.isAfter(iacaNotAfter)) {
            report.add("DS_VALIDITY_OUTSIDE_IACA", "the DS validity " + dsNotBefore + " to " + dsNotAfter
                    + " is not inside the IACA validity " + iacaNotBefore + " to " + iacaNotAfter);
        }
    }

    // -------------------------------------------------------------------- signature

    /** The named curve of a key that passed {@link Certificates#keyProblem}, or {@code null} when it did not. */
    private static ASN1ObjectIdentifier curveOf(SubjectPublicKeyInfo spki) {
        if (Certificates.keyProblem(spki) != null) {
            return null;
        }
        return (ASN1ObjectIdentifier) spki.getAlgorithm().getParameters().toASN1Primitive();
    }

    private static void signature(Report report, X509Certificate certificate, ASN1ObjectIdentifier signerCurve) {
        AlgorithmIdentifier outer = outerSignatureAlgorithm(certificate);
        AlgorithmIdentifier inner = innerSignatureAlgorithm(certificate);
        signatureAlgorithm(report, outer, inner, signerCurve, "certificate", "tbsCertificate");
    }

    private static void crlSignature(Report report, X509CRL crl, X509Certificate iaca) {
        AlgorithmIdentifier outer = outerSignatureAlgorithm(crl);
        AlgorithmIdentifier inner = innerSignatureAlgorithm(crl);
        signatureAlgorithm(report, outer, inner, curveOf(Certificates.subjectPublicKeyInfo(iaca)), "CRL", "tbsCertList");
    }

    /**
     * The signature AlgorithmIdentifier: one of {@code ecdsa-with-SHA256/384/512} with its parameters field absent (RFC
     * 5758 section 3.2), identical to the one inside the signed part (RFC 5280 sections 4.1.1.2 and 5.1.1.2) and
     * matching the signer's curve.
     */
    private static void signatureAlgorithm(Report report, AlgorithmIdentifier outer, AlgorithmIdentifier inner,
                                           ASN1ObjectIdentifier signerCurve, String object, String signedPart) {
        ASN1ObjectIdentifier declared = outer == null ? null : outer.getAlgorithm();
        ASN1ObjectIdentifier required = declared == null ? null : Certificates.signatureCurve(declared);
        if (required == null) {
            report.fail("SIGNATURE_ALGORITHM_INVALID", "the " + object + " signature algorithm "
                    + (declared == null ? "cannot be read" : declared.getId()) + " is not ecdsa-with-SHA256/384/512");
        } else if (outer.getParameters() != null) {
            report.fail("SIGNATURE_ALGORITHM_INVALID", "the " + object + " signature algorithm " + declared.getId()
                    + " carries parameters; RFC 5758 section 3.2 requires the parameters field to be absent");
        }
        if (inner == null || !inner.equals(outer)) {
            report.fail("ALGORITHM_IDENTIFIER_MISMATCH", "the " + signedPart + " signature algorithm does not match the "
                    + object + " signature algorithm");
        }
        if (required != null && signerCurve != null && !required.equals(signerCurve)) {
            report.fail("SIGNATURE_ALGORITHM_MISMATCH", "the " + object + " signature algorithm " + declared.getId()
                    + " does not match the " + Certificates.curveName(signerCurve) + " signing key");
        }
    }

    private static AlgorithmIdentifier innerSignatureAlgorithm(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded()).toASN1Structure().getTBSCertificate().getSignature();
        } catch (Exception e) {
            return null;
        }
    }

    private static AlgorithmIdentifier outerSignatureAlgorithm(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded()).getSignatureAlgorithm();
        } catch (Exception e) {
            return null;
        }
    }

    private static AlgorithmIdentifier innerSignatureAlgorithm(X509CRL crl) {
        try {
            return new X509CRLHolder(crl.getEncoded()).toASN1Structure().getTBSCertList().getSignature();
        } catch (Exception e) {
            return null;
        }
    }

    private static AlgorithmIdentifier outerSignatureAlgorithm(X509CRL crl) {
        try {
            return new X509CRLHolder(crl.getEncoded()).toASN1Structure().getSignatureAlgorithm();
        } catch (Exception e) {
            return null;
        }
    }

    // -------------------------------------------------------------------- CRL

    /** RFC 5280 section 5.2.3: a non-negative cRLNumber of at most 20 DER content octets, so at most 2^159 - 1. */
    private static void crlNumber(Report report, X509CRL crl) {
        Ext<BigInteger> extension = read(crl, Extension.cRLNumber, AnnexBValidator::integer);
        if (extension.malformed()) {
            report.add("CRL_NUMBER_MALFORMED", "the cRLNumber cannot be read: " + extension.problem());
            return;
        }
        if (!extension.present()) {
            report.add("CRL_NUMBER_MISSING", "the CRL has no cRLNumber");
            return;
        }
        BigInteger number = extension.value();
        if (!CrlBuilder.fitsCrlNumber(number)) {
            report.add("CRL_NUMBER_INVALID", "the cRLNumber " + number + " is outside 0..2^159-1 (20 DER content octets)");
        }
        if (Certificates.critical(crl, Extension.cRLNumber)) {
            report.add("CRL_NUMBER_CRITICAL", "the cRLNumber is marked critical");
        }
    }

    private static void crlExtensions(Report report, X509CRL crl) {
        Set<String> extensions = new TreeSet<>();
        if (crl.getCriticalExtensionOIDs() != null) {
            extensions.addAll(crl.getCriticalExtensionOIDs());
        }
        if (crl.getNonCriticalExtensionOIDs() != null) {
            extensions.addAll(crl.getNonCriticalExtensionOIDs());
        }
        for (String oid : extensions) {
            if (!Extension.authorityKeyIdentifier.getId().equals(oid) && !Extension.cRLNumber.getId().equals(oid)) {
                report.add("CRL_EXTENSION_UNEXPECTED", "the CRL carries an extension the profile does not define: " + oid);
            }
        }
    }

    /**
     * Revoked entries must carry no entry extensions: the Annex B CRL profile, as the reviewers read it, allows none
     * (decision log, 2026-11-13; the table and its wording are to be confirmed against the purchased ISO text).
     */
    private static void entryExtensions(Report report, X509CRL crl) {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries == null) {
            return;
        }
        for (X509CRLEntry entry : entries) {
            if (entry.hasExtensions()) {
                report.add("CRL_ENTRY_EXTENSION_PRESENT", "the entry for serial " + entry.getSerialNumber()
                        + " carries extensions, which the profile does not allow");
            }
        }
    }

    private static void crlDates(Report report, X509CRL crl, X509Certificate iaca, Instant at) {
        Instant thisUpdate = crl.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(at.plus(CLOCK_SKEW))) {
            report.add("CRL_THIS_UPDATE_IN_FUTURE", "the CRL thisUpdate " + thisUpdate + " is more than " + CLOCK_SKEW
                    + " after the validation instant " + at);
        }
        if (crl.getNextUpdate() == null) {
            report.add("CRL_NEXT_UPDATE_MISSING", "the CRL has no nextUpdate");
            return;
        }
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        if (!nextUpdate.isAfter(thisUpdate)) {
            report.add("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "the CRL nextUpdate is not after thisUpdate");
        }
        Instant iacaNotAfter = iaca.getNotAfter().toInstant();
        if (nextUpdate.isAfter(iacaNotAfter)) {
            report.add("CRL_NEXT_UPDATE_AFTER_IACA", "the CRL nextUpdate " + nextUpdate
                    + " is after the IACA expires at " + iacaNotAfter);
        }
    }
}
