package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1String;
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
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.cert.X509CRL;
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
 * certificate an operator obtained elsewhere is held to the same rules as one {@link IsoMdocProfiles} wrote.
 *
 * <p><b>It never throws for an object a JCA provider could construct.</b> Each certificate or CRL is read once from its
 * {@code getEncoded()} DER with BouncyCastle's ASN.1 structures, never through the JCA getters (the JDK keeps what it
 * does not understand as raw octets, and BouncyCastle's provider decodes names, dates and extensions lazily, so a getter
 * can throw on first access). An encoding those structures cannot read, or one that is BER but not DER (RFC 5280
 * requires DER), is reported as {@code IACA_ENCODING_INVALID}, {@code DS_ENCODING_INVALID} or
 * {@code CRL_ENCODING_INVALID} and no other property of that object is assessed; an IACA that cannot be read while a
 * Document Signer or CRL is checked against it is reported as {@code IACA_ENCODING_INVALID} and the checks that depend
 * on it are skipped. An extension whose value cannot be read as DER is reported as {@code *_<EXTENSION>_MALFORMED}, a
 * subject string that cannot be decoded as {@code *_SUBJECT_ENCODING_INVALID}. Anything else thrown out of this class
 * is a programming error.
 *
 * <p>A non-conforming object fails under every provider, but the rule it fails with may differ: the JDK keeps the
 * octets it parsed, so a BER encoding re-signed over those octets is {@code *_ENCODING_INVALID}, while BouncyCastle's
 * provider re-encodes the object to DER on construction, so the signature over the original octets no longer verifies
 * ({@code IACA_NOT_SELF_SIGNED}, {@code DS_SIGNATURE_INVALID}, {@code CRL_SIGNATURE_INVALID}).
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
            "ENCODING_INVALID",
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
            "CRL_ENCODING_INVALID",
            "CRL_ISSUER_MISMATCH", "CRL_SIGNATURE_INVALID",
            "CRL_SIGNATURE_ALGORITHM_INVALID", "CRL_SIGNATURE_ALGORITHM_MISMATCH", "CRL_ALGORITHM_IDENTIFIER_MISMATCH",
            "CRL_VERSION_INVALID",
            "CRL_AKI_MISSING", "CRL_AKI_MISMATCH", "CRL_AKI_CRITICAL", "CRL_AKI_MALFORMED",
            "CRL_NUMBER_MISSING", "CRL_NUMBER_INVALID", "CRL_NUMBER_CRITICAL", "CRL_NUMBER_MALFORMED",
            "CRL_EXTENSION_UNEXPECTED", "CRL_ENTRY_EXTENSION_PRESENT",
            "CRL_NEXT_UPDATE_MISSING", "CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "CRL_NEXT_UPDATE_AFTER_IACA",
            "CRL_THIS_UPDATE_IN_FUTURE", "CRL_THIS_UPDATE_BEFORE_IACA");

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

    /**
     * How far a CRL's thisUpdate may lie after the validation instant before it is reported as in the future; the
     * {@link CrlBuilder} refuses a thisUpdate further than this after the instant it builds.
     */
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
        Objects.requireNonNull(iaca, "iaca");
        Report report = new Report("IACA");
        Parsed.Cert certificate = read(report, iaca);
        if (certificate == null) {
            return report.violations();
        }
        version(report, certificate);
        serial(report, certificate);
        subject(report, certificate.subject());
        issuerAltName(report, certificate);
        crlDistributionPoint(report, certificate);
        Ext<byte[]> ski = subjectKeyIdentifier(report, certificate);
        Ext<AuthorityKeyIdentifier> aki = authorityKeyIdentifier(report, certificate);
        if (aki.parsed() && aki.value().getKeyIdentifier() != null && ski.parsed()
                && !Arrays.equals(aki.value().getKeyIdentifier(), ski.value())) {
            report.add("IACA_AKI_MISMATCH", "the authority key identifier is not the subject key identifier");
        }
        unknownCriticalExtension(report, certificate);

        SubjectPublicKeyInfo iacaKey = certificate.spki();
        key(report, iacaKey);
        if (!Certificates.sameName(certificate.subject(), certificate.issuer())) {
            report.add("IACA_NOT_SELF_SIGNED", "the IACA subject and issuer differ");
        } else if (Certificates.keyProblem(iacaKey) == null && !certificate.signedBy(iacaKey)) {
            report.add("IACA_NOT_SELF_SIGNED", "the IACA certificate is not signed by its own key");
        }

        keyUsage(report, certificate, (1 << 5) | (1 << 6), "keyCertSign and cRLSign");
        iacaBasicConstraints(report, certificate);
        validity(report, certificate, certificate.notBefore().atZone(ZoneOffset.UTC).plusYears(20).toInstant(),
                "20 calendar years");
        signature(report, certificate, curveOf(iacaKey));
        return report.violations();
    }

    /**
     * Document Signer profile of ISO/IEC 18013-5:2021 Annex B, checked against the IACA that issued it. An IACA that
     * cannot be read is reported as {@code IACA_ENCODING_INVALID}, and the checks that compare the DS with it are
     * skipped; the DS's own checks still run.
     */
    public static List<Violation> validateDs(X509Certificate ds, X509Certificate iaca) {
        Objects.requireNonNull(ds, "ds");
        Objects.requireNonNull(iaca, "iaca");
        Report report = new Report("DS");
        Parsed.Cert certificate = read(report, ds);
        Parsed.Cert issuer = readIaca(report, iaca);
        if (certificate == null) {
            return report.violations();
        }
        version(report, certificate);
        serial(report, certificate);
        subject(report, certificate.subject());
        List<AltName> dsIssuerAltNames = issuerAltName(report, certificate);
        crlDistributionPoint(report, certificate);
        subjectKeyIdentifier(report, certificate);
        Ext<AuthorityKeyIdentifier> aki = authorityKeyIdentifier(report, certificate);
        unknownCriticalExtension(report, certificate);
        key(report, certificate.spki());
        keyUsage(report, certificate, 1, "digitalSignature");
        extendedKeyUsage(report, certificate);
        dsBasicConstraints(report, certificate);
        validity(report, certificate, certificate.notBefore().plus(IsoMdocProfiles.DS_MAX_VALIDITY),
                IsoMdocProfiles.DS_MAX_VALIDITY.toDays() + " days");
        if (issuer == null) {
            signature(report, certificate, null);
            return report.violations();
        }

        if (!Certificates.sameName(certificate.issuer(), issuer.subject())) {
            report.add("DS_ISSUER_MISMATCH", "the DS issuer is not the IACA subject");
        }
        String keyProblem = Certificates.keyProblem(issuer.spki());
        if (keyProblem != null) {
            report.add("DS_SIGNATURE_INVALID", "the DS signature cannot be verified: the IACA key is outside the key"
                    + " profile (" + keyProblem + ")");
        } else if (!certificate.signedBy(issuer.spki())) {
            report.add("DS_SIGNATURE_INVALID", "the DS certificate is not signed by the IACA key");
        }

        if (!aki.malformed()) {
            byte[] declared = aki.parsed() ? aki.value().getKeyIdentifier() : null;
            byte[] iacaKeyId = keyIdentifierOf(issuer);
            if (declared == null) {
                report.add("DS_AKI_MISSING", "the DS certificate has no authority key identifier keyIdentifier");
            } else if (iacaKeyId == null) {
                report.add("DS_AKI_MISMATCH", "the IACA subject key identifier is malformed, so the DS authority key"
                        + " identifier cannot be matched to it");
            } else if (!Arrays.equals(declared, iacaKeyId)) {
                report.add("DS_AKI_MISMATCH", "the DS authority key identifier is not the IACA subject key identifier");
            }
        }

        ASN1Encodable iacaCountry = Certificates.value(issuer.subject(), BCStyle.C);
        ASN1Encodable dsCountry = Certificates.value(certificate.subject(), BCStyle.C);
        if (dsCountry != null && iacaCountry != null && !Certificates.sameValue(dsCountry, iacaCountry)) {
            report.add("DS_COUNTRY_MISMATCH", "the DS country " + text(dsCountry) + " is not the IACA country "
                    + text(iacaCountry));
        }
        ASN1Encodable iacaState = Certificates.value(issuer.subject(), BCStyle.ST);
        ASN1Encodable dsState = Certificates.value(certificate.subject(), BCStyle.ST);
        if (iacaState != null && (dsState == null || !Certificates.sameValue(dsState, iacaState))) {
            report.add("DS_STATE_MISMATCH", "the DS state is not the IACA state " + text(iacaState));
        }

        if (dsIssuerAltNames != null && !dsIssuerAltNames.isEmpty()) {
            Ext<List<AltName>> iacaIssuerAltNames = read(issuer.extension(Extension.issuerAlternativeName),
                    AnnexBValidator::generalNames);
            if (!iacaIssuerAltNames.parsed()) {
                report.add("DS_ISSUER_ALT_NAME_MISMATCH", "the IACA issuerAltName is absent or malformed, so the DS"
                        + " issuerAltName cannot be a copy of it");
            } else if (!new LinkedHashSet<>(dsIssuerAltNames).equals(new LinkedHashSet<>(iacaIssuerAltNames.value()))) {
                report.add("DS_ISSUER_ALT_NAME_MISMATCH", "the DS issuerAltName is not the IACA issuerAltName");
            }
        }

        withinIacaValidity(report, certificate, issuer);
        signature(report, certificate, curveOf(issuer.spki()));
        return report.violations();
    }

    /** The v2 CRL an IACA publishes at its distribution point, judged at the current instant. */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca) {
        return validateCrl(crl, iaca, Instant.now());
    }

    /**
     * The v2 CRL an IACA publishes at its distribution point, judged at {@code at}: a thisUpdate more than
     * {@link #CLOCK_SKEW} after {@code at} is reported as {@code CRL_THIS_UPDATE_IN_FUTURE}. An IACA that cannot be
     * read is reported as {@code IACA_ENCODING_INVALID}, and the checks that compare the CRL with it are skipped.
     */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca, Instant at) {
        Objects.requireNonNull(crl, "crl");
        Objects.requireNonNull(iaca, "iaca");
        Objects.requireNonNull(at, "at");
        Report report = new Report("CRL");
        Parsed.Crl list;
        try {
            list = Parsed.crl(crl);
        } catch (PkiException e) {
            list = null;
            report.add("CRL_ENCODING_INVALID", e.getMessage());
        }
        Parsed.Cert issuer = readIaca(report, iaca);
        if (list == null) {
            return report.violations();
        }

        if (issuer != null) {
            if (!Certificates.sameName(list.issuer(), issuer.subject())) {
                report.add("CRL_ISSUER_MISMATCH", "the CRL issuer is not the IACA subject");
            }
            String keyProblem = Certificates.keyProblem(issuer.spki());
            if (keyProblem != null) {
                report.add("CRL_SIGNATURE_INVALID", "the CRL signature cannot be verified: the IACA key is outside the"
                        + " key profile (" + keyProblem + ")");
            } else if (!list.signedBy(issuer.spki())) {
                report.add("CRL_SIGNATURE_INVALID", "the CRL is not signed by the IACA key");
            }
        }
        signatureAlgorithm(report, list.outerAlgorithm(), list.innerAlgorithm(),
                issuer == null ? null : curveOf(issuer.spki()), "CRL", "tbsCertList");
        if (list.version() != 2) {
            report.add("CRL_VERSION_INVALID", "the CRL version is " + list.version()
                    + ", the profile requires an X.509 version 2 CRL");
        }

        Ext<AuthorityKeyIdentifier> aki = read(list.extension(Extension.authorityKeyIdentifier),
                AuthorityKeyIdentifier::getInstance);
        if (aki.malformed()) {
            report.add("CRL_AKI_MALFORMED", "the CRL authority key identifier cannot be read: " + aki.problem());
        } else {
            byte[] declared = aki.parsed() ? aki.value().getKeyIdentifier() : null;
            if (declared == null) {
                report.add("CRL_AKI_MISSING", "the CRL has no authority key identifier keyIdentifier");
            } else if (issuer != null) {
                byte[] iacaKeyId = keyIdentifierOf(issuer);
                if (iacaKeyId == null || !Arrays.equals(declared, iacaKeyId)) {
                    report.add("CRL_AKI_MISMATCH", "the CRL authority key identifier is not the IACA subject key"
                            + " identifier");
                }
            }
            if (aki.present() && list.critical(Extension.authorityKeyIdentifier)) {
                report.add("CRL_AKI_CRITICAL", "the CRL authority key identifier is marked critical");
            }
        }
        crlNumber(report, list);
        crlExtensions(report, list);
        entryExtensions(report, list);
        crlDates(report, list, issuer, at);
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

    /** The certificate under validation read from its DER, or {@code null} after reporting {@code <profile>_ENCODING_INVALID}. */
    private static Parsed.Cert read(Report report, X509Certificate certificate) {
        try {
            return Parsed.certificate(certificate);
        } catch (PkiException e) {
            report.fail("ENCODING_INVALID", e.getMessage());
            return null;
        }
    }

    /** The IACA a DS or CRL is checked against, or {@code null} after reporting {@code IACA_ENCODING_INVALID}. */
    private static Parsed.Cert readIaca(Report report, X509Certificate iaca) {
        try {
            return Parsed.certificate(iaca);
        } catch (PkiException e) {
            report.add("IACA_ENCODING_INVALID", "the IACA the " + report.profile + " is checked against cannot be read,"
                    + " so the checks against it are skipped: " + e.getMessage());
            return null;
        }
    }

    /** A value for a message: the decoded string, or the DER in hex when it does not decode. */
    private static String text(ASN1Encodable value) {
        String decoded = Certificates.string(value);
        if (decoded != null) {
            return decoded;
        }
        try {
            return "#" + Hex.toHexString(value.toASN1Primitive().getEncoded());
        } catch (Exception e) {
            return "(unreadable)";
        }
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

    /**
     * Reads one extension value: exactly one DER object inside the extension's OCTET STRING (trailing octets are an
     * error, and so is an encoding that differs from its DER re-encoding, such as a basicConstraints {@code cA} written
     * as BOOLEAN {@code 01}), then the extension's own structure, decoded eagerly by {@code parser}. Any failure makes
     * the extension malformed.
     */
    private static <T> Ext<T> read(Extension extension, Function<ASN1Primitive, T> parser) {
        if (extension == null) {
            return new Ext<>(false, null, null);
        }
        try {
            T value = parser.apply(Parsed.der(extension.getExtnValue().getOctets()));
            return value == null ? new Ext<>(true, null, "the extension value is empty") : new Ext<>(true, value, null);
        } catch (Exception e) {
            return new Ext<>(true, null, Parsed.describe(e));
        }
    }

    private static byte[] octetString(ASN1Primitive primitive) {
        return ASN1OctetString.getInstance(primitive).getOctets();
    }

    /** A GeneralName as its tag and decoded text; equal names are equal records. */
    private record AltName(int tag, String value) {}

    /** The GeneralNames, every value decoded here (a directoryName included) so a failure is a malformed extension. */
    private static List<AltName> generalNames(ASN1Primitive primitive) {
        return altNames(GeneralNames.getInstance(primitive));
    }

    private static List<AltName> altNames(GeneralNames names) {
        List<AltName> values = new ArrayList<>();
        for (GeneralName name : names.getNames()) {
            values.add(new AltName(name.getTagNo(), Certificates.generalNameValue(name)));
        }
        return values;
    }

    /** The RFC 5280 key usage bits, index 0 digitalSignature through 8 decipherOnly, as {@link X509Certificate#getKeyUsage}. */
    private static boolean[] keyUsageBits(ASN1Primitive primitive) {
        ASN1BitString bits = ASN1BitString.getInstance(primitive);
        byte[] bytes = bits.getBytes();
        boolean[] usage = new boolean[Math.max(0, bytes.length * 8 - bits.getPadBits())];
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

    /**
     * A CRL distribution point, read eagerly so that a malformed one fails here and not halfway through the checks:
     * the name's type ({@code null} when the point has no name), its fullName GeneralNames, and whether it restricts
     * reasons or names a cRLIssuer.
     */
    private record Point(Integer type, List<AltName> names, boolean reasons, boolean crlIssuer) {}

    private static List<Point> distributionPoints(ASN1Primitive primitive) {
        List<Point> points = new ArrayList<>();
        for (DistributionPoint point : CRLDistPoint.getInstance(primitive).getDistributionPoints()) {
            DistributionPointName name = point.getDistributionPoint();
            List<AltName> names = name != null && name.getType() == DistributionPointName.FULL_NAME
                    ? altNames(GeneralNames.getInstance(name.getName())) : List.of();
            points.add(new Point(name == null ? null : name.getType(), names, point.getReasons() != null,
                    point.getCRLIssuer() != null));
        }
        return points;
    }

    private static BigInteger integer(ASN1Primitive primitive) {
        return ASN1Integer.getInstance(primitive).getValue();
    }

    /** The IACA's declared subject key identifier, its RFC 5280 method 1 value when absent, null when malformed. */
    private static byte[] keyIdentifierOf(Parsed.Cert iaca) {
        Ext<byte[]> ski = read(iaca.extension(Extension.subjectKeyIdentifier), AnnexBValidator::octetString);
        if (ski.malformed()) {
            return null;
        }
        return ski.parsed() ? ski.value() : Certificates.keyIdentifier(iaca.spki());
    }

    // ------------------------------------------------------------------ shared certificate checks

    private static void version(Report report, Parsed.Cert certificate) {
        if (certificate.version() != 3) {
            report.fail("VERSION_INVALID", "the certificate version is v" + certificate.version()
                    + ", the profile requires a version 3 certificate");
        }
    }

    private static void serial(Report report, Parsed.Cert certificate) {
        BigInteger serial = certificate.serial();
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

    private static void subject(Report report, X500Name subject) {
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
        // a CN that is present but cannot be decoded is reported below as an encoding failure, not as missing
        List<AttributeTypeAndValue> commonNames = Certificates.attributes(subject, BCStyle.CN);
        String commonName = commonNames.isEmpty() ? null : Certificates.string(commonNames.get(0).getValue());
        if (commonNames.isEmpty() || (commonName != null && commonName.isBlank())) {
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
                } else if (value instanceof ASN1String && Certificates.string(value) == null) {
                    report.fail("SUBJECT_ENCODING_INVALID", "the " + (label != null ? label
                            : "attribute " + attribute.getType().getId()) + " cannot be decoded as a "
                            + value.getClass().getSimpleName());
                }
            }
        }
    }

    private static void country(Report report, AttributeTypeAndValue country) {
        ASN1Encodable value = country.getValue();
        if (!(value instanceof ASN1PrintableString)) {
            report.fail("SUBJECT_COUNTRY_NOT_PRINTABLE", "the country is a " + value.getClass().getSimpleName()
                    + "; X.520 countryName is a PrintableString");
        }
        String text = Certificates.string(value);
        if (text != null && !COUNTRIES.contains(text)) {
            report.fail("SUBJECT_COUNTRY_INVALID", "the country " + text + " is not an ISO 3166-1 alpha-2 code");
        }
    }

    /** The issuerAltName names, or null when the extension is absent or malformed. */
    private static List<AltName> issuerAltName(Report report, Parsed.Cert certificate) {
        Ext<List<AltName>> extension = read(certificate.extension(Extension.issuerAlternativeName),
                AnnexBValidator::generalNames);
        if (extension.malformed()) {
            report.fail("ISSUER_ALT_NAME_MALFORMED", "the issuerAltName cannot be read: " + extension.problem());
            return null;
        }
        if (!extension.present() || extension.value().isEmpty()) {
            report.fail("ISSUER_ALT_NAME_MISSING", "the certificate has no issuerAltName URI or email");
            return extension.present() ? extension.value() : null;
        }
        for (AltName name : extension.value()) {
            if (name.tag() == GeneralName.uniformResourceIdentifier) {
                if (!Certificates.isIssuerAltUri(name.value())) {
                    report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName URI " + name.value()
                            + " is not an absolute https, http, mailto or urn URI");
                }
            } else if (name.tag() == GeneralName.rfc822Name) {
                if (!Certificates.isMailbox(name.value())) {
                    report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName email " + name.value()
                            + " is not an rfc822 mailbox");
                }
            } else {
                report.fail("ISSUER_ALT_NAME_INVALID", "the issuerAltName carries a GeneralName with tag " + name.tag()
                        + "; the profile allows a URI or an rfc822Name");
            }
        }
        if (certificate.critical(Extension.issuerAlternativeName)) {
            report.fail("ISSUER_ALT_NAME_CRITICAL", "the issuerAltName is marked critical");
        }
        return extension.value();
    }

    private static void crlDistributionPoint(Report report, Parsed.Cert certificate) {
        Ext<List<Point>> extension = read(certificate.extension(Extension.cRLDistributionPoints),
                AnnexBValidator::distributionPoints);
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
            if (point.type() == null || point.type() != DistributionPointName.FULL_NAME) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point is not a fullName");
                continue;
            }
            if (point.names().isEmpty()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point names no location");
            }
            for (AltName name : point.names()) {
                if (name.tag() != GeneralName.uniformResourceIdentifier) {
                    report.fail("CRL_DP_INVALID", "the CRL distribution point carries a GeneralName with tag "
                            + name.tag() + "; the profile allows URIs");
                } else if (!Certificates.isHttpUri(name.value())) {
                    report.fail("CRL_DP_INVALID", "the CRL distribution point " + name.value()
                            + " is not an absolute http or https URI with a host");
                }
            }
            if (point.reasons()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point restricts the revocation reasons it covers");
            }
            if (point.crlIssuer()) {
                report.fail("CRL_DP_INVALID", "the CRL distribution point names a cRLIssuer; the IACA signs its own CRL");
            }
        }
        if (certificate.critical(Extension.cRLDistributionPoints)) {
            report.fail("CRL_DP_CRITICAL", "the CRL distribution point is marked critical");
        }
    }

    private static Ext<byte[]> subjectKeyIdentifier(Report report, Parsed.Cert certificate) {
        Ext<byte[]> extension = read(certificate.extension(Extension.subjectKeyIdentifier), AnnexBValidator::octetString);
        if (extension.malformed()) {
            report.fail("SKI_MALFORMED", "the subject key identifier cannot be read: " + extension.problem());
            return extension;
        }
        if (!extension.present()) {
            report.fail("SKI_MISSING", "the certificate has no subject key identifier");
            return extension;
        }
        SubjectPublicKeyInfo spki = certificate.spki();
        if (Certificates.keyProblem(spki) == null && !Arrays.equals(extension.value(), Certificates.keyIdentifier(spki))) {
            report.fail("SKI_MISMATCH", "the subject key identifier is not the RFC 5280 method 1 SHA-1 of the public key");
        }
        if (certificate.critical(Extension.subjectKeyIdentifier)) {
            report.fail("SKI_CRITICAL", "the subject key identifier is marked critical");
        }
        return extension;
    }

    /** The authorityKeyIdentifier, reported when malformed or critical; the key identifier is compared by the caller. */
    private static Ext<AuthorityKeyIdentifier> authorityKeyIdentifier(Report report, Parsed.Cert certificate) {
        Ext<AuthorityKeyIdentifier> extension = read(certificate.extension(Extension.authorityKeyIdentifier),
                AuthorityKeyIdentifier::getInstance);
        if (extension.malformed()) {
            report.fail("AKI_MALFORMED", "the authority key identifier cannot be read: " + extension.problem());
            return extension;
        }
        if (extension.present() && certificate.critical(Extension.authorityKeyIdentifier)) {
            report.fail("AKI_CRITICAL", "the authority key identifier is marked critical");
        }
        return extension;
    }

    private static void unknownCriticalExtension(Report report, Parsed.Cert certificate) {
        Set<String> known = PROFILE_EXTENSIONS.get(report.profile);
        for (String oid : certificate.criticalExtensions()) {
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
    private static void keyUsage(Report report, Parsed.Cert certificate, int required, String names) {
        Ext<boolean[]> extension = read(certificate.extension(Extension.keyUsage), AnnexBValidator::keyUsageBits);
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
        if (!certificate.critical(Extension.keyUsage)) {
            report.fail("KEY_USAGE_NOT_CRITICAL", "the keyUsage extension is not critical");
        }
    }

    private static void extendedKeyUsage(Report report, Parsed.Cert ds) {
        Ext<List<String>> extension = read(ds.extension(Extension.extendedKeyUsage), AnnexBValidator::extendedKeyUsages);
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
        if (extension.present() && !ds.critical(Extension.extendedKeyUsage)) {
            report.add("DS_EKU_NOT_CRITICAL", "the extendedKeyUsage extension is not critical");
        }
    }

    /**
     * A Document Signer may carry basicConstraints {@code CA:false}, critical or not (decision log, 2026-11-13: the
     * 2021 profile lists none and the builder writes none, but an explicit end-entity marker is harmless); {@code CA:true}
     * is refused.
     */
    private static void dsBasicConstraints(Report report, Parsed.Cert ds) {
        Ext<BasicConstraints> extension = read(ds.extension(Extension.basicConstraints), BasicConstraints::getInstance);
        if (extension.malformed()) {
            report.fail("BASIC_CONSTRAINTS_MALFORMED", "the basicConstraints extension cannot be read: "
                    + extension.problem());
        } else if (extension.parsed() && extension.value().isCA()) {
            report.add("DS_IS_CA", "the DS certificate is a CA certificate (basicConstraints CA:true)");
        }
    }

    private static void iacaBasicConstraints(Report report, Parsed.Cert iaca) {
        Ext<BasicConstraints> extension = read(iaca.extension(Extension.basicConstraints), BasicConstraints::getInstance);
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
        if (!iaca.critical(Extension.basicConstraints)) {
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
    private static void validity(Report report, Parsed.Cert certificate, Instant limit, String cap) {
        Instant notBefore = certificate.notBefore();
        Instant notAfter = certificate.notAfter();
        if (!notAfter.isAfter(notBefore)) {
            report.fail("VALIDITY_REVERSED", "notAfter " + notAfter + " is not after notBefore " + notBefore);
            return;
        }
        if (notAfter.isAfter(limit)) {
            report.fail("VALIDITY_TOO_LONG", "notAfter " + notAfter + " is more than " + cap + " after notBefore "
                    + notBefore);
        }
    }

    private static void withinIacaValidity(Report report, Parsed.Cert ds, Parsed.Cert iaca) {
        if (ds.notBefore().isBefore(iaca.notBefore()) || ds.notAfter().isAfter(iaca.notAfter())) {
            report.add("DS_VALIDITY_OUTSIDE_IACA", "the DS validity " + ds.notBefore() + " to " + ds.notAfter()
                    + " is not inside the IACA validity " + iaca.notBefore() + " to " + iaca.notAfter());
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

    private static void signature(Report report, Parsed.Cert certificate, ASN1ObjectIdentifier signerCurve) {
        signatureAlgorithm(report, certificate.outerAlgorithm(), certificate.innerAlgorithm(), signerCurve,
                "certificate", "tbsCertificate");
    }

    /**
     * The signature AlgorithmIdentifier: one of {@code ecdsa-with-SHA256/384/512} with its parameters field absent (RFC
     * 5758 section 3.2), identical to the one inside the signed part (RFC 5280 sections 4.1.1.2 and 5.1.1.2) and
     * matching the signer's curve.
     */
    private static void signatureAlgorithm(Report report, AlgorithmIdentifier outer, AlgorithmIdentifier inner,
                                           ASN1ObjectIdentifier signerCurve, String object, String signedPart) {
        ASN1ObjectIdentifier declared = outer.getAlgorithm();
        ASN1ObjectIdentifier required = Certificates.signatureCurve(declared);
        if (required == null) {
            report.fail("SIGNATURE_ALGORITHM_INVALID", "the " + object + " signature algorithm " + declared.getId()
                    + " is not ecdsa-with-SHA256/384/512");
        } else if (outer.getParameters() != null) {
            report.fail("SIGNATURE_ALGORITHM_INVALID", "the " + object + " signature algorithm " + declared.getId()
                    + " carries parameters; RFC 5758 section 3.2 requires the parameters field to be absent");
        }
        if (!inner.equals(outer)) {
            report.fail("ALGORITHM_IDENTIFIER_MISMATCH", "the " + signedPart + " signature algorithm does not match the "
                    + object + " signature algorithm");
        }
        if (required != null && signerCurve != null && !required.equals(signerCurve)) {
            report.fail("SIGNATURE_ALGORITHM_MISMATCH", "the " + object + " signature algorithm " + declared.getId()
                    + " does not match the " + Certificates.curveName(signerCurve) + " signing key");
        }
    }

    // -------------------------------------------------------------------- CRL

    /** RFC 5280 section 5.2.3: a non-negative cRLNumber of at most 20 DER content octets, so at most 2^159 - 1. */
    private static void crlNumber(Report report, Parsed.Crl crl) {
        Ext<BigInteger> extension = read(crl.extension(Extension.cRLNumber), AnnexBValidator::integer);
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
        if (crl.critical(Extension.cRLNumber)) {
            report.add("CRL_NUMBER_CRITICAL", "the cRLNumber is marked critical");
        }
    }

    private static void crlExtensions(Report report, Parsed.Crl crl) {
        for (String oid : crl.extensionOids()) {
            if (!Extension.authorityKeyIdentifier.getId().equals(oid) && !Extension.cRLNumber.getId().equals(oid)) {
                report.add("CRL_EXTENSION_UNEXPECTED", "the CRL carries an extension the profile does not define: " + oid);
            }
        }
    }

    /**
     * Revoked entries must carry no entry extensions: the Annex B CRL profile, as the reviewers read it, allows none
     * (decision log, 2026-11-13; the table and its wording are to be confirmed against the purchased ISO text).
     */
    private static void entryExtensions(Report report, Parsed.Crl crl) {
        for (Parsed.Entry entry : crl.entries()) {
            if (entry.hasExtensions()) {
                report.add("CRL_ENTRY_EXTENSION_PRESENT", "the entry for serial " + entry.serial()
                        + " carries extensions, which the profile does not allow");
            }
        }
    }

    /**
     * thisUpdate not more than {@link #CLOCK_SKEW} after {@code at} and not before the IACA's notBefore; nextUpdate
     * present, after thisUpdate and not after the IACA's notAfter (decision log, 2026-11-13). The IACA-dependent
     * checks are skipped when the IACA cannot be read.
     */
    private static void crlDates(Report report, Parsed.Crl crl, Parsed.Cert iaca, Instant at) {
        Instant thisUpdate = crl.thisUpdate();
        if (thisUpdate.isAfter(at.plus(CLOCK_SKEW))) {
            report.add("CRL_THIS_UPDATE_IN_FUTURE", "the CRL thisUpdate " + thisUpdate + " is more than " + CLOCK_SKEW
                    + " after the validation instant " + at);
        }
        if (iaca != null && thisUpdate.isBefore(iaca.notBefore())) {
            report.add("CRL_THIS_UPDATE_BEFORE_IACA", "the CRL thisUpdate " + thisUpdate
                    + " is before the IACA is valid from " + iaca.notBefore());
        }
        if (crl.nextUpdate() == null) {
            report.add("CRL_NEXT_UPDATE_MISSING", "the CRL has no nextUpdate");
            return;
        }
        Instant nextUpdate = crl.nextUpdate();
        if (!nextUpdate.isAfter(thisUpdate)) {
            report.add("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "the CRL nextUpdate is not after thisUpdate");
        }
        if (iaca != null && nextUpdate.isAfter(iaca.notAfter())) {
            report.add("CRL_NEXT_UPDATE_AFTER_IACA", "the CRL nextUpdate " + nextUpdate
                    + " is after the IACA expires at " + iaca.notAfter());
        }
    }
}
