package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Checks a certificate or CRL against the ISO/IEC 18013-5:2021 Annex B profiles. Every failure carries a stable rule
 * identifier a caller can refuse an issuance on, and a message naming the object and the clause it misses.
 *
 * <p>The validator is deliberately independent of the builders: it re-derives every profile property from the DER, so a
 * certificate an operator obtained elsewhere is held to the same rules as one {@link IsoMdocProfiles} wrote.
 *
 * <p>Rule identifiers are {@code <PROFILE>_<PROPERTY>}: {@code IACA_*}, {@code DS_*}, {@code CRL_*}. A violation list is
 * unordered; {@link #ruleIds} returns the distinct identifiers in a stable order.
 */
public final class AnnexBValidator {

    /** One named rule failure. {@code ruleId} does not change between releases; messages may. */
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

    private static final List<String> COUNTRIES = List.of(Locale.getISOCountries());

    /** The extensions Annex B allows on its certificates; anything else marked critical is a violation. */
    private static final Set<String> CERTIFICATE_EXTENSIONS = Set.of(
            Extension.subjectKeyIdentifier.getId(),
            Extension.authorityKeyIdentifier.getId(),
            Extension.keyUsage.getId(),
            Extension.basicConstraints.getId(),
            Extension.extendedKeyUsage.getId(),
            Extension.issuerAlternativeName.getId(),
            Extension.cRLDistributionPoints.getId());

    /** RFC 5280 5.2.3: the CRL number is a non-negative integer of at most 20 octets. */
    private static final BigInteger MAX_CRL_NUMBER = BigInteger.ONE.shiftLeft(159);

    private AnnexBValidator() {}

    /** IACA profile, ISO/IEC 18013-5:2021 Annex B. An empty list means the certificate conforms. */
    public static List<Violation> validateIaca(X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        String profile = "IACA";
        version(violations, iaca, profile);
        serial(violations, iaca, profile);
        subject(violations, iaca, profile);
        issuerAltName(violations, iaca, profile);
        crlDistributionPoint(violations, iaca, profile);
        subjectKeyIdentifier(violations, iaca, profile);
        authorityKeyIdentifier(violations, iaca, profile, true);
        unknownCriticalExtension(violations, iaca, profile);

        SubjectPublicKeyInfo iacaKey = Certificates.subjectPublicKeyInfo(iaca);
        key(violations, iacaKey, profile);
        X500Name subject = Certificates.name(iaca.getSubjectX500Principal());
        X500Name issuer = Certificates.name(iaca.getIssuerX500Principal());
        if (!Arrays.equals(Certificates.der(subject), Certificates.der(issuer))) {
            violations.add(new Violation("IACA_NOT_SELF_SIGNED", "the IACA subject and issuer differ"));
        } else if (Certificates.keyProblem(iacaKey) == null && !Certificates.signedBy(iaca, iaca.getPublicKey())) {
            violations.add(new Violation("IACA_NOT_SELF_SIGNED", "the IACA certificate is not signed by its own key"));
        }

        keyUsage(violations, iaca, profile, KeyUsageProfile.IACA);
        basicConstraints(violations, iaca);
        validity(violations, iaca, IacaCap.INSTANCE, profile);
        signature(violations, iaca, curveOf(iacaKey), profile);
        return violations;
    }

    /** Document Signer profile of ISO/IEC 18013-5:2021 Annex B, checked against the IACA that issued it. */
    public static List<Violation> validateDs(X509Certificate ds, X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        String profile = "DS";
        version(violations, ds, profile);
        serial(violations, ds, profile);
        subject(violations, ds, profile);
        issuerAltName(violations, ds, profile);
        crlDistributionPoint(violations, ds, profile);
        subjectKeyIdentifier(violations, ds, profile);
        authorityKeyIdentifier(violations, ds, profile, false);
        unknownCriticalExtension(violations, ds, profile);
        key(violations, Certificates.subjectPublicKeyInfo(ds), profile);
        keyUsage(violations, ds, profile, KeyUsageProfile.DS);
        extendedKeyUsage(violations, ds);
        basicConstraintsAbsent(violations, ds);

        if (!Arrays.equals(Certificates.der(Certificates.name(ds.getIssuerX500Principal())),
                Certificates.der(Certificates.name(iaca.getSubjectX500Principal())))) {
            violations.add(new Violation("DS_ISSUER_MISMATCH", "the DS issuer is not the IACA subject"));
        }
        SubjectPublicKeyInfo iacaKey = Certificates.subjectPublicKeyInfo(iaca);
        if (Certificates.keyProblem(iacaKey) == null && !Certificates.signedBy(ds, iaca.getPublicKey())) {
            violations.add(new Violation("DS_SIGNATURE_INVALID", "the DS certificate is not signed by the IACA key"));
        }

        byte[] iacaKeyId = Certificates.keyIdentifier(iaca);
        byte[] dsAuthorityKeyIdentifier = Certificates.authorityKeyIdentifier(ds);
        if (dsAuthorityKeyIdentifier == null) {
            violations.add(new Violation("DS_AKI_MISSING", "the DS certificate has no authority key identifier"));
        } else if (!Arrays.equals(dsAuthorityKeyIdentifier, iacaKeyId)) {
            violations.add(new Violation("DS_AKI_MISMATCH",
                    "the DS authority key identifier is not the IACA subject key identifier"));
        }

        String iacaCountry = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.C);
        String dsCountry = Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.C);
        if (dsCountry != null && iacaCountry != null && !dsCountry.equals(iacaCountry)) {
            violations.add(new Violation("DS_COUNTRY_MISMATCH",
                    "the DS country " + dsCountry + " is not the IACA country " + iacaCountry));
        }
        String iacaState = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.ST);
        String dsState = Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.ST);
        if (iacaState != null && !iacaState.equals(dsState)) {
            violations.add(new Violation("DS_STATE_MISMATCH", "the DS state is not the IACA state " + iacaState));
        }

        List<String> dsIssuerAltNames = Certificates.issuerAltNames(ds);
        if (!dsIssuerAltNames.isEmpty()
                && !new LinkedHashSet<>(dsIssuerAltNames).equals(new LinkedHashSet<>(Certificates.issuerAltNames(iaca)))) {
            violations.add(new Violation("DS_ISSUER_ALT_NAME_MISMATCH",
                    "the DS issuerAltName is not the IACA issuerAltName"));
        }

        validity(violations, ds, ConstantCap.of(IsoMdocProfiles.DS_MAX_VALIDITY), profile);
        withinIacaValidity(violations, ds, iaca);
        signature(violations, ds, curveOf(iacaKey), profile);
        return violations;
    }

    /** The v2 CRL profile Annex B requires from the IACA's distribution point. */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        if (!Arrays.equals(Certificates.der(Certificates.name(crl.getIssuerX500Principal())),
                Certificates.der(Certificates.name(iaca.getSubjectX500Principal())))) {
            violations.add(new Violation("CRL_ISSUER_MISMATCH", "the CRL issuer is not the IACA subject"));
        }
        try {
            crl.verify(iaca.getPublicKey());
        } catch (Exception e) {
            violations.add(new Violation("CRL_SIGNATURE_INVALID", "the CRL is not signed by the IACA key: " + e.getMessage()));
        }
        crlSignature(violations, crl, iaca);
        if (crl.getVersion() != 2) {
            violations.add(new Violation("CRL_VERSION_INVALID", "the CRL version is " + crl.getVersion()
                    + ", Annex B requires an X.509 version 2 CRL"));
        }
        byte[] authorityKeyIdentifier = Certificates.authorityKeyIdentifier(crl);
        if (authorityKeyIdentifier == null) {
            violations.add(new Violation("CRL_AKI_MISSING", "the CRL has no authority key identifier"));
        } else if (!Arrays.equals(authorityKeyIdentifier, Certificates.keyIdentifier(iaca))) {
            violations.add(new Violation("CRL_AKI_MISMATCH",
                    "the CRL authority key identifier is not the IACA subject key identifier"));
        }
        if (Certificates.critical(crl, Extension.authorityKeyIdentifier)) {
            violations.add(new Violation("CRL_AKI_CRITICAL", "the CRL authority key identifier is marked critical"));
        }
        crlNumber(violations, crl);
        crlExtensions(violations, crl);
        entryExtensions(violations, crl);
        crlDates(violations, crl);
        return violations;
    }

    /** Every distinct rule id in a stable order, for callers that report one code per failure. */
    public static List<String> ruleIds(List<Violation> violations) {
        return new ArrayList<>(new TreeSet<>(violations.stream().map(Violation::ruleId).toList()));
    }

    // ------------------------------------------------------------------ shared certificate checks

    private static void version(List<Violation> violations, X509Certificate certificate, String profile) {
        if (certificate.getVersion() != 3) {
            violations.add(new Violation(profile + "_VERSION_INVALID", "the certificate version is v"
                    + certificate.getVersion() + ", Annex B requires a version 3 certificate"));
        }
    }

    private static void serial(List<Violation> violations, X509Certificate certificate, String profile) {
        BigInteger serial = certificate.getSerialNumber();
        if (serial == null || serial.signum() <= 0) {
            violations.add(new Violation(profile + "_SERIAL_NOT_POSITIVE", "the serial number is not a positive integer"));
            return;
        }
        if (serial.bitLength() < Serials.MIN_BITS) {
            violations.add(new Violation(profile + "_SERIAL_TOO_SHORT", "the serial number has " + serial.bitLength()
                    + " bits, Annex B requires at least " + Serials.MIN_BITS));
        }
        if (Serials.octets(serial) > Serials.MAX_OCTETS) {
            violations.add(new Violation(profile + "_SERIAL_TOO_LONG", "the serial number is " + Serials.octets(serial)
                    + " DER content octets, RFC 5280 allows " + Serials.MAX_OCTETS));
        }
    }

    private static void subject(List<Violation> violations, X509Certificate certificate, String profile) {
        X500Name subject = Certificates.name(certificate.getSubjectX500Principal());
        List<AttributeTypeAndValue> countries = Certificates.attributes(subject, BCStyle.C);
        if (countries.isEmpty()) {
            violations.add(new Violation(profile + "_SUBJECT_COUNTRY_MISSING", "the subject has no country (C)"));
        } else if (countries.size() > 1) {
            violations.add(new Violation(profile + "_SUBJECT_COUNTRY_DUPLICATE", "the subject carries "
                    + countries.size() + " country (C) attributes"));
        } else {
            country(violations, countries.get(0), profile);
        }
        if (Certificates.attributes(subject, BCStyle.ST).size() > 1) {
            violations.add(new Violation(profile + "_SUBJECT_STATE_DUPLICATE", "the subject carries more than one state (ST)"));
        }
        String commonName = Certificates.attribute(certificate.getSubjectX500Principal(), BCStyle.CN);
        if (commonName == null || commonName.isBlank()) {
            violations.add(new Violation(profile + "_SUBJECT_CN_MISSING", "the subject has no common name (CN)"));
        }
    }

    private static void country(List<Violation> violations, AttributeTypeAndValue country, String profile) {
        if (!(country.getValue() instanceof org.bouncycastle.asn1.ASN1PrintableString)) {
            violations.add(new Violation(profile + "_SUBJECT_COUNTRY_NOT_PRINTABLE",
                    "the country is a " + country.getValue().getClass().getSimpleName() + ", Annex B requires a PrintableString"));
        }
        String value = Certificates.string(country.getValue());
        if (!COUNTRIES.contains(value)) {
            violations.add(new Violation(profile + "_SUBJECT_COUNTRY_INVALID",
                    "the country " + value + " is not an ISO 3166-1 alpha-2 code"));
        }
    }

    private static void issuerAltName(List<Violation> violations, X509Certificate certificate, String profile) {
        List<GeneralName> names = Certificates.issuerAltNameNames(certificate);
        if (names.isEmpty()) {
            violations.add(new Violation(profile + "_ISSUER_ALT_NAME_MISSING",
                    "the certificate has no issuerAltName URI or email"));
        }
        for (GeneralName name : names) {
            int tag = name.getTagNo();
            if (tag != GeneralName.uniformResourceIdentifier && tag != GeneralName.rfc822Name) {
                violations.add(new Violation(profile + "_ISSUER_ALT_NAME_INVALID", "the issuerAltName carries a "
                        + tag + " GeneralName, Annex B allows a URI or an rfc822Name"));
            } else if (tag == GeneralName.uniformResourceIdentifier && !Certificates.isHttpUri(Certificates.generalNameValue(name))) {
                violations.add(new Violation(profile + "_ISSUER_ALT_NAME_INVALID", "the issuerAltName "
                        + Certificates.generalNameValue(name) + " is not an http or https URI"));
            }
        }
        if (Certificates.critical(certificate, Extension.issuerAlternativeName)) {
            violations.add(new Violation(profile + "_ISSUER_ALT_NAME_CRITICAL", "the issuerAltName is marked critical"));
        }
    }

    private static void crlDistributionPoint(List<Violation> violations, X509Certificate certificate, String profile) {
        List<DistributionPoint> points = Certificates.distributionPoints(certificate);
        if (points.isEmpty()) {
            violations.add(new Violation(profile + "_CRL_DP_MISSING", "the certificate has no CRL distribution point"));
        }
        for (DistributionPoint point : points) {
            DistributionPointName name = point.getDistributionPoint();
            if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                violations.add(new Violation(profile + "_CRL_DP_INVALID",
                        "the CRL distribution point is not a fullName"));
                continue;
            }
            GeneralName[] names = GeneralNames.getInstance(name.getName()).getNames();
            if (names.length == 0) {
                violations.add(new Violation(profile + "_CRL_DP_INVALID", "the CRL distribution point names no location"));
            }
            for (GeneralName generalName : names) {
                if (generalName.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    violations.add(new Violation(profile + "_CRL_DP_INVALID", "the CRL distribution point carries a "
                            + generalName.getTagNo() + " GeneralName, Annex B allows URIs"));
                }
            }
            if (point.getReasons() != null) {
                violations.add(new Violation(profile + "_CRL_DP_INVALID",
                        "the CRL distribution point restricts the revocation reasons it covers"));
            }
            if (point.getCRLIssuer() != null) {
                violations.add(new Violation(profile + "_CRL_DP_INVALID",
                        "the CRL distribution point names a cRLIssuer, Annex B has the IACA sign its own CRL"));
            }
        }
        if (Certificates.critical(certificate, Extension.cRLDistributionPoints)) {
            violations.add(new Violation(profile + "_CRL_DP_CRITICAL", "the CRL distribution point is marked critical"));
        }
    }

    private static void subjectKeyIdentifier(List<Violation> violations, X509Certificate certificate, String profile) {
        byte[] declared = Certificates.subjectKeyIdentifier(certificate);
        if (declared == null) {
            violations.add(new Violation(profile + "_SKI_MISSING", "the certificate has no subject key identifier"));
            return;
        }
        SubjectPublicKeyInfo spki = Certificates.subjectPublicKeyInfo(certificate);
        if (Certificates.keyProblem(spki) == null && !Arrays.equals(declared, Certificates.keyIdentifier(spki))) {
            violations.add(new Violation(profile + "_SKI_MISMATCH",
                    "the subject key identifier is not the RFC 5280 method 1 SHA-1 of the public key"));
        }
        if (Certificates.critical(certificate, Extension.subjectKeyIdentifier)) {
            violations.add(new Violation(profile + "_SKI_CRITICAL", "the subject key identifier is marked critical"));
        }
    }

    /**
     * authorityKeyIdentifier on a certificate. For an IACA, which signs itself, the key identifier must be its own
     * subject key identifier ({@code selfReferential}); a Document Signer's authority key identifier points at the
     * IACA instead and is checked in {@link #validateDs}.
     */
    private static void authorityKeyIdentifier(List<Violation> violations, X509Certificate certificate,
                                               String profile, boolean selfReferential) {
        byte[] declared = Certificates.authorityKeyIdentifier(certificate);
        if (declared == null) {
            return;
        }
        if (selfReferential) {
            byte[] subjectKeyIdentifier = Certificates.subjectKeyIdentifier(certificate);
            if (subjectKeyIdentifier != null && !Arrays.equals(declared, subjectKeyIdentifier)) {
                violations.add(new Violation(profile + "_AKI_MISMATCH",
                        "the authority key identifier is not the subject key identifier"));
            }
        }
        if (Certificates.critical(certificate, Extension.authorityKeyIdentifier)) {
            violations.add(new Violation(profile + "_AKI_CRITICAL", "the authority key identifier is marked critical"));
        }
    }

    private static void unknownCriticalExtension(List<Violation> violations, X509Certificate certificate, String profile) {
        Set<String> critical = certificate.getCriticalExtensionOIDs();
        if (critical == null) {
            return;
        }
        for (String oid : critical) {
            if (!CERTIFICATE_EXTENSIONS.contains(oid)) {
                violations.add(new Violation(profile + "_UNKNOWN_CRITICAL_EXTENSION",
                        "the certificate marks an extension Annex B does not define as critical: " + oid));
            }
        }
    }

    private static void key(List<Violation> violations, SubjectPublicKeyInfo spki, String profile) {
        String problem = Certificates.keyProblem(spki);
        if (problem != null) {
            violations.add(new Violation(profile + "_KEY_INVALID", problem));
        }
    }

    private enum KeyUsageProfile { IACA, DS }

    private static void keyUsage(List<Violation> violations, X509Certificate certificate, String profile,
                                 KeyUsageProfile kind) {
        boolean[] usage = certificate.getKeyUsage();
        // getKeyUsage() indexes the RFC 5280 bits: 0 digitalSignature, 5 keyCertSign, 6 cRLSign
        int required = kind == KeyUsageProfile.IACA ? (1 << 5) | (1 << 6) : (1 << 0);
        if (usage == null) {
            violations.add(new Violation(profile + "_KEY_USAGE_MISSING", "the certificate has no keyUsage extension"));
        } else {
            int actual = 0;
            for (int bit = 0; bit < usage.length; bit++) {
                if (usage[bit]) {
                    actual |= 1 << bit;
                }
            }
            if ((actual & required) != required) {
                violations.add(new Violation(profile + "_KEY_USAGE_MISSING", kind == KeyUsageProfile.IACA
                        ? "the keyUsage extension does not allow keyCertSign and cRLSign"
                        : "the keyUsage extension does not allow digitalSignature"));
            }
            int extra = actual & ~required;
            if (extra != 0) {
                violations.add(new Violation(profile + "_KEY_USAGE_EXTRA", "the keyUsage extension allows "
                        + usage(kind) + " which Annex B does not"));
            }
            if (!Certificates.critical(certificate, Extension.keyUsage)) {
                violations.add(new Violation(profile + "_KEY_USAGE_NOT_CRITICAL", "the keyUsage extension is not critical"));
            }
        }
    }

    private static String usage(KeyUsageProfile kind) {
        return kind == KeyUsageProfile.IACA ? "more than keyCertSign and cRLSign" : "more than digitalSignature";
    }

    private static void extendedKeyUsage(List<Violation> violations, X509Certificate ds) {
        List<String> purposes;
        try {
            purposes = ds.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            purposes = null;
        }
        boolean present = Certificates.extension(ds, Extension.extendedKeyUsage) != null;
        if (purposes == null || !purposes.contains(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)) {
            violations.add(new Violation("DS_EKU_MISSING",
                    "the DS extendedKeyUsage does not contain " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE));
        } else if (purposes.size() > 1) {
            violations.add(new Violation("DS_EKU_INVALID",
                    "the DS extendedKeyUsage carries purposes other than " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE));
        }
        if (present && !Certificates.critical(ds, Extension.extendedKeyUsage)) {
            violations.add(new Violation("DS_EKU_NOT_CRITICAL", "the extendedKeyUsage extension is not critical"));
        }
    }

    private static void basicConstraintsAbsent(List<Violation> violations, X509Certificate ds) {
        if (Certificates.extension(ds, Extension.basicConstraints) != null) {
            violations.add(new Violation("DS_BASIC_CONSTRAINTS_PRESENT",
                    "the DS certificate carries basicConstraints, which Annex B does not allow"));
            if (ds.getBasicConstraints() != -1) {
                violations.add(new Violation("DS_IS_CA", "the DS certificate is a CA certificate"));
            }
        }
    }

    private static void basicConstraints(List<Violation> violations, X509Certificate iaca) {
        boolean present = Certificates.extension(iaca, Extension.basicConstraints) != null;
        if (!present || iaca.getBasicConstraints() < 0) {
            violations.add(new Violation("IACA_BASIC_CONSTRAINTS_MISSING",
                    "the IACA certificate is not marked as a CA in a basicConstraints extension"));
            return;
        }
        if (!Certificates.critical(iaca, Extension.basicConstraints)) {
            violations.add(new Violation("IACA_BASIC_CONSTRAINTS_NOT_CRITICAL", "the basicConstraints extension is not critical"));
        }
        if (iaca.getBasicConstraints() != 0) {
            violations.add(new Violation("IACA_PATHLEN",
                    "the IACA pathLenConstraint is " + iaca.getBasicConstraints() + ", Annex B requires 0"));
        }
    }

    /** A validity cap: either a fixed duration or a calendar period measured from {@code notBefore}. */
    private sealed interface ValidityCap {
        Instant cap(Instant notBefore);
    }

    private enum IacaCap implements ValidityCap {
        INSTANCE;

        @Override
        public Instant cap(Instant notBefore) {
            return notBefore.atZone(ZoneOffset.UTC).plus(Period.ofYears(20)).toInstant();
        }
    }

    private record ConstantCap(Duration maximum) implements ValidityCap {
        static ConstantCap of(Duration maximum) {
            return new ConstantCap(maximum);
        }

        @Override
        public Instant cap(Instant notBefore) {
            return notBefore.plus(maximum);
        }
    }

    private static void validity(List<Violation> violations, X509Certificate certificate, ValidityCap cap, String profile) {
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant();
        if (!notAfter.isAfter(notBefore)) {
            violations.add(new Violation(profile + "_VALIDITY_REVERSED",
                    "notAfter " + notAfter + " is not after notBefore " + notBefore));
            return;
        }
        // RFC 5280 4.1.2.5: notAfter is inclusive, so the period is notAfter - notBefore + 1s
        Instant end = notAfter.plusSeconds(1);
        Instant limit = cap.cap(notBefore);
        if (end.isAfter(limit)) {
            violations.add(new Violation(profile + "_VALIDITY_TOO_LONG", "the validity of "
                    + Duration.between(notBefore, end) + " exceeds the cap of " + Duration.between(notBefore, limit)));
        }
    }

    private static void withinIacaValidity(List<Violation> violations, X509Certificate ds, X509Certificate iaca) {
        Instant dsNotBefore = ds.getNotBefore().toInstant();
        Instant dsNotAfter = ds.getNotAfter().toInstant();
        Instant iacaNotBefore = iaca.getNotBefore().toInstant();
        Instant iacaNotAfter = iaca.getNotAfter().toInstant();
        if (dsNotBefore.isBefore(iacaNotBefore) || dsNotAfter.isAfter(iacaNotAfter)) {
            violations.add(new Violation("DS_VALIDITY_OUTSIDE_IACA", "the DS validity " + dsNotBefore + " to "
                    + dsNotAfter + " is not inside the IACA validity " + iacaNotBefore + " to " + iacaNotAfter));
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

    private static void signature(List<Violation> violations, X509Certificate certificate,
                                  ASN1ObjectIdentifier signerCurve, String profile) {
        ASN1ObjectIdentifier declared = new ASN1ObjectIdentifier(certificate.getSigAlgOID());
        ASN1ObjectIdentifier required = Certificates.signatureCurve(declared);
        if (required == null) {
            violations.add(new Violation(profile + "_SIGNATURE_ALGORITHM_INVALID", "the signature algorithm "
                    + declared.getId() + " is not ecdsa-with-SHA256/384/512"));
        }
        AlgorithmIdentifier inner = innerSignatureAlgorithm(certificate);
        if (inner == null || !inner.equals(outerSignatureAlgorithm(certificate))) {
            violations.add(new Violation(profile + "_ALGORITHM_IDENTIFIER_MISMATCH",
                    "the tbsCertificate signature algorithm does not match the certificate signature algorithm"));
        }
        if (required != null && signerCurve != null && !required.equals(signerCurve)) {
            violations.add(new Violation(profile + "_SIGNATURE_ALGORITHM_MISMATCH",
                    "the signature algorithm " + declared.getId() + " does not match the "
                            + signerCurve.getId() + " signing key"));
        }
    }

    private static void crlSignature(List<Violation> violations, X509CRL crl, X509Certificate iaca) {
        ASN1ObjectIdentifier declared = new ASN1ObjectIdentifier(crl.getSigAlgOID());
        ASN1ObjectIdentifier required = Certificates.signatureCurve(declared);
        if (required == null) {
            violations.add(new Violation("CRL_SIGNATURE_ALGORITHM_INVALID", "the CRL signature algorithm "
                    + declared.getId() + " is not ecdsa-with-SHA256/384/512"));
        }
        AlgorithmIdentifier inner = innerSignatureAlgorithm(crl);
        if (inner == null || !inner.equals(outerSignatureAlgorithm(crl))) {
            violations.add(new Violation("CRL_ALGORITHM_IDENTIFIER_MISMATCH",
                    "the tbsCertList signature algorithm does not match the CRL signature algorithm"));
        }
        ASN1ObjectIdentifier iacaCurve = curveOf(Certificates.subjectPublicKeyInfo(iaca));
        if (required != null && iacaCurve != null && !required.equals(iacaCurve)) {
            violations.add(new Violation("CRL_SIGNATURE_ALGORITHM_MISMATCH",
                    "the CRL signature algorithm " + declared.getId() + " does not match the "
                            + iacaCurve.getId() + " IACA key"));
        }
    }

    private static AlgorithmIdentifier innerSignatureAlgorithm(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded()).toASN1Structure()
                    .getTBSCertificate().getSignature();
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

    private static void crlNumber(List<Violation> violations, X509CRL crl) {
        byte[] extension = Certificates.extension(crl, Extension.cRLNumber);
        if (extension == null) {
            violations.add(new Violation("CRL_NUMBER_MISSING", "the CRL has no cRLNumber"));
        } else {
            BigInteger number = crlNumberValue(extension);
            if (number.signum() < 0 || number.compareTo(MAX_CRL_NUMBER) > 0) {
                violations.add(new Violation("CRL_NUMBER_INVALID", "the cRLNumber " + number + " is outside 0..2^159"));
            }
        }
        if (Certificates.critical(crl, Extension.cRLNumber)) {
            violations.add(new Violation("CRL_NUMBER_CRITICAL", "the cRLNumber is marked critical"));
        }
    }

    private static BigInteger crlNumberValue(byte[] extension) {
        try {
            return CRLNumber.getInstance(ASN1Primitive.fromByteArray(extension)).getCRLNumber();
        } catch (IOException e) {
            throw new PkiException("Cannot read the CRL number", e);
        }
    }

    private static void crlExtensions(List<Violation> violations, X509CRL crl) {
        Set<String> extensions = new LinkedHashSet<>();
        if (crl.getCriticalExtensionOIDs() != null) {
            extensions.addAll(crl.getCriticalExtensionOIDs());
        }
        if (crl.getNonCriticalExtensionOIDs() != null) {
            extensions.addAll(crl.getNonCriticalExtensionOIDs());
        }
        for (String oid : extensions) {
            if (!Extension.authorityKeyIdentifier.getId().equals(oid) && !Extension.cRLNumber.getId().equals(oid)) {
                violations.add(new Violation("CRL_EXTENSION_UNEXPECTED",
                        "the CRL carries an extension Annex B does not define: " + oid));
            }
        }
    }

    private static void entryExtensions(List<Violation> violations, X509CRL crl) {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries == null) {
            return;
        }
        for (X509CRLEntry entry : entries) {
            if (entry.hasExtensions()) {
                violations.add(new Violation("CRL_ENTRY_EXTENSION_PRESENT", "the entry for serial "
                        + entry.getSerialNumber() + " carries extensions; Annex B Table B.9 prohibits them"));
            }
        }
    }

    private static void crlDates(List<Violation> violations, X509CRL crl) {
        if (crl.getNextUpdate() == null) {
            violations.add(new Violation("CRL_NEXT_UPDATE_MISSING", "the CRL has no nextUpdate"));
        } else if (crl.getThisUpdate() != null && !crl.getNextUpdate().after(crl.getThisUpdate())) {
            violations.add(new Violation("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "the CRL nextUpdate is not after thisUpdate"));
        }
    }
}
