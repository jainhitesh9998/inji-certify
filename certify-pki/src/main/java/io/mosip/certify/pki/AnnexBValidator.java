package io.mosip.certify.pki;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;

import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Checks a certificate or CRL against the ISO/IEC 18013-5:2021 Annex B profiles. Every failure carries a stable rule
 * identifier a caller can refuse an issuance on, and a message naming the certificate and the clause it misses.
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

    private static final String COUNTRY = "[A-Z]{2}";

    private AnnexBValidator() {}

    /** IACA profile, ISO/IEC 18013-5:2021 Annex B. An empty list means the certificate conforms. */
    public static List<Violation> validateIaca(X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        serial(violations, iaca, "IACA");
        String country = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.C);
        if (country == null) {
            violations.add(new Violation("IACA_SUBJECT_COUNTRY_MISSING", "the IACA subject has no country (C)"));
        } else if (!country.matches(COUNTRY)) {
            violations.add(new Violation("IACA_SUBJECT_COUNTRY_INVALID",
                    "the IACA country " + country + " is not an ISO 3166-1 alpha-2 code"));
        }
        if (Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.CN) == null) {
            violations.add(new Violation("IACA_SUBJECT_CN_MISSING", "the IACA subject has no common name (CN)"));
        }
        if (!iaca.getSubjectX500Principal().equals(iaca.getIssuerX500Principal())) {
            violations.add(new Violation("IACA_NOT_SELF_SIGNED", "the IACA subject and issuer differ"));
        } else if (!Certificates.signedBy(iaca, iaca.getPublicKey())) {
            violations.add(new Violation("IACA_NOT_SELF_SIGNED", "the IACA certificate is not signed by its own key"));
        }
        issuerAltName(violations, iaca, "IACA");
        if (Certificates.crlDistributionPointUris(iaca).isEmpty()) {
            violations.add(new Violation("IACA_CRL_DP_MISSING", "the IACA certificate has no CRL distribution point URI"));
        }
        if (Certificates.subjectKeyIdentifier(iaca) == null) {
            violations.add(new Violation("IACA_SKI_MISSING", "the IACA certificate has no subject key identifier"));
        }
        keyUsage(violations, iaca, "IACA", true);
        basicConstraints(violations, iaca);
        validity(violations, iaca, IsoMdocProfiles.IACA_MAX_VALIDITY, "IACA_VALIDITY_TOO_LONG");
        signature(violations, iaca, "IACA");
        return violations;
    }

    /** Document Signer profile of ISO/IEC 18013-5:2021 Annex B, checked against the IACA that issued it. */
    public static List<Violation> validateDs(X509Certificate ds, X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        serial(violations, ds, "DS");
        if (!ds.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) {
            violations.add(new Violation("DS_ISSUER_MISMATCH", "the DS issuer is not the IACA subject"));
        }
        if (!Certificates.signedBy(ds, iaca.getPublicKey())) {
            violations.add(new Violation("DS_SIGNATURE_INVALID", "the DS certificate is not signed by the IACA key"));
        }
        String iacaCountry = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.C);
        String dsCountry = Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.C);
        if (dsCountry == null) {
            violations.add(new Violation("DS_COUNTRY_MISSING", "the DS subject has no country (C)"));
        } else if (!dsCountry.equals(iacaCountry)) {
            violations.add(new Violation("DS_COUNTRY_MISMATCH",
                    "the DS country " + dsCountry + " is not the IACA country " + iacaCountry));
        }
        String iacaState = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.ST);
        if (iacaState != null && !iacaState.equals(Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.ST))) {
            violations.add(new Violation("DS_STATE_MISMATCH",
                    "the DS state is not the IACA state " + iacaState));
        }
        if (Certificates.attribute(ds.getSubjectX500Principal(), BCStyle.CN) == null) {
            violations.add(new Violation("DS_SUBJECT_CN_MISSING", "the DS subject has no common name (CN)"));
        }
        byte[] authorityKeyIdentifier = Certificates.authorityKeyIdentifier(ds);
        if (authorityKeyIdentifier == null) {
            violations.add(new Violation("DS_AKI_MISSING", "the DS certificate has no authority key identifier"));
        } else if (!java.util.Arrays.equals(authorityKeyIdentifier, Certificates.keyIdentifier(iaca))) {
            violations.add(new Violation("DS_AKI_MISMATCH", "the DS authority key identifier is not the IACA subject key identifier"));
        }
        if (Certificates.subjectKeyIdentifier(ds) == null) {
            violations.add(new Violation("DS_SKI_MISSING", "the DS certificate has no subject key identifier"));
        }
        keyUsage(violations, ds, "DS", false);
        extendedKeyUsage(violations, ds);
        issuerAltName(violations, ds, "DS");
        List<String> dsIssuerAltNames = issuerAltNames(ds);
        if (!dsIssuerAltNames.isEmpty()
                && !new HashSet<>(dsIssuerAltNames).equals(new HashSet<>(issuerAltNames(iaca)))) {
            violations.add(new Violation("DS_ISSUER_ALT_NAME_MISMATCH", "the DS issuerAltName is not the IACA issuerAltName"));
        }
        if (Certificates.crlDistributionPointUris(ds).isEmpty()) {
            violations.add(new Violation("DS_CRL_DP_MISSING", "the DS certificate has no CRL distribution point URI"));
        }
        validity(violations, ds, IsoMdocProfiles.DS_MAX_VALIDITY, "DS_VALIDITY_TOO_LONG");
        if (Certificates.extension(ds, Extension.basicConstraints) != null) {
            violations.add(new Violation("DS_BASIC_CONSTRAINTS_PRESENT",
                    "the DS certificate carries basicConstraints, which Annex B does not allow"));
            if (ds.getBasicConstraints() != -1) {
                violations.add(new Violation("DS_IS_CA", "the DS certificate is a CA certificate"));
            }
        }
        return violations;
    }

    /** The v2 CRL profile Annex B requires from the IACA's distribution point. */
    public static List<Violation> validateCrl(X509CRL crl, X509Certificate iaca) {
        List<Violation> violations = new ArrayList<>();
        if (!crl.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) {
            violations.add(new Violation("CRL_ISSUER_MISMATCH", "the CRL issuer is not the IACA subject"));
        }
        try {
            crl.verify(iaca.getPublicKey());
        } catch (Exception e) {
            violations.add(new Violation("CRL_SIGNATURE_INVALID", "the CRL is not signed by the IACA key: " + e.getMessage()));
        }
        if (crl.getVersion() != 2) {
            violations.add(new Violation("CRL_VERSION_INVALID", "the CRL is not an X.509 version 2 CRL"));
        }
        byte[] extension = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (extension == null) {
            violations.add(new Violation("CRL_AKI_MISSING", "the CRL has no authority key identifier"));
        } else {
            byte[] keyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
                    .getInstance(org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets())
                    .getKeyIdentifier();
            if (!java.util.Arrays.equals(keyIdentifier, Certificates.keyIdentifier(iaca))) {
                violations.add(new Violation("CRL_AKI_MISMATCH", "the CRL authority key identifier is not the IACA subject key identifier"));
            }
        }
        if (crl.getExtensionValue(Extension.cRLNumber.getId()) == null) {
            violations.add(new Violation("CRL_NUMBER_MISSING", "the CRL has no cRLNumber"));
        }
        if (crl.getNextUpdate() == null) {
            violations.add(new Violation("CRL_NEXT_UPDATE_MISSING", "the CRL has no nextUpdate"));
        } else if (!crl.getNextUpdate().after(crl.getThisUpdate())) {
            violations.add(new Violation("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE", "the CRL nextUpdate is not after thisUpdate"));
        }
        return violations;
    }

    private static void serial(List<Violation> violations, X509Certificate certificate, String profile) {
        if (certificate.getSerialNumber().signum() <= 0) {
            violations.add(new Violation(profile + "_SERIAL_NOT_POSITIVE", "the serial number is not a positive integer"));
        } else if (!Serials.fits(certificate.getSerialNumber())) {
            violations.add(new Violation("SERIAL_TOO_LONG",
                    "the serial number " + certificate.getSerialNumber().bitLength() + " bits exceeds 20 octets"));
        }
    }

    private static void issuerAltName(List<Violation> violations, X509Certificate certificate, String profile) {
        if (issuerAltNames(certificate).isEmpty()) {
            violations.add(new Violation(profile + "_ISSUER_ALT_NAME_MISSING",
                    "the certificate has no issuerAltName URI or email"));
        }
        if (Certificates.critical(certificate, Extension.issuerAlternativeName)) {
            violations.add(new Violation(profile + "_ISSUER_ALT_NAME_CRITICAL", "the issuerAltName is marked critical"));
        }
    }

    private static List<String> issuerAltNames(X509Certificate certificate) {
        return Certificates.issuerAltNames(certificate);
    }

    private static void keyUsage(List<Violation> violations, X509Certificate certificate, String profile, boolean ca) {
        boolean[] usage = certificate.getKeyUsage();
        boolean keyCertSign = usage != null && usage[5];
        boolean crlSign = usage != null && usage[6];
        boolean required = ca ? keyCertSign && crlSign : usage != null && usage[0];
        if (!required) {
            violations.add(new Violation(profile + "_KEY_USAGE_MISSING", ca
                    ? "the keyUsage extension does not allow keyCertSign and cRLSign"
                    : "the keyUsage extension does not allow digitalSignature"));
            return;
        }
        if (!Certificates.critical(certificate, Extension.keyUsage)) {
            violations.add(new Violation(profile + "_KEY_USAGE_NOT_CRITICAL", "the keyUsage extension is not critical"));
        }
        if (!ca && (usage[1] || usage[2] || usage[3] || usage[4] || keyCertSign || crlSign || usage[7] || usage[8])) {
            violations.add(new Violation("DS_KEY_USAGE_EXTRA", "the DS keyUsage allows more than digitalSignature"));
        }
    }

    private static void extendedKeyUsage(List<Violation> violations, X509Certificate ds) {
        List<String> purposes;
        try {
            purposes = ds.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            purposes = null;
        }
        if (purposes == null || !purposes.contains(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)) {
            violations.add(new Violation("DS_EKU_MISSING",
                    "the DS extendedKeyUsage does not contain " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE));
            return;
        }
        if (!Certificates.critical(ds, Extension.extendedKeyUsage)) {
            violations.add(new Violation("DS_EKU_NOT_CRITICAL", "the extendedKeyUsage extension is not critical"));
        }
        if (purposes.size() > 1) {
            violations.add(new Violation("DS_EKU_INVALID",
                    "the DS extendedKeyUsage carries purposes other than " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE));
        }
    }

    private static void basicConstraints(List<Violation> violations, X509Certificate iaca) {
        boolean present = Certificates.extension(iaca, Extension.basicConstraints) != null;
        if (!present || iaca.getBasicConstraints() < 0) {
            violations.add(new Violation("IACA_BASIC_CONSTRAINTS_MISSING",
                    "the IACA certificate is not marked as a CA in a critical basicConstraints extension"));
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

    private static void validity(List<Violation> violations, X509Certificate certificate, Duration maximum, String ruleId) {
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant();
        if (Duration.between(notBefore, notAfter).compareTo(maximum) > 0) {
            violations.add(new Violation(ruleId, "the validity of " + Duration.between(notBefore, notAfter)
                    + " exceeds " + maximum));
        }
    }

    private static void signature(List<Violation> violations, X509Certificate iaca, String profile) {
        int expectedBits = Certificates.signatureCurveBits(iaca.getSigAlgOID());
        if (expectedBits == 0) {
            violations.add(new Violation(profile + "_SIGNATURE_ALGORITHM_INVALID",
                    "the signature algorithm " + iaca.getSigAlgName() + " is not ecdsa-with-SHA256/384/512"));
            return;
        }
        PublicKey key = iaca.getPublicKey();
        if (!(key instanceof ECPublicKey ec)) {
            violations.add(new Violation(profile + "_SIGNATURE_ALGORITHM_MISMATCH",
                    "an " + key.getAlgorithm() + " key cannot carry " + iaca.getSigAlgName()));
            return;
        }
        int bits = ec.getParams().getCurve().getField().getFieldSize();
        if (bits != expectedBits) {
            violations.add(new Violation(profile + "_SIGNATURE_ALGORITHM_MISMATCH",
                    "the " + bits + " bit key does not match " + iaca.getSigAlgName()));
        }
    }

    /** Every distinct rule id in the given violations, for callers that report one code per failure. */
    public static List<String> ruleIds(List<Violation> violations) {
        return new ArrayList<>(new HashSet<>(violations.stream().map(Violation::ruleId).toList()));
    }
}
