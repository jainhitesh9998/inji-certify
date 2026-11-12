package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * ISO/IEC 18013-5:2021 Annex B certificate profiles.
 *
 * <p>An IACA certificate is a self-signed root with a country and a common name in its subject, an issuerAltName, a
 * CRL distribution point, a subject key identifier, {@code keyUsage = keyCertSign + cRLSign} (critical),
 * {@code basicConstraints = CA:true, pathLen:0} (critical), a lifetime of at most 20 years and an
 * {@code ecdsa-with-SHA256/384/512} signature matching a P-256/384/521 key.
 *
 * <p>A Document Signer certificate is issued by an IACA: the issuer is the IACA subject DER unchanged, the country and
 * state come from the IACA's subject with their original ASN.1 string types, the authority key identifier is the IACA
 * subject key identifier, it has its own subject key identifier, {@code keyUsage = digitalSignature} (critical), the
 * document signer extended key usage {@value #DS_EXTENDED_KEY_USAGE} (critical), the IACA issuerAltName, a CRL
 * distribution point, no basicConstraints, and a lifetime of at most 457 days, inside the IACA's own validity.
 *
 * <p>Builders refuse input the profile cannot represent rather than write a certificate a verifier would reject: a
 * validity shorter than {@link #MIN_VALIDITY} or longer than the cap, a Document Signer that clamping to its IACA would
 * leave shorter than {@link #MIN_VALIDITY}, a serial outside RFC 5280 or shorter than {@value Serials#MIN_BITS} bits, an
 * empty or over-long subject attribute, a country that is not an ISO 3166-1 alpha-2 code, an issuerAltName that is
 * neither an absolute URI nor a mailbox, a CRL distribution point that is not an http(s) URI, a key outside the
 * P-256/384/521 allowlist of this module and an IACA that fails {@link AnnexBValidator}. Every refusal message starts
 * with a rule identifier.
 *
 * <p>Builders accept either a freshly generated key pair or the public key of a PKCS#10 request ({@link Csr}); the IACA
 * is self-signed by definition, so it always takes its own key pair.
 */
public final class IsoMdocProfiles {

    /** The document signer extended key usage of ISO/IEC 18013-5:2021 Annex B. */
    public static final String DS_EXTENDED_KEY_USAGE = "1.0.18013.5.1.2";

    /** Annex B caps the IACA lifetime at 20 years: 7305 days, leap days included. */
    public static final Duration IACA_MAX_VALIDITY = Duration.ofDays(7_305);

    /** Annex B caps the Document Signer certificate lifetime at 457 days. */
    public static final Duration DS_MAX_VALIDITY = Duration.ofDays(457);

    /**
     * The shortest validity a builder writes, for the IACA and for a Document Signer after clamping. Annex B sets no
     * minimum; this one keeps every certificate well clear of {@code notAfter <= notBefore} (decision log, 2026-11-13).
     */
    public static final Duration MIN_VALIDITY = Duration.ofHours(1);

    /** RFC 5280 Appendix A upper bounds: ub-common-name and ub-organization-name 64, ub-state-name 128. */
    static final int MAX_COMMON_NAME = 64;
    static final int MAX_ORGANIZATION = 64;
    static final int MAX_STATE = 128;

    /** The ISO 3166-1 alpha-2 codes an IACA or DS subject country must come from. */
    private static final List<String> COUNTRIES = List.of(Locale.getISOCountries());

    private IsoMdocProfiles() {}

    /** A self-signed IACA certificate for the given key pair. */
    public static IacaBuilder iaca(KeyPair keyPair) {
        return new IacaBuilder(keyPair);
    }

    /** A Document Signer certificate for a generated key pair, issued by the IACA. */
    public static DsBuilder ds(KeyPair subjectKeyPair, X509Certificate iaca, KeyPair iacaKeyPair) {
        return new DsBuilder(Objects.requireNonNull(subjectKeyPair, "subjectKeyPair").getPublic(), iaca, iacaKeyPair);
    }

    /**
     * A Document Signer certificate for the public key of a PKCS#10 request, issued by the IACA. The key is checked
     * against the same allowlist as any other: a CSR is an untrusted input.
     */
    public static DsBuilder ds(PublicKey subjectPublicKey, X509Certificate iaca, KeyPair iacaKeyPair) {
        return new DsBuilder(subjectPublicKey, iaca, iacaKeyPair);
    }

    /** Builder for an IACA certificate, ISO/IEC 18013-5:2021 Annex B. */
    public static final class IacaBuilder {

        private final KeyPair keyPair;
        private String country;
        private String state;
        private String organization;
        private String commonName;
        private String issuerAltUri;
        private String issuerAltEmail;
        private String crlDistributionPoint;
        private Instant notBefore = Instant.now();
        private Duration validity = IACA_MAX_VALIDITY;
        private BigInteger serial;

        private IacaBuilder(KeyPair keyPair) {
            this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        }

        /** Country (C): ISO 3166-1 alpha-2, mandatory. */
        public IacaBuilder country(String alpha2) {
            this.country = alpha2;
            return this;
        }

        /** State or province (ST), optional. */
        public IacaBuilder state(String state) {
            this.state = state;
            return this;
        }

        /** Organization (O), optional. */
        public IacaBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        /** Common name (CN), mandatory. Annex B recommends marking a demo or test IACA as such. */
        public IacaBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /** issuerAltName URI, non-critical: any absolute URI ({@code https:}, {@code mailto:}, ...); a URI or an email is mandatory. */
        public IacaBuilder issuerAltUri(String uri) {
            this.issuerAltUri = uri;
            return this;
        }

        /** issuerAltName rfc822 mailbox, non-critical; a URI or an email is mandatory. */
        public IacaBuilder issuerAltEmail(String email) {
            this.issuerAltEmail = email;
            return this;
        }

        /** CRL distribution point URI, mandatory and http(s). */
        public IacaBuilder crlDistributionPoint(String uri) {
            this.crlDistributionPoint = uri;
            return this;
        }

        /** Start of the validity period, default now, truncated to whole seconds. */
        public IacaBuilder notBefore(Instant notBefore) {
            this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
            return this;
        }

        /** Requested validity, default {@link #IACA_MAX_VALIDITY}; between {@link #MIN_VALIDITY} and the cap, else refused. */
        public IacaBuilder validity(Duration validity) {
            this.validity = Objects.requireNonNull(validity, "validity");
            return this;
        }

        /** Serial number, default {@link Serials#random()}; positive, 64 bits or more, at most 20 content octets. */
        public IacaBuilder serial(BigInteger serial) {
            this.serial = Objects.requireNonNull(serial, "serial");
            return this;
        }

        public X509Certificate build() {
            requireText(country, "IACA_SUBJECT_COUNTRY_MISSING", "a country (C) is mandatory for an IACA certificate");
            if (!COUNTRIES.contains(country)) {
                throw new PkiException("IACA_SUBJECT_COUNTRY_INVALID: country " + country
                        + " is not an ISO 3166-1 alpha-2 code");
            }
            requireText(commonName, "IACA_SUBJECT_CN_MISSING", "a common name (CN) is mandatory for an IACA certificate");
            maxLength(commonName, MAX_COMMON_NAME, "IACA_SUBJECT_CN_TOO_LONG", "common name (CN)");
            if (state != null) {
                requireText(state, "IACA_SUBJECT_STATE_EMPTY", "a state (ST), when given, must not be empty");
                maxLength(state, MAX_STATE, "IACA_SUBJECT_STATE_TOO_LONG", "state (ST)");
            }
            if (organization != null) {
                requireText(organization, "IACA_SUBJECT_ORGANIZATION_EMPTY",
                        "an organization (O), when given, must not be empty");
                maxLength(organization, MAX_ORGANIZATION, "IACA_SUBJECT_ORGANIZATION_TOO_LONG", "organization (O)");
            }
            if (issuerAltUri == null && issuerAltEmail == null) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_MISSING: an IACA certificate needs an issuerAltName URI or email");
            }
            GeneralNames issuerAltNames = Certificates.issuerAltNames(issuerAltUri, issuerAltEmail);
            requireText(crlDistributionPoint, "IACA_CRL_DP_MISSING", "an IACA certificate needs a CRL distribution point");
            Certificates.checkValidity(validity, IACA_MAX_VALIDITY, "IACA");
            BigInteger serialNumber = serial != null ? serial : Serials.random();
            Certificates.checkSerial(serialNumber, "IACA");
            Certificates.curve(keyPair.getPublic(), "IACA");
            String algorithm = Certificates.signatureAlgorithm(keyPair.getPublic(), "IACA");

            Instant start = notBefore.truncatedTo(ChronoUnit.SECONDS);
            Instant end = Certificates.end(start, validity);
            // 20 calendar years, measured on real dates, is the cap the validator applies
            Instant cap = start.atZone(ZoneOffset.UTC).plus(Period.ofYears(20)).toInstant();
            if (end.isAfter(cap)) {
                throw new PkiException("IACA_VALIDITY_TOO_LONG: a validity ending " + end
                        + " exceeds 20 calendar years from " + start);
            }
            X500Name name = name(country, state, organization, commonName);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serialNumber,
                    Date.from(start), Date.from(end), name, keyPair.getPublic());
            try {
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(Certificates.keyIdentifier(Certificates.spki(keyPair.getPublic()))));
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
                builder.addExtension(Extension.issuerAlternativeName, false, issuerAltNames);
                builder.addExtension(Extension.cRLDistributionPoints, false, Certificates.crlDistributionPoint(crlDistributionPoint));
            } catch (CertIOException e) {
                throw new PkiException("Cannot add an extension to the IACA certificate", e);
            }
            return Certificates.certificate(builder.build(Certificates.signer(keyPair.getPrivate(), algorithm)));
        }
    }

    /** Builder for a Document Signer certificate, ISO/IEC 18013-5:2021 Annex B. */
    public static final class DsBuilder {

        private final PublicKey subjectPublicKey;
        private final X509Certificate iaca;
        private final KeyPair iacaKeyPair;
        private String commonName;
        private String crlDistributionPoint;
        private Instant notBefore = Instant.now();
        private Duration validity = DS_MAX_VALIDITY;
        private BigInteger serial;

        private DsBuilder(PublicKey subjectPublicKey, X509Certificate iaca, KeyPair iacaKeyPair) {
            this.subjectPublicKey = Objects.requireNonNull(subjectPublicKey, "subjectPublicKey");
            this.iaca = Objects.requireNonNull(iaca, "iaca");
            this.iacaKeyPair = Objects.requireNonNull(iacaKeyPair, "iacaKeyPair");
        }

        /** Common name (CN), mandatory. Country and state come from the IACA, never set here. */
        public DsBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /** CRL distribution point URI, an absolute http(s) URI; default the IACA's own distribution point. */
        public DsBuilder crlDistributionPoint(String uri) {
            this.crlDistributionPoint = uri;
            return this;
        }

        /**
         * Start of the validity period, default now. A start before the IACA's {@code notBefore} is moved forward to it,
         * because a Document Signer cannot be valid before the authority that signed it, and an end after the IACA's
         * {@code notAfter} is clamped to it; when that leaves less than {@link #MIN_VALIDITY}, {@link #build} refuses.
         */
        public DsBuilder notBefore(Instant notBefore) {
            this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
            return this;
        }

        /** Requested validity, default {@link #DS_MAX_VALIDITY}; between {@link #MIN_VALIDITY} and the cap, else refused. */
        public DsBuilder validity(Duration validity) {
            this.validity = Objects.requireNonNull(validity, "validity");
            return this;
        }

        /** Serial number, default {@link Serials#random()}; positive, 64 bits or more, at most 20 content octets. */
        public DsBuilder serial(BigInteger serial) {
            this.serial = Objects.requireNonNull(serial, "serial");
            return this;
        }

        public X509Certificate build() {
            requireText(commonName, "DS_SUBJECT_CN_MISSING", "a common name (CN) is mandatory for a Document Signer certificate");
            maxLength(commonName, MAX_COMMON_NAME, "DS_SUBJECT_CN_TOO_LONG", "common name (CN)");
            if (!Arrays.equals(iaca.getPublicKey().getEncoded(), iacaKeyPair.getPublic().getEncoded())) {
                throw new PkiException("IACA_KEY_MISMATCH: the IACA signing key does not match the IACA certificate");
            }
            List<AnnexBValidator.Violation> violations = AnnexBValidator.validateIaca(iaca);
            if (!violations.isEmpty()) {
                throw new PkiException("DS_IACA_INVALID: the IACA does not meet the Annex B profile: " + violations.get(0));
            }
            Certificates.curve(subjectPublicKey, "DS");
            Certificates.checkValidity(validity, DS_MAX_VALIDITY, "DS");
            BigInteger serialNumber = serial != null ? serial : Serials.random();
            Certificates.checkSerial(serialNumber, "DS");
            String crlUri = crlUri();
            X500Name iacaSubject = Certificates.name(iaca);
            X500Name subject = dsSubject(iacaSubject, commonName);
            String algorithm = Certificates.signatureAlgorithm(iacaKeyPair.getPublic(), "IACA");

            Instant iacaNotBefore = iaca.getNotBefore().toInstant().truncatedTo(ChronoUnit.SECONDS);
            Instant iacaNotAfter = iaca.getNotAfter().toInstant().truncatedTo(ChronoUnit.SECONDS);
            Instant start = notBefore.truncatedTo(ChronoUnit.SECONDS);
            if (start.isBefore(iacaNotBefore)) {
                start = iacaNotBefore;
            }
            Instant end = Certificates.end(start, validity);
            if (end.isAfter(iacaNotAfter)) {
                end = iacaNotAfter;
            }
            // the span the clamped certificate is valid for, notAfter inclusive (RFC 5280 section 4.1.2.5)
            Duration clamped = Duration.between(start, end).plusSeconds(1);
            if (clamped.compareTo(MIN_VALIDITY) < 0) {
                throw new PkiException("DS_VALIDITY_OUTSIDE_IACA: the IACA validity ends at " + iacaNotAfter
                        + ", so a Document Signer starting at " + start + " would be valid for "
                        + (clamped.isNegative() || clamped.isZero() ? "no time at all" : clamped)
                        + ", less than the minimum of " + MIN_VALIDITY + "; renew the IACA first");
            }

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer(iaca), serialNumber, Date.from(start), Date.from(end), subject, subjectPublicKey);
            try {
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(Certificates.subjectKeyIdentifier(iaca)));
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(Certificates.keyIdentifier(Certificates.spki(subjectPublicKey))));
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
                builder.addExtension(Extension.extendedKeyUsage, true,
                        new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(DS_EXTENDED_KEY_USAGE))));
                // copied verbatim so the URI and rfc822 tags survive
                builder.addExtension(Extension.issuerAlternativeName, false, iacaIssuerAltNames());
                builder.addExtension(Extension.cRLDistributionPoints, false, Certificates.crlDistributionPoint(crlUri));
            } catch (CertIOException e) {
                throw new PkiException("Cannot add an extension to the Document Signer certificate", e);
            }
            return Certificates.certificate(builder.build(Certificates.signer(iacaKeyPair.getPrivate(), algorithm)));
        }

        /** The IACA subject DER, unchanged: a re-encoded issuer would break byte-equality with the IACA subject. */
        private static X500Name issuer(X509Certificate iaca) {
            return X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded());
        }

        /**
         * The DS subject: the IACA's country (C) and state (ST) RDNs, copied as the ASN.1 values the IACA carries so a
         * value keeps its string type and its bytes, followed by the configured common name.
         */
        private static X500Name dsSubject(X500Name iacaSubject, String commonName) {
            List<RDN> rdns = new ArrayList<>();
            for (RDN rdn : iacaSubject.getRDNs()) {
                for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                    if (value.getType().equals(BCStyle.C) || value.getType().equals(BCStyle.ST)) {
                        rdns.add(rdn);
                        break;
                    }
                }
            }
            rdns.add(new RDN(BCStyle.CN, new DERUTF8String(commonName)));
            return new X500Name(rdns.toArray(RDN[]::new));
        }

        private GeneralNames iacaIssuerAltNames() {
            byte[] extension = Certificates.extension(iaca, Extension.issuerAlternativeName);
            if (extension == null) {
                throw new PkiException("DS_ISSUER_ALT_NAME_MISSING: the IACA certificate has no issuerAltName to copy");
            }
            return GeneralNames.getInstance(extension);
        }

        private String crlUri() {
            if (crlDistributionPoint != null) {
                if (!Certificates.isHttpUri(crlDistributionPoint)) {
                    throw new PkiException("DS_CRL_DP_INVALID: " + crlDistributionPoint
                            + " is not an absolute http or https URI");
                }
                return crlDistributionPoint;
            }
            var uris = Certificates.crlDistributionPointUris(iaca);
            if (uris.isEmpty()) {
                throw new PkiException("DS_CRL_DP_MISSING: the IACA certificate has no CRL distribution point to copy");
            }
            return uris.get(0);
        }
    }

    private static X500Name name(String country, String state, String organization, String commonName) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, country);
        if (state != null) {
            builder.addRDN(BCStyle.ST, state);
        }
        if (organization != null) {
            builder.addRDN(BCStyle.O, organization);
        }
        return builder.addRDN(BCStyle.CN, commonName).build();
    }

    private static void requireText(String value, String ruleId, String message) {
        if (value == null || value.isBlank()) {
            throw new PkiException(ruleId + ": " + message);
        }
    }

    /** RFC 5280 Appendix A upper bounds count characters (code points), not UTF-8 octets. */
    private static void maxLength(String value, int maximum, String ruleId, String attribute) {
        int length = value.codePointCount(0, value.length());
        if (length > maximum) {
            throw new PkiException(ruleId + ": the " + attribute + " is " + length + " characters, RFC 5280 allows "
                    + maximum);
        }
    }
}
