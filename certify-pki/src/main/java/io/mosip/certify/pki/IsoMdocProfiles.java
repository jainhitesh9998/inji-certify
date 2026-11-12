package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;

/**
 * ISO/IEC 18013-5:2021 Annex B certificate profiles.
 *
 * <p>An IACA certificate is a self-signed root with a country and a common name in its subject, an issuerAltName, a
 * CRL distribution point, a subject key identifier, {@code keyUsage = keyCertSign + cRLSign} (critical),
 * {@code basicConstraints = CA:true, pathLen:0} (critical), a lifetime of at most 20 years and an
 * {@code ecdsa-with-SHA256/384/512} signature matching a P-256/384/521 key.
 *
 * <p>A Document Signer certificate is issued by an IACA: the issuer is the IACA subject, the country (and state, when
 * the IACA has one) is copied from the IACA, the authority key identifier is the IACA subject key identifier, it has
 * its own subject key identifier, {@code keyUsage = digitalSignature} (critical), the document signer extended key
 * usage {@value #DS_EXTENDED_KEY_USAGE} (critical), the IACA issuerAltName, a CRL distribution point, no
 * basicConstraints, and a lifetime of at most 457 days.
 *
 * <p>Builders accept either a freshly generated key pair or the public key of a PKCS#10 request ({@link Csr}); the
 * IACA is self-signed by definition, so it always takes its own key pair.
 */
public final class IsoMdocProfiles {

    /** The document signer extended key usage of ISO/IEC 18013-5:2021 Annex B. */
    public static final String DS_EXTENDED_KEY_USAGE = "1.0.18013.5.1.2";

    /** Annex B caps the IACA lifetime at 20 years: 7305 days, leap days included. */
    public static final Duration IACA_MAX_VALIDITY = Duration.ofDays(7_305);

    /** Annex B caps the Document Signer certificate lifetime at 457 days. */
    public static final Duration DS_MAX_VALIDITY = Duration.ofDays(457);

    private static final Pattern COUNTRY = Pattern.compile("[A-Z]{2}");

    private IsoMdocProfiles() {}

    /** A self-signed IACA certificate for the given key pair. */
    public static IacaBuilder iaca(KeyPair keyPair) {
        return new IacaBuilder(keyPair);
    }

    /** A Document Signer certificate for a generated key pair, issued by the IACA. */
    public static DsBuilder ds(KeyPair subjectKeyPair, X509Certificate iaca, KeyPair iacaKeyPair) {
        return new DsBuilder(Objects.requireNonNull(subjectKeyPair, "subjectKeyPair").getPublic(), iaca, iacaKeyPair);
    }

    /** A Document Signer certificate for the public key of a PKCS#10 request, issued by the IACA. */
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

        /** issuerAltName URI, non-critical; a URI or an email is mandatory. */
        public IacaBuilder issuerAltUri(String uri) {
            this.issuerAltUri = uri;
            return this;
        }

        /** issuerAltName rfc822 mailbox, non-critical; a URI or an email is mandatory. */
        public IacaBuilder issuerAltEmail(String email) {
            this.issuerAltEmail = email;
            return this;
        }

        /** CRL distribution point URI, mandatory. */
        public IacaBuilder crlDistributionPoint(String uri) {
            this.crlDistributionPoint = uri;
            return this;
        }

        /** Start of the validity period, default now. */
        public IacaBuilder notBefore(Instant notBefore) {
            this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
            return this;
        }

        /** Requested validity, default and cap {@link #IACA_MAX_VALIDITY}; a longer request is capped, not refused. */
        public IacaBuilder validity(Duration validity) {
            this.validity = Objects.requireNonNull(validity, "validity");
            return this;
        }

        /** Serial number, default {@link Serials#random()}. */
        public IacaBuilder serial(BigInteger serial) {
            this.serial = Objects.requireNonNull(serial, "serial");
            return this;
        }

        public X509Certificate build() {
            require(country, "IACA_SUBJECT_COUNTRY_MISSING", "a country (C) is mandatory for an IACA certificate");
            if (!COUNTRY.matcher(country).matches()) {
                throw new PkiException("IACA_SUBJECT_COUNTRY_INVALID: country " + country + " is not an ISO 3166-1 alpha-2 code");
            }
            require(commonName, "IACA_SUBJECT_CN_MISSING", "a common name (CN) is mandatory for an IACA certificate");
            if (issuerAltUri == null && issuerAltEmail == null) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_MISSING: an IACA certificate needs an issuerAltName URI or email");
            }
            require(crlDistributionPoint, "IACA_CRL_DP_MISSING", "an IACA certificate needs a CRL distribution point");
            X500Name name = name(country, state, organization, commonName);
            Date start = Date.from(notBefore);
            Date end = Date.from(notBefore.plus(cap(validity, IACA_MAX_VALIDITY)));
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
                    serial != null ? serial : Serials.random(), start, end, name, keyPair.getPublic());
            try {
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(Certificates.keyIdentifier(keyPair.getPublic())));
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
                builder.addExtension(Extension.issuerAlternativeName, false, Certificates.issuerAltNames(issuerAltUri, issuerAltEmail));
                builder.addExtension(Extension.cRLDistributionPoints, false, Certificates.crlDistributionPoint(crlDistributionPoint));
            } catch (CertIOException e) {
                throw new PkiException("Cannot add an extension to the IACA certificate", e);
            }
            String algorithm = Certificates.signatureAlgorithm(keyPair.getPublic());
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

        /** Common name (CN), mandatory. Country and state are copied from the IACA, never set here. */
        public DsBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /** CRL distribution point URI, default the IACA's own distribution point. */
        public DsBuilder crlDistributionPoint(String uri) {
            this.crlDistributionPoint = uri;
            return this;
        }

        /** Start of the validity period, default now. */
        public DsBuilder notBefore(Instant notBefore) {
            this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
            return this;
        }

        /** Requested validity, default and cap {@link #DS_MAX_VALIDITY}; a longer request is capped, not refused. */
        public DsBuilder validity(Duration validity) {
            this.validity = Objects.requireNonNull(validity, "validity");
            return this;
        }

        /** Serial number, default {@link Serials#random()}. */
        public DsBuilder serial(BigInteger serial) {
            this.serial = Objects.requireNonNull(serial, "serial");
            return this;
        }

        public X509Certificate build() {
            require(commonName, "DS_SUBJECT_CN_MISSING", "a common name (CN) is mandatory for a Document Signer certificate");
            if (!Arrays.equals(iaca.getPublicKey().getEncoded(), iacaKeyPair.getPublic().getEncoded())) {
                throw new PkiException("IACA_KEY_MISMATCH: the IACA signing key does not match the IACA certificate");
            }
            X500Principal iacaSubject = iaca.getSubjectX500Principal();
            String country = Certificates.attribute(iacaSubject, BCStyle.C);
            if (country == null) {
                throw new PkiException("DS_COUNTRY_MISSING: the IACA certificate has no country (C) to copy");
            }
            X500Name subject = name(country, Certificates.attribute(iacaSubject, BCStyle.ST), null, commonName);
            Date start = Date.from(notBefore);
            Date end = Date.from(notBefore.plus(cap(validity, DS_MAX_VALIDITY)));
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(iaca,
                    serial != null ? serial : Serials.random(), start, end, subject, subjectPublicKey);
            try {
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(Certificates.keyIdentifier(subjectPublicKey)));
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
                builder.addExtension(Extension.extendedKeyUsage, true,
                        new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(DS_EXTENDED_KEY_USAGE))));
                // copied verbatim so the URI and rfc822 tags survive
                builder.addExtension(Extension.issuerAlternativeName, false, iacaIssuerAltNames());
                builder.addExtension(Extension.cRLDistributionPoints, false, Certificates.crlDistributionPoint(crlUri()));
            } catch (CertIOException e) {
                throw new PkiException("Cannot add an extension to the Document Signer certificate", e);
            }
            String algorithm = Certificates.signatureAlgorithm(iacaKeyPair.getPublic());
            return Certificates.certificate(builder.build(Certificates.signer(iacaKeyPair.getPrivate(), algorithm)));
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

    private static Duration cap(Duration requested, Duration maximum) {
        return requested.compareTo(maximum) > 0 ? maximum : requested;
    }

    private static void require(String value, String ruleId, String message) {
        if (value == null) {
            throw new PkiException(ruleId + ": " + message);
        }
    }
}
