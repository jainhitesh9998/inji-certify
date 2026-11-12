package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * Certificates, keys and CRLs built with plain BouncyCastle rather than the production builders: a builder that refuses
 * invalid input cannot produce the object a negative test needs. Each factory starts from a conforming object; a test
 * mutates exactly one property and the validator must report exactly one named violation.
 *
 * <p>Every default here is itself conforming — a random 64-bit-or-more serial, an ISO country, a validity inside both
 * caps — so a mutation is the only difference between the baseline and the row that breaks it.
 */
final class BadCerts {

    static final String IACA_URI = "https://credentials.example.test/mdoc/iaca";
    static final String CRL_URI = "https://credentials.example.test/mdoc/iaca/iaca.crl";
    static final Provider BC = new BouncyCastleProvider();

    private BadCerts() {}

    // ------------------------------------------------------------------ keys

    /** A JDK P-256/384/521 key pair: named curve, uncompressed point, what a hardware key would produce. */
    static KeyPair ec(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curveName(bits)));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A BouncyCastle key pair, which exposes the point so a compressed form can be built from it. */
    static KeyPair bcEc(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC);
            generator.initialize(new ECGenParameterSpec(curveName(bits)));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair brainpool() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC);
            generator.initialize(new ECGenParameterSpec("brainpoolP256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String curveName(int bits) {
        return switch (bits) {
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> "secp256r1";
        };
    }

    static SubjectPublicKeyInfo spki(PublicKey key) {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded());
    }

    /** The same key with a compressed point, which the key profile of this module does not allow. */
    static SubjectPublicKeyInfo compressed(KeyPair bcKeyPair) {
        ECPublicKey key = (ECPublicKey) bcKeyPair.getPublic();
        SubjectPublicKeyInfo original = spki(bcKeyPair.getPublic());
        return new SubjectPublicKeyInfo(original.getAlgorithm(), new DERBitString(key.getQ().getEncoded(true)));
    }

    /** The same key with explicit curve parameters instead of a named-curve OID, which the key profile does not allow. */
    static SubjectPublicKeyInfo explicitParameters(PublicKey key) {
        X9ECParameters curve = ECNamedCurveTable.getByName("secp256r1");
        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(spki(key).getAlgorithm().getAlgorithm(), curve.toASN1Primitive()),
                new DERBitString(spki(key).getPublicKeyData().getBytes()));
    }

    /**
     * A P-256 subjectPublicKeyInfo whose uncompressed point has the given coordinates, which need not be on the curve:
     * {@code 04 || x || y} with each coordinate left-padded to 32 octets.
     */
    static SubjectPublicKeyInfo p256Point(BigInteger x, BigInteger y) {
        byte[] point = new byte[65];
        point[0] = 0x04;
        byte[] xs = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, x);
        byte[] ys = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, y);
        System.arraycopy(xs, 0, point, 1, 32);
        System.arraycopy(ys, 0, point, 33, 32);
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey, Certificates.P256), new DERBitString(point));
    }

    /** {@code 04 || 64 zero octets}: the point (0, 0), which is not on P-256 (and which some libraries read as infinity). */
    static SubjectPublicKeyInfo zeroPoint() {
        return p256Point(BigInteger.ZERO, BigInteger.ZERO);
    }

    static byte[] keyId(PublicKey key) {
        return Certificates.keyIdentifier(key);
    }

    static byte[] keyId(SubjectPublicKeyInfo spki) {
        return Certificates.keyIdentifier(spki);
    }

    // ------------------------------------------------------------- names

    static GeneralNames issuerAltNames(String value) {
        return new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, value));
    }

    static GeneralNames dnsIssuerAltNames(String value) {
        return new GeneralNames(new GeneralName(GeneralName.dNSName, value));
    }

    static CRLDistPoint crlDistributionPoint(String uri) {
        return crlDistributionPoint(new DistributionPoint(
                new DistributionPointName(new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, uri))), null, null));
    }

    static CRLDistPoint crlDistributionPoint(DistributionPoint... points) {
        return new CRLDistPoint(points);
    }

    static ExtendedKeyUsage documentSignerEku() {
        return new ExtendedKeyUsage(KeyPurposeId.getInstance(
                new ASN1ObjectIdentifier(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE)));
    }

    /** A name with any of country, state and common name left out, so a negative test can drop one. */
    static X500Name name(String country, String state, String commonName) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (country != null) {
            builder.addRDN(BCStyle.C, country);
        }
        if (state != null) {
            builder.addRDN(BCStyle.ST, state);
        }
        if (commonName != null) {
            builder.addRDN(BCStyle.CN, commonName);
        }
        return builder.build();
    }

    /** A country encoded as a UTF8String, where X.520 countryName is a PrintableString. */
    static X500Name utf8CountryName(String country, String commonName) {
        return new X500Name(new RDN[] {
                new RDN(BCStyle.C, new DERUTF8String(country)),
                new RDN(BCStyle.CN, new DERUTF8String(commonName))});
    }

    /** A name carrying the given attribute twice, on top of an otherwise complete subject. */
    static X500Name duplicateAttributeName(String country, String state, String commonName,
                                           ASN1ObjectIdentifier duplicate) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (country != null) {
            builder.addRDN(BCStyle.C, country);
        }
        if (state != null) {
            builder.addRDN(BCStyle.ST, state);
        }
        builder.addRDN(BCStyle.CN, commonName);
        builder.addRDN(duplicate, duplicate.equals(BCStyle.C) ? country : state);
        return builder.build();
    }

    /** A name whose country is a UTF8String, with the state a Document Signer inherits, so only that rule fires. */
    static X500Name utf8CountryName(String country, String state, String commonName) {
        return new X500Name(new RDN[] {
                new RDN(BCStyle.C, new DERUTF8String(country)),
                new RDN(BCStyle.ST, new DERPrintableString(state)),
                new RDN(BCStyle.CN, new DERUTF8String(commonName))});
    }

    /** A name of the given attribute type and value pairs, one RDN each, with the ASN.1 string types given. */
    static X500Name rdns(Object... typesAndValues) {
        RDN[] rdns = new RDN[typesAndValues.length / 2];
        for (int i = 0; i < rdns.length; i++) {
            rdns[i] = new RDN((ASN1ObjectIdentifier) typesAndValues[2 * i], (ASN1Encodable) typesAndValues[2 * i + 1]);
        }
        return new X500Name(rdns);
    }

    /** A JCA key whose encoding carries explicit curve parameters, which no JDK key factory would produce. */
    static PublicKey explicitParametersKey(KeyPair jdkKeyPair) {
        return publicKey(explicitParameters(jdkKeyPair.getPublic()));
    }

    static PublicKey compressedKey(KeyPair bcKeyPair) {
        return publicKey(compressed(bcKeyPair));
    }

    /** A JCA key whose encoding is the given subjectPublicKeyInfo, keeping whatever form it has. */
    static PublicKey publicKey(SubjectPublicKeyInfo spki) {
        try {
            return new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider(BC).getPublicKey(spki);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------ certificates

    /** A conforming IACA certificate for the key pair, ready to be mutated. */
    static Cert iaca(KeyPair keyPair) {
        return iaca(keyPair, "IN", null);
    }

    static Cert iaca(KeyPair keyPair, String country, String state) {
        X500Name name = name(country, state, "Bad IACA");
        Cert cert = new Cert();
        cert.subject = name;
        cert.issuer = name;
        cert.publicKey = keyPair.getPublic();
        cert.signingKey = keyPair.getPrivate();
        cert.notAfter = Date.from(Instant.now().plus(Duration.ofDays(3_650)));
        cert.with(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyId(keyPair.getPublic())));
        cert.with(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        cert.with(Extension.basicConstraints, true, new BasicConstraints(0));
        cert.with(Extension.issuerAlternativeName, false, issuerAltNames(IACA_URI));
        cert.with(Extension.cRLDistributionPoints, false, crlDistributionPoint(CRL_URI));
        return cert;
    }

    /** A conforming Document Signer certificate for the key pair, issued by the given IACA, ready to be mutated. */
    static Cert ds(KeyPair subjectKeyPair, X509Certificate iaca, KeyPair iacaKeyPair) {
        String country = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.C);
        String state = Certificates.attribute(iaca.getSubjectX500Principal(), BCStyle.ST);
        Cert cert = new Cert();
        cert.subject = name(country == null ? "IN" : country, state, "Bad DSC");
        cert.issuer = X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded());
        cert.publicKey = subjectKeyPair.getPublic();
        cert.signingKey = iacaKeyPair.getPrivate();
        // inside the IACA validity, so only a test that breaks that reports it
        cert.notBefore = iaca.getNotBefore();
        cert.notAfter = Date.from(iaca.getNotBefore().toInstant().plus(Duration.ofDays(300)));
        cert.with(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
        cert.with(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyId(subjectKeyPair.getPublic())));
        cert.with(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        cert.with(Extension.extendedKeyUsage, true, documentSignerEku());
        // copied from the IACA, as Annex B requires, so only a test that breaks it reports a mismatch
        cert.with(Extension.issuerAlternativeName, false,
                GeneralNames.getInstance(Certificates.extension(iaca, Extension.issuerAlternativeName)));
        cert.with(Extension.cRLDistributionPoints, false, crlDistributionPoint(CRL_URI));
        return cert;
    }

    /** A mutable certificate description; {@link #build()} signs it as described. */
    static final class Cert {

        private X500Name issuer;
        private X500Name subject;
        private BigInteger serial = Serials.random();
        private Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
        private Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(300)));
        private PublicKey publicKey;
        private SubjectPublicKeyInfo subjectPublicKeyInfo;
        private PrivateKey signingKey;
        private String signatureAlgorithm = "SHA256withECDSA";
        private final List<Ext> extensions = new ArrayList<>();

        private record Ext(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value, byte[] raw) {}

        Cert issuer(X500Name issuer) {
            this.issuer = issuer;
            return this;
        }

        Cert subject(X500Name subject) {
            this.subject = subject;
            return this;
        }

        Cert serial(BigInteger serial) {
            this.serial = serial;
            return this;
        }

        Cert notAfter(Date notAfter) {
            this.notAfter = notAfter;
            return this;
        }

        Cert notBefore(Date notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        Cert signedBy(PrivateKey signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        /** The subject public key, including forms no JCA key factory accepts, such as a compressed point. */
        Cert subjectPublicKeyInfo(SubjectPublicKeyInfo spki) {
            this.subjectPublicKeyInfo = spki;
            return this;
        }

        Cert signatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        Cert without(ASN1ObjectIdentifier oid) {
            extensions.removeIf(extension -> extension.oid().equals(oid));
            return this;
        }

        Cert critical(ASN1ObjectIdentifier oid, boolean critical) {
            for (int i = 0; i < extensions.size(); i++) {
                Ext extension = extensions.get(i);
                if (extension.oid().equals(oid)) {
                    extensions.set(i, new Ext(oid, critical, extension.value(), extension.raw()));
                }
            }
            return this;
        }

        Cert with(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
            without(oid);
            extensions.add(new Ext(oid, critical, value, null));
            return this;
        }

        /** An extension whose extnValue holds exactly these octets, well-formed or not. */
        Cert withRaw(ASN1ObjectIdentifier oid, boolean critical, byte[] der) {
            without(oid);
            extensions.add(new Ext(oid, critical, null, der));
            return this;
        }

        X509Certificate build() {
            return build(extensions);
        }

        /**
         * The certificate parsed by the JDK rather than BouncyCastle: BouncyCastle refuses a certificate whose keyUsage or
         * basicConstraints cannot be read, while the JDK keeps a malformed non-critical extension as raw octets, which is
         * the shape a malformed-extension rule has to see.
         */
        X509Certificate buildJdk() {
            return toCertificate(encoded(holder(extensions)));
        }

        /** The certificate with an explicit NULL in both signature AlgorithmIdentifiers, which RFC 5758 forbids. */
        X509Certificate buildWithAlgorithmParameters() {
            AlgorithmIdentifier withNull = new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256, org.bouncycastle.asn1.DERNull.INSTANCE);
            return toCertificate(BadCerts.resign(encoded(holder(extensions)), signingKey, "SHA256withECDSA", withNull,
                    elements -> {
                        elements.set(tbsSignatureIndex(elements), withNull);
                        return elements;
                    }));
        }

        private X509Certificate build(List<Ext> with) {
            try {
                return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder(with));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private org.bouncycastle.cert.X509CertificateHolder holder(List<Ext> with) {
            SubjectPublicKeyInfo spki = subjectPublicKeyInfo != null ? subjectPublicKeyInfo : BadCerts.spki(publicKey);
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, spki);
            for (Ext extension : with) {
                try {
                    if (extension.raw() != null) {
                        builder.addExtension(extension.oid(), extension.critical(), extension.raw());
                    } else {
                        builder.addExtension(extension.oid(), extension.critical(), extension.value());
                    }
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            try {
                return builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signatureAlgorithm)
                        .setProvider(BC).build(signingKey));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static byte[] encoded(org.bouncycastle.cert.X509CertificateHolder holder) {
            try {
                return holder.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * The same certificate as X.509 version 1. A version 1 certificate cannot carry extensions, so the profile's
         * extensions are dropped with the version field, and the rules that require them report as well.
         */
        X509Certificate buildV1() {
            return toCertificate(BadCerts.resign(encoded(build(List.of())), signingKey, "SHA256withECDSA",
                    new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256),
                    elements -> new ArrayList<>(elements.subList(1, elements.size()))));
        }

        /** The same certificate with a tbsCertificate AlgorithmIdentifier that differs from the outer one. */
        X509Certificate buildInnerAlgorithmMismatch() {
            return toCertificate(BadCerts.resign(encoded(build()), signingKey, "SHA256withECDSA",
                    new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256), elements -> {
                        // the same OID with an explicit NULL parameter: RFC 5280 4.1.1.2 requires the two
                        // AlgorithmIdentifiers to be identical, and every reference implementation still parses it
                        elements.set(tbsSignatureIndex(elements),
                                new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256, org.bouncycastle.asn1.DERNull.INSTANCE));
                        return elements;
                    }));
        }

        private static byte[] encoded(X509Certificate certificate) {
            try {
                return certificate.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ------------------------------------------------------------------ CRLs

    /** A conforming v2 CRL signed by the IACA key, ready to be mutated. */
    static Crl crl(X509Certificate iaca, KeyPair signingKey) {
        return new Crl(iaca, signingKey);
    }

    /** A mutable CRL description; {@link #build()} signs it as described. */
    static final class Crl {

        private final X509Certificate iaca;
        private X500Name issuer;
        private PrivateKey signingKey;
        private String signatureAlgorithm = "SHA256withECDSA";
        private Date thisUpdate = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
        private Date nextUpdate = Date.from(Instant.now().plus(Duration.ofDays(30)));
        private boolean withNextUpdate = true;
        private final List<Ext> extensions = new ArrayList<>();
        private final List<Entry> entries = new ArrayList<>();

        private record Ext(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value, byte[] raw) {}

        private record Entry(BigInteger serial, Date revokedAt, Extensions extensions) {}

        private Crl(X509Certificate iaca, KeyPair signingKey) {
            this.iaca = iaca;
            this.issuer = X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded());
            this.signingKey = signingKey.getPrivate();
            with(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
            with(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1_700_000_000L)));
        }

        Crl issuer(X500Name issuer) {
            this.issuer = issuer;
            return this;
        }

        Crl signedBy(PrivateKey signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        Crl signatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        Crl thisUpdate(Date thisUpdate) {
            this.thisUpdate = thisUpdate;
            return this;
        }

        Crl nextUpdate(Date nextUpdate) {
            this.nextUpdate = nextUpdate;
            return this;
        }

        Crl withoutNextUpdate() {
            this.withNextUpdate = false;
            return this;
        }

        Crl without(ASN1ObjectIdentifier oid) {
            extensions.removeIf(extension -> extension.oid().equals(oid));
            return this;
        }

        Crl critical(ASN1ObjectIdentifier oid, boolean critical) {
            for (int i = 0; i < extensions.size(); i++) {
                Ext extension = extensions.get(i);
                if (extension.oid().equals(oid)) {
                    extensions.set(i, new Ext(oid, critical, extension.value(), extension.raw()));
                }
            }
            return this;
        }

        Crl with(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
            without(oid);
            extensions.add(new Ext(oid, critical, value, null));
            return this;
        }

        /** A CRL extension whose extnValue holds exactly these octets, well-formed or not. */
        Crl withRaw(ASN1ObjectIdentifier oid, boolean critical, byte[] der) {
            without(oid);
            extensions.add(new Ext(oid, critical, null, der));
            return this;
        }

        Crl revoke(BigInteger serial) {
            entries.add(new Entry(serial, thisUpdate, null));
            return this;
        }

        /** An entry with an extension, which the profile (as read, to be confirmed) does not allow. */
        Crl revokeWithReason(BigInteger serial) {
            ExtensionsGenerator generator = new ExtensionsGenerator();
            try {
                generator.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.keyCompromise));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            entries.add(new Entry(serial, thisUpdate, generator.generate()));
            return this;
        }

        X509CRL build() {
            X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, thisUpdate);
            if (withNextUpdate) {
                builder.setNextUpdate(nextUpdate);
            }
            for (Entry entry : entries) {
                builder.addCRLEntry(entry.serial(), entry.revokedAt(), entry.extensions());
            }
            for (Ext extension : extensions) {
                try {
                    if (extension.raw() != null) {
                        builder.addExtension(extension.oid(), extension.critical(), extension.raw());
                    } else {
                        builder.addExtension(extension.oid(), extension.critical(), extension.value());
                    }
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            try {
                return new JcaX509CRLConverter().setProvider(BC).getCRL(builder.build(
                        new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signatureAlgorithm)
                                .setProvider(BC).build(signingKey)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /** The same CRL as X.509 version 1: the version field dropped, the signature re-made. */
        X509CRL buildV1() {
            return toCrl(BadCerts.resign(encoded(build()), signingKey, "SHA256withECDSA",
                    new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256),
                    elements -> new ArrayList<>(elements.subList(1, elements.size()))));
        }

        /** The same CRL with a tbsCertList AlgorithmIdentifier that differs from the outer one. */
        X509CRL buildInnerAlgorithmMismatch() {
            return toCrl(BadCerts.resign(encoded(build()), signingKey, "SHA256withECDSA",
                    new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256), elements -> {
                        // the same OID with an explicit NULL parameter: RFC 5280 4.1.1.2 requires the two
                        // AlgorithmIdentifiers to be identical, and every reference implementation still parses it
                        elements.set(tbsSignatureIndex(elements),
                                new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256, org.bouncycastle.asn1.DERNull.INSTANCE));
                        return elements;
                    }));
        }

        /** The CRL with an explicit NULL in both signature AlgorithmIdentifiers, which RFC 5758 forbids. */
        X509CRL buildWithAlgorithmParameters() {
            AlgorithmIdentifier withNull = new AlgorithmIdentifier(Certificates.ECDSA_WITH_SHA256, org.bouncycastle.asn1.DERNull.INSTANCE);
            return toCrl(BadCerts.resign(encoded(build()), signingKey, "SHA256withECDSA", withNull, elements -> {
                elements.set(tbsSignatureIndex(elements), withNull);
                return elements;
            }));
        }

        private static byte[] encoded(X509CRL crl) {
            try {
                return crl.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ------------------------------------------------------------- re-encoding

    /**
     * Re-encodes a signed structure ({@code SEQUENCE { tbs, signatureAlgorithm, signature BIT STRING }}) after
     * rewriting its tbs part, and signs the rewritten tbs with the given algorithm. Used for the two fields no builder
     * can produce: a missing version and a tbs signature algorithm that disagrees with the outer one.
     */
    private static byte[] resign(byte[] signed, PrivateKey key, String signatureAlgorithm, AlgorithmIdentifier outer,
                                 UnaryOperator<List<ASN1Encodable>> rewrite) {
        try {
            ASN1Sequence structure = ASN1Sequence.getInstance(signed);
            ASN1Sequence tbs = ASN1Sequence.getInstance(structure.getObjectAt(0));
            List<ASN1Encodable> elements = new ArrayList<>();
            for (int i = 0; i < tbs.size(); i++) {
                elements.add(tbs.getObjectAt(i));
            }
            DERSequence rewritten = new DERSequence(rewrite.apply(elements).toArray(ASN1Encodable[]::new));
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(key);
            signer.update(rewritten.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
            ASN1EncodableVector out = new ASN1EncodableVector();
            out.add(rewritten);
            out.add(outer);
            out.add(new DERBitString(signer.sign()));
            return new DERSequence(out).getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The index of the signature AlgorithmIdentifier (an ECDSA OID, parameters absent) in a tbs element list. */
    private static int tbsSignatureIndex(List<ASN1Encodable> elements) {
        for (int i = 0; i < elements.size(); i++) {
            if (elements.get(i) instanceof ASN1Sequence sequence && sequence.size() >= 1 && sequence.size() <= 2
                    && sequence.getObjectAt(0) instanceof ASN1ObjectIdentifier oid
                    && Certificates.isEcdsaSignature(oid)) {
                return i;
            }
        }
        throw new IllegalStateException("no signature AlgorithmIdentifier in the tbs");
    }

    private static X509Certificate toCertificate(byte[] der) {
        try {
            // BouncyCastle refuses a version 1 certificate that still carries extensions, which is exactly the shape
            // the version rule has to see, so the JDK parser reads this one
            return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509CRL toCrl(byte[] der) {
        try {
            return (X509CRL) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCRL(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A DER CSR whose signature algorithm is replaced, for the case no signer can produce: an algorithm that does not
     * match the key it is made with.
     */
    static byte[] csrWithSignatureAlgorithm(byte[] csr, String signatureOid, String signingAlgorithm, PrivateKey key) {
        return resign(csr, key, signingAlgorithm, new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOid)),
                elements -> elements);
    }

    /** A CRL number extension the validator must reject: outside 0..2^159. */
    static CRLNumber negativeCrlNumber() {
        return new CRLNumber(BigInteger.valueOf(-1));
    }

    static DistributionPoint withReasons(String uri) {
        return new DistributionPoint(
                new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))),
                new ReasonFlags(ReasonFlags.keyCompromise), null);
    }

    static DistributionPoint withCrlIssuer(String uri) {
        return new DistributionPoint(
                new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))),
                null, new GeneralNames(new GeneralName(GeneralName.dNSName, "issuer.example.test")));
    }
}
