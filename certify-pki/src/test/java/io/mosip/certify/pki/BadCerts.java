package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Certificates that break exactly one Annex B rule, built with plain BouncyCastle rather than the production builders:
 * a builder that refuses invalid input cannot produce the certificate a negative test needs. Each factory starts from a
 * conforming certificate; a test mutates one property and the validator must report one named violation.
 */
final class BadCerts {

    static final String IACA_URI = "https://credentials.example.test/mdoc/iaca";
    static final String CRL_URI = "https://credentials.example.test/mdoc/iaca/iaca.crl";
    static final Provider BC = new BouncyCastleProvider();

    private BadCerts() {}

    static KeyPair ec(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(switch (bits) {
                case 384 -> "secp384r1";
                case 521 -> "secp521r1";
                default -> "secp256r1";
            }));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] keyId(PublicKey key) {
        return Certificates.keyIdentifier(key);
    }

    static GeneralNames issuerAltNames(String value) {
        return new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, value));
    }

    static CRLDistPoint crlDistributionPoint(String uri) {
        return new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(new DistributionPointName(new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, uri))), null, null)});
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
        cert.with(Extension.subjectKeyIdentifier, false, new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(keyId(keyPair.getPublic())));
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
        cert.notAfter = Date.from(Instant.now().plus(Duration.ofDays(300)));
        cert.with(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
        cert.with(Extension.subjectKeyIdentifier, false, new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(keyId(subjectKeyPair.getPublic())));
        cert.with(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        cert.with(Extension.extendedKeyUsage, true, documentSignerEku());
        // copied from the IACA, as Annex B requires, so only a test that breaks it reports a mismatch
        cert.with(Extension.issuerAlternativeName, false,
                GeneralNames.getInstance(Certificates.extension(iaca, Extension.issuerAlternativeName)));
        cert.with(Extension.cRLDistributionPoints, false, crlDistributionPoint(CRL_URI));
        return cert;
    }

    /** A CRL signed by the IACA key, with optional v2 extensions, ready to be mutated through the arguments. */
    static X509CRL crl(X509Certificate iaca, KeyPair signingKey, String issuer, byte[] authorityKeyIdentifier,
                       boolean crlNumber, Date thisUpdate, Date nextUpdate, BigInteger... revoked) {
        X500Name name = issuer == null ? X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded()) : new X500Name(issuer);
        X509v2CRLBuilder builder = new X509v2CRLBuilder(name, thisUpdate);
        if (nextUpdate != null) {
            builder.setNextUpdate(nextUpdate);
        }
        try {
            if (authorityKeyIdentifier != null) {
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(authorityKeyIdentifier));
            }
            if (crlNumber) {
                builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(thisUpdate.getTime())));
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        for (BigInteger serial : revoked) {
            builder.addCRLEntry(serial, thisUpdate, 0);
        }
        try {
            return new JcaX509CRLConverter().setProvider(BC)
                    .getCRL(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(signingKey.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** An X.509 version 1 CRL, which BouncyCastle no longer builds: hand-encoded with no version and no extensions. */
    static X509CRL v1Crl(X509Certificate iaca, KeyPair signingKey, Date thisUpdate) {
        try {
            X500Name issuer = X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded());
            AlgorithmIdentifier algorithm = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(Certificates.ECDSA_WITH_SHA256));
            DERSequence tbs = new DERSequence(new ASN1Encodable[] {algorithm, issuer, new Time(thisUpdate)});
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
            signature.initSign(signingKey.getPrivate());
            signature.update(tbs.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
            ASN1EncodableVector list = new ASN1EncodableVector();
            list.add(tbs);
            list.add(algorithm);
            list.add(new DERBitString(signature.sign()));
            byte[] der = new DERSequence(list).getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
            return new JcaX509CRLConverter().setProvider(BC).getCRL(new X509CRLHolder(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A mutable certificate description; {@link #build()} signs it as described. */
    static final class Cert {

        private X500Name issuer;
        private X500Name subject;
        private BigInteger serial = BigInteger.valueOf(1);
        private Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
        private Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(300)));
        private PublicKey publicKey;
        private PrivateKey signingKey;
        private String signatureAlgorithm = "SHA256withECDSA";
        private final List<Ext> extensions = new ArrayList<>();

        private record Ext(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {}

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
                    extensions.set(i, new Ext(oid, critical, extension.value()));
                }
            }
            return this;
        }

        Cert with(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
            without(oid);
            extensions.add(new Ext(oid, critical, value));
            return this;
        }

        X509Certificate build() {
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject,
                    SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            for (Ext extension : extensions) {
                try {
                    builder.addExtension(extension.oid(), extension.critical(), extension.value());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            try {
                return new JcaX509CertificateConverter().setProvider(BC).getCertificate(builder.build(
                        new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signingKey)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
