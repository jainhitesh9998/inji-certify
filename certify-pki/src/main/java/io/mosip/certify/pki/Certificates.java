package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/**
 * DER, extension and signature helpers shared by the Annex B builders and the validator. BouncyCastle is used as an
 * explicit provider instance rather than installed in {@code java.security}, so the library changes no global state.
 */
final class Certificates {

    static final String ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    static final String ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";

    private static final Provider BC = new BouncyCastleProvider();

    private Certificates() {}

    static Provider provider() {
        return BC;
    }

    /** The value of a single-valued RDN of a subject or issuer name, or {@code null} when it is absent. */
    static String attribute(X500Principal principal, ASN1ObjectIdentifier type) {
        var rdns = X500Name.getInstance(principal.getEncoded()).getRDNs(type);
        if (rdns.length == 0) {
            return null;
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    /** The DER value of an extension, or {@code null} when the certificate does not carry it. */
    static byte[] extension(X509Certificate certificate, ASN1ObjectIdentifier oid) {
        byte[] encoded = certificate.getExtensionValue(oid.getId());
        return encoded == null ? null : ASN1OctetString.getInstance(encoded).getOctets();
    }

    /** Whether the certificate carries the extension and marks it critical. */
    static boolean critical(X509Certificate certificate, ASN1ObjectIdentifier oid) {
        return certificate.getCriticalExtensionOIDs() != null
                && certificate.getCriticalExtensionOIDs().contains(oid.getId());
    }

    /** The SubjectKeyIdentifier extension value, or {@code null} when absent. */
    static byte[] subjectKeyIdentifier(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.subjectKeyIdentifier);
        return extension == null ? null : SubjectKeyIdentifier.getInstance(extension).getKeyIdentifier();
    }

    /** The AuthorityKeyIdentifier keyIdentifier of a certificate, or {@code null} when absent. */
    static byte[] authorityKeyIdentifier(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.authorityKeyIdentifier);
        return extension == null ? null : AuthorityKeyIdentifier.getInstance(extension).getKeyIdentifier();
    }

    /** The SKI of a certificate, computed from its public key when the extension is absent. */
    static byte[] keyIdentifier(X509Certificate certificate) {
        byte[] declared = subjectKeyIdentifier(certificate);
        return declared != null ? declared : keyIdentifier(certificate.getPublicKey());
    }

    /** The RFC 5280 method 1 key identifier of a public key: SHA-1 over the subjectPublicKey bit string. */
    static byte[] keyIdentifier(PublicKey publicKey) {
        try {
            return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey).getKeyIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new PkiException("Cannot compute a key identifier", e);
        }
    }

    /** The URI and rfc822 values of the issuerAltName extension, empty when absent. */
    static List<String> issuerAltNames(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.issuerAlternativeName);
        return extension == null ? List.of() : values(GeneralNames.getInstance(extension).getNames());
    }

    /** The URI distribution points of the CRL distribution point extension, empty when absent. */
    static List<String> crlDistributionPointUris(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.cRLDistributionPoints);
        if (extension == null) {
            return List.of();
        }
        List<String> uris = new ArrayList<>();
        for (DistributionPoint point : CRLDistPoint.getInstance(extension).getDistributionPoints()) {
            DistributionPointName name = point.getDistributionPoint();
            if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                uris.addAll(values(GeneralNames.getInstance(name.getName()).getNames()));
            }
        }
        return uris;
    }

    private static List<String> values(GeneralName[] names) {
        List<String> values = new ArrayList<>();
        for (GeneralName name : names) {
            if (name.getTagNo() == GeneralName.uniformResourceIdentifier || name.getTagNo() == GeneralName.rfc822Name) {
                values.add(name.getName().toString());
            }
        }
        return values;
    }

    /** An issuerAltName value with an optional URI and an optional rfc822 email. */
    static GeneralNames issuerAltNames(String uri, String email) {
        List<GeneralName> names = new ArrayList<>(2);
        if (uri != null) {
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
        }
        if (email != null) {
            names.add(new GeneralName(GeneralName.rfc822Name, email));
        }
        if (names.isEmpty()) {
            throw new PkiException("IACA_ISSUER_ALT_NAME_MISSING: an issuerAltName needs a URI or an email address");
        }
        return new GeneralNames(names.toArray(GeneralName[]::new));
    }

    static CRLDistPoint crlDistributionPoint(String uri) {
        return new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(
                        new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))),
                        null, null)});
    }

    /** The ECDSA signature algorithm Annex B pairs with a P-256, P-384 or P-521 key. */
    static String signatureAlgorithm(PublicKey key) {
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            return switch (bits) {
                case 256 -> "SHA256withECDSA";
                case 384 -> "SHA384withECDSA";
                case 521 -> "SHA512withECDSA";
                default -> throw new PkiException(
                        "CURVE_UNSUPPORTED: Annex B signs with ECDSA over P-256, P-384 or P-521, not " + bits + " bits");
            };
        }
        throw new PkiException("KEY_UNSUPPORTED: Annex B certificates are signed with ECDSA, not " + key.getAlgorithm());
    }

    /** The curve size Annex B pairs with an {@code ecdsa-with-SHA*} signature algorithm, or {@code 0} when unsupported. */
    static int signatureCurveBits(String signatureAlgorithmOid) {
        return switch (signatureAlgorithmOid) {
            case ECDSA_WITH_SHA256 -> 256;
            case ECDSA_WITH_SHA384 -> 384;
            case ECDSA_WITH_SHA512 -> 521;
            default -> 0;
        };
    }

    static ContentSigner signer(PrivateKey key, String signatureAlgorithm) {
        try {
            return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(key);
        } catch (OperatorCreationException e) {
            throw new PkiException("Cannot sign with " + signatureAlgorithm, e);
        }
    }

    static X509Certificate certificate(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
        } catch (CertificateException e) {
            throw new PkiException("Cannot convert the certificate", e);
        }
    }

    static X509CRL crl(X509CRLHolder holder) {
        try {
            return new JcaX509CRLConverter().setProvider(BC).getCRL(holder);
        } catch (java.security.cert.CRLException e) {
            throw new PkiException("Cannot convert the CRL", e);
        }
    }

    /** Whether the certificate is signed by the given key. */
    static boolean signedBy(X509Certificate certificate, PublicKey key) {
        try {
            certificate.verify(key);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
