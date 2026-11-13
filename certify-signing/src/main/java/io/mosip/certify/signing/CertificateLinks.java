package io.mosip.certify.signing;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * How one certificate links to the one that issued it (RFC 5280 4.2.1.1, 4.2.1.2): the key identifiers, and the issuer
 * among a set of candidates. Used to find the trust anchor a Document Signer chains to and to complete a chain a key
 * provider returns leaf-only.
 */
public final class CertificateLinks {

    private CertificateLinks() {}

    /** The subjectKeyIdentifier octets, when the certificate carries a readable one. */
    public static Optional<byte[]> subjectKeyIdentifier(X509Certificate certificate) {
        byte[] value = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(value).getOctets()).getKeyIdentifier());
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** The authorityKeyIdentifier keyIdentifier octets, when the certificate carries a readable one. */
    public static Optional<byte[]> authorityKeyIdentifier(X509Certificate certificate) {
        byte[] value = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(value).getOctets()).getKeyIdentifier());
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** The subjectKeyIdentifier as lower-case hex, when present. */
    public static Optional<String> subjectKeyIdentifierHex(X509Certificate certificate) {
        return subjectKeyIdentifier(certificate).map(HexFormat.of()::formatHex);
    }

    /**
     * Whether the certificate is self-issued (RFC 5280 6.1: subject and issuer names are equal). The signature is not
     * verified; {@link #signedBy} says whether a key actually signed a certificate.
     */
    public static boolean selfIssued(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    /** Whether the certificate's signature verifies under {@code issuer}'s public key, whatever the names and key identifiers say. */
    public static boolean signedBy(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Whether {@code issuer} issued {@code certificate}: the authority key identifier equals the issuer's subject key
     * identifier when both are present, otherwise the issuer name equals the issuer's subject; and in either case the
     * certificate's signature verifies under the issuer's key.
     */
    public static boolean issuedBy(X509Certificate certificate, X509Certificate issuer) {
        Optional<byte[]> aki = authorityKeyIdentifier(certificate);
        Optional<byte[]> ski = subjectKeyIdentifier(issuer);
        boolean named = aki.isPresent() && ski.isPresent()
                ? Arrays.equals(aki.get(), ski.get())
                : certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal());
        return named && signedBy(certificate, issuer);
    }

    /** The first candidate that issued {@code certificate}, by {@link #issuedBy}. */
    public static Optional<X509Certificate> issuerAmong(X509Certificate certificate, List<X509Certificate> candidates) {
        return candidates.stream().filter(candidate -> issuedBy(certificate, candidate)).findFirst();
    }
}
