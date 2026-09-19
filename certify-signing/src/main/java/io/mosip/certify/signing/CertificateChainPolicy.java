package io.mosip.certify.signing;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * The checks a certificate chain must pass before it signs a credential (docs/design/06a-x509-pki-and-mdoc.md): every
 * certificate is valid at signing time and is signed by the next one, a self-signed last certificate by itself. A chain
 * that ends at a certificate whose issuer is absent is accepted: the verifier's trust anchor decides that link.
 */
public final class CertificateChainPolicy {

    private CertificateChainPolicy() {}

    public static void check(CertificateChain chain, Instant now) {
        if (chain == null || chain.isEmpty()) {
            return;
        }
        List<X509Certificate> certificates = chain.leafFirst();
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate certificate = certificates.get(i);
            try {
                certificate.checkValidity(Date.from(now));
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new SigningException("Certificate " + certificate.getSubjectX500Principal() + " is not valid at " + now + ": " + e.getMessage(), e);
            }
            X509Certificate issuer;
            if (i + 1 < certificates.size()) {
                issuer = certificates.get(i + 1);
            } else if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                issuer = certificate;
            } else {
                continue;
            }
            try {
                certificate.verify(issuer.getPublicKey());
            } catch (GeneralSecurityException e) {
                throw new SigningException("Certificate " + certificate.getSubjectX500Principal() + " is not signed by " + issuer.getSubjectX500Principal(), e);
            }
        }
    }
}
