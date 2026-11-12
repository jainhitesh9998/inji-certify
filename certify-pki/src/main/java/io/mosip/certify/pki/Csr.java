package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;

/**
 * A PKCS#10 certification request whose key, signature algorithm and proof of possession have been checked. The public
 * key and subject are what a Document Signer certificate needs; the request itself is kept so it can be written back
 * out.
 *
 * <p>A CSR is untrusted input: it may come from a keymanager the operator does not control. So it is held to the same
 * key profile as a generated key (EC, named P-256/384/521, uncompressed point, no explicit parameters) and its
 * signature algorithm must be one of {@code ecdsa-with-SHA256/384/512} matching that curve.
 */
public final class Csr {

    private final PKCS10CertificationRequest request;
    private final X500Principal subject;
    private final PublicKey publicKey;

    private Csr(PKCS10CertificationRequest request, X500Principal subject, PublicKey publicKey) {
        this.request = request;
        this.subject = subject;
        this.publicKey = publicKey;
    }

    /** Parse a PKCS#10 request in DER or PEM and verify its self-signature; throws when any check fails. */
    public static Csr parse(byte[] encoded) {
        PKCS10CertificationRequest request = request(encoded);
        if (request == null) {
            throw new PkiException("CSR_INVALID: not a PKCS#10 certification request");
        }
        SubjectPublicKeyInfo spki = request.getSubjectPublicKeyInfo();
        String problem = Certificates.keyProblem(spki);
        if (problem != null) {
            throw new PkiException("CSR_KEY_INVALID: " + problem);
        }
        AlgorithmIdentifier signature = request.getSignatureAlgorithm();
        ASN1ObjectIdentifier required = Certificates.signatureCurve(signature.getAlgorithm());
        if (required == null) {
            throw new PkiException("CSR_SIGNATURE_ALGORITHM_INVALID: the request signature algorithm "
                    + signature.getAlgorithm().getId() + " is not ecdsa-with-SHA256/384/512");
        }
        if (signature.getParameters() != null) {
            throw new PkiException("CSR_SIGNATURE_ALGORITHM_INVALID: the request signature algorithm carries parameters");
        }
        ASN1ObjectIdentifier curve = (ASN1ObjectIdentifier) spki.getAlgorithm().getParameters().toASN1Primitive();
        if (!required.equals(curve)) {
            throw new PkiException("CSR_SIGNATURE_ALGORITHM_MISMATCH: the request is signed with "
                    + signature.getAlgorithm().getId() + " over a " + curve.getId() + " key");
        }
        try {
            boolean valid = request.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(Certificates.provider()).build(spki));
            if (!valid) {
                throw new PkiException("CSR_SIGNATURE_INVALID: the request is not signed by the key it carries");
            }
            PublicKey publicKey = new JcaPEMKeyConverter().setProvider(Certificates.provider()).getPublicKey(spki);
            return new Csr(request, new X500Principal(request.getSubject().getEncoded()), publicKey);
        } catch (Exception e) {
            if (e instanceof PkiException pki) {
                throw pki;
            }
            throw new PkiException("CSR_SIGNATURE_INVALID: cannot verify the request signature", e);
        }
    }

    /** Parse a PEM {@code CERTIFICATE REQUEST} or {@code NEW CERTIFICATE REQUEST} block. */
    public static Csr parsePem(String pem) {
        return parse(pem.getBytes(StandardCharsets.US_ASCII));
    }

    public X500Principal subject() {
        return subject;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    /** The PEM {@code CERTIFICATE REQUEST} encoding of this request. */
    public String pem() {
        return Pem.writeCsr(request);
    }

    private static PKCS10CertificationRequest request(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return null;
        }
        String text = new String(encoded, StandardCharsets.US_ASCII);
        if (text.contains("-----BEGIN")) {
            try (PEMParser parser = new PEMParser(new StringReader(text))) {
                Object object = parser.readObject();
                return object instanceof PKCS10CertificationRequest csr ? csr : null;
            } catch (IOException e) {
                throw new PkiException("CSR_INVALID: cannot parse the PEM request", e);
            }
        }
        try {
            return new PKCS10CertificationRequest(encoded);
        } catch (IOException | RuntimeException e) {
            throw new PkiException("CSR_INVALID: cannot parse the DER request", e);
        }
    }
}
