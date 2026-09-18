package io.mosip.certify.signing;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** An X.509 chain, leaf first, as carried by every {@link SigningKey}; may be empty for keys without certificates. */
public record CertificateChain(List<X509Certificate> leafFirst) {

    public static final CertificateChain EMPTY = new CertificateChain(List.of());

    public CertificateChain {
        leafFirst = List.copyOf(leafFirst);
    }

    public static CertificateChain of(X509Certificate... certificates) {
        return new CertificateChain(List.of(certificates));
    }

    public boolean isEmpty() { return leafFirst.isEmpty(); }

    public Optional<X509Certificate> leaf() {
        return leafFirst.isEmpty() ? Optional.empty() : Optional.of(leafFirst.get(0));
    }

    public Optional<X509Certificate> root() {
        return leafFirst.isEmpty() ? Optional.empty() : Optional.of(leafFirst.get(leafFirst.size() - 1));
    }

    /** Subject alternative names of the leaf as strings (dNSName and URI entries), for {@code iss} matching. */
    public List<String> subjectAltNames() {
        List<String> names = new ArrayList<>();
        leaf().ifPresent(cert -> {
            try {
                Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (san.size() == 2 && san.get(1) instanceof String value) {
                            names.add(value);
                        }
                    }
                }
            } catch (java.security.cert.CertificateParsingException e) {
                throw new SigningException("Cannot read subject alternative names of the leaf certificate", e);
            }
        });
        return names;
    }

    /** DER certificates base64 (not base64url) encoded, leaf first: the {@code x5c} header value. */
    public List<String> toX5c() {
        List<String> out = new ArrayList<>(leafFirst.size());
        for (X509Certificate cert : leafFirst) {
            out.add(Base64.getEncoder().encodeToString(der(cert)));
        }
        return out;
    }

    /** DER certificates, leaf first: the COSE {@code x5chain} value. */
    public List<byte[]> toDer() {
        List<byte[]> out = new ArrayList<>(leafFirst.size());
        for (X509Certificate cert : leafFirst) {
            out.add(der(cert));
        }
        return out;
    }

    private static byte[] der(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new SigningException("Cannot DER-encode certificate " + cert.getSubjectX500Principal(), e);
        }
    }
}
