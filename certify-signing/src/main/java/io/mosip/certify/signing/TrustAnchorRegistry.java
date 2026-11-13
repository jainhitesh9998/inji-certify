package io.mosip.certify.signing;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The trust anchors this issuer chains to, per purpose (docs/design/06a-x509-pki-and-mdoc.md): for
 * {@value #MDOC_IACA}, the ISO/IEC 18013-5 Annex B IACA certificates whose Document Signers may sign an mDoc, each
 * with the CRL it publishes when one is configured. The registry is what the mDoc DSC policy checks a signing chain
 * against, what a key provider completes a leaf-only chain from, and what the IACA publication serves; it decides
 * nothing itself.
 *
 * <p>An anchor's id is stable and URL-safe: the publication serves {@code /mdoc/iaca/<id>.crl}, which is the CRL
 * distribution point an operator writes into the IACA.
 */
public interface TrustAnchorRegistry {

    /** ISO/IEC 18013-5 Issuing Authority CA certificates, the roots of mDoc Document Signer chains. */
    String MDOC_IACA = PublicKeyDescriptor.PURPOSE_MDOC_IACA;

    /** A registry without anchors: nothing is enforced against it and nothing is published. */
    TrustAnchorRegistry EMPTY = new TrustAnchorRegistry() {
        @Override
        public List<Anchor> entries(String purpose) {
            return List.of();
        }

        @Override
        public Optional<X509CRL> crl(String anchorId) {
            return Optional.empty();
        }
    };

    /** One trust anchor: its id, the purpose it is trusted for, and the certificate. */
    record Anchor(String id, String purpose, X509Certificate certificate) {
        public Anchor {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(purpose, "purpose");
            Objects.requireNonNull(certificate, "certificate");
        }
    }

    /** The anchors trusted for {@code purpose}, in a stable order; empty when none is configured. */
    List<Anchor> entries(String purpose);

    /** The current CRL the anchor publishes, when one is configured or generated. */
    Optional<X509CRL> crl(String anchorId);

    /** The anchor certificates trusted for {@code purpose}. */
    default List<X509Certificate> anchors(String purpose) {
        return entries(purpose).stream().map(Anchor::certificate).toList();
    }

    /** The anchor with this id among those trusted for {@code purpose}. */
    default Optional<Anchor> anchor(String purpose, String anchorId) {
        return entries(purpose).stream().filter(anchor -> anchor.id().equals(anchorId)).findFirst();
    }
}
