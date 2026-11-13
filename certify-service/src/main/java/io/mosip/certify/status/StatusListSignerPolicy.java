package io.mosip.certify.status;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateChainPolicy;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.SigningContext;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The checks a signer passes before it signs a CWT status list (docs/design/wp/M-11-status-list-under-iaca.md section
 * 4.7). Every refusal is an {@link IllegalStateException} whose message starts with the rule it broke, because that
 * message is what the service logs and what an operator acts on: at renewal it becomes the existing back-off and 503
 * path, at issuance {@code FormatException("status_list_unavailable")}.
 *
 * <p>Two groups, as for the mDoc Document Signer ({@code MdocDscPolicy}):
 * <ul>
 *     <li><b>always</b>: the signer has a certificate chain, the leaf is not self-signed, the signing instant lies
 *     inside every certificate's validity and every link verifies ({@link CertificateChainPolicy}), and the
 *     {@code x5chain} the token would carry holds no self-signed certificate;</li>
 *     <li><b>once an {@code mdoc-iaca} anchor is configured</b> ({@link #enforced()}): an IACA issued the chain's top
 *     certificate, the anchor's CRL does not list the leaf and is not stale, and the leaf carries the extended key
 *     usage its {@link Mode} needs plus {@code digitalSignature} key usage.</li>
 * </ul>
 *
 * <p>This class runs <b>before every</b> {@code CwtEnvelope.signOrdered} call: M-11a's envelope refuses only an empty
 * chain, a self-signed leaf and an emitted chain that carries a self-signed certificate, and checks no validity, EKU,
 * revocation or IACA. Its own {@link SigningException}s use the same {@code STATUS_SIGNER_} prefixes, and
 * {@link #refusal} maps them onto this class's type so both layers fail the same way.
 *
 * <p>Without anchors none of the second group runs, so a deployment whose mDLs are signed by keymanager's
 * master-signed certificate keeps signing lists exactly as it signs credentials (CLAUDE.md rule 1; D16 refined by the
 * decision log), and startup says so at INFO ({@link #enforced()}, logged by the bean that owns this policy).
 */
public final class StatusListSignerPolicy {

    /** The signing key has no certificate, so the token's protected {@code x5chain} would be empty. */
    public static final String NO_CHAIN = "STATUS_SIGNER_NO_CHAIN";
    /** The signing certificate is self-signed, so the token would carry its own trust anchor. */
    public static final String SELF_SIGNED = "STATUS_SIGNER_SELF_SIGNED";
    /** A certificate of the chain is expired at the signing instant. */
    public static final String EXPIRED = "STATUS_SIGNER_EXPIRED";
    /** A certificate of the chain is not yet valid at the signing instant. */
    public static final String NOT_YET_VALID = "STATUS_SIGNER_NOT_YET_VALID";
    /** A link of the chain does not verify. */
    public static final String CHAIN_LINK_INVALID = "CHAIN_LINK_INVALID";
    /** The {@code x5chain} the token would emit holds a self-signed certificate above the leaf. */
    public static final String CARRIES_ANCHOR = "STATUS_SIGNER_CARRIES_ANCHOR";
    /** No configured IACA issued the chain's top certificate. */
    public static final String NO_TRUSTED_IACA = "STATUS_SIGNER_NO_TRUSTED_IACA";
    /** The anchor's CRL lists the signer's certificate. */
    public static final String REVOKED = "STATUS_SIGNER_REVOKED";
    /** The anchor's CRL passed its {@code nextUpdate} beyond the stale-CRL grace before the signing instant. */
    public static final String CRL_STALE = "CRL_STALE";
    /** The leaf lacks the extended key usage of its mode, or key usage {@code digitalSignature}. */
    public static final String PURPOSE = "STATUS_SIGNER_PURPOSE";

    /** ISO/IEC 18013-5 Annex B Table B.3: the Document Signer's extended key usage, {@code id-kp-documentSigner}. */
    public static final String DOCUMENT_SIGNER_EKU = "1.0.18013.5.1.2";
    /** IANA "SMI Security for PKIX Extended Key Purpose" 45 (registered 2026-06-12): {@code id-kp-oauthStatusSigning}. */
    public static final String STATUS_SIGNING_EKU = "1.3.6.1.5.5.7.3.45";

    /** The prefix every refusal of this layer (and of M-11a's envelope) carries. */
    public static final String PREFIX = "STATUS_SIGNER_";

    /** The rules this class names. */
    public static final Set<String> RULES = Set.of(NO_CHAIN, SELF_SIGNED, EXPIRED, NOT_YET_VALID, CHAIN_LINK_INVALID,
            CARRIES_ANCHOR, NO_TRUSTED_IACA, REVOKED, CRL_STALE, PURPOSE);

    /** Which extended key usage the leaf must carry: the mDL Document Signer's, or the dedicated status signer's. */
    public enum Mode {
        /** The Document Signer that signed the mDLs on the list also signs the list (D-M11-1 (a), TSL section 11.3). */
        DOCUMENT_SIGNER,
        /** A signer the IACA issued for status-list signing only (D-M11-1 (b), TSL section 10; M-11h). */
        DEDICATED
    }

    private final TrustAnchorRegistry registry;

    public StatusListSignerPolicy(TrustAnchorRegistry registry) {
        this.registry = registry == null ? TrustAnchorRegistry.EMPTY : registry;
    }

    /** The policy without trust anchors: only the rules that hold whatever is configured. */
    public static StatusListSignerPolicy notEnforced() {
        return new StatusListSignerPolicy(TrustAnchorRegistry.EMPTY);
    }

    /** Whether the trust-anchor rules apply: the registry holds at least one {@code mdoc-iaca} anchor (the D16 switch). */
    public boolean enforced() {
        return !registry.entries(TrustAnchorRegistry.MDOC_IACA).isEmpty();
    }

    /**
     * Holds a signer to section 4.7 before it signs a status list.
     *
     * @throws IllegalStateException with the rule's name as the message prefix
     */
    public void check(SigningContext signing, Instant now, Mode mode) {
        Objects.requireNonNull(signing, "signing");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(mode, "mode");
        CertificateChain chain = signing.key().chain();
        if (chain == null || chain.isEmpty() || chain.leaf().isEmpty()) {
            throw refuse(NO_CHAIN, "the key " + signing.key().ref() + " has no certificate; the protected x5chain of a"
                    + " Status List Token is the only statement of who signed it (TSL section 11.3, ISO/IEC 18013-5"
                    + " second edition 12.3.6.3), so a token without one is invalid on arrival");
        }
        List<X509Certificate> certificates = chain.leafFirst();
        X509Certificate leaf = certificates.get(0);
        if (CertificateLinks.selfIssued(leaf)) {
            throw refuse(SELF_SIGNED, "the signing certificate " + leaf.getSubjectX500Principal() + " is self-signed;"
                    + " the trust anchor is the verifier's to supply (ISO/IEC 18013-5 second edition 12.3.6.2), so the"
                    + " signer needs a certificate issued by the IACA");
        }
        try {
            CertificateChainPolicy.check(chain, now);
        } catch (SigningException e) {
            throw validityRefusal(e);
        }
        List<X509Certificate> emitted = chain.withoutAnchor().leafFirst();
        for (int index = 1; index < emitted.size(); index++) {
            X509Certificate certificate = emitted.get(index);
            if (CertificateLinks.selfIssued(certificate)) {
                throw refuse(CARRIES_ANCHOR, "the x5chain the token would carry holds the self-signed certificate "
                        + certificate.getSubjectX500Principal() + " at position " + index + "; a verifier supplies the"
                        + " trust anchor itself (ISO/IEC 18013-5 second edition 12.3.6.2)");
            }
        }
        if (enforced()) {
            checkTrust(leaf, certificates, now, mode);
        }
    }

    /** The validity rule a failed {@link CertificateChainPolicy} check broke, with the same prefix family. */
    private static IllegalStateException validityRefusal(SigningException failure) {
        Throwable cause = failure.getCause();
        String rule = cause instanceof CertificateExpiredException ? EXPIRED
                : cause instanceof CertificateNotYetValidException ? NOT_YET_VALID : CHAIN_LINK_INVALID;
        return refuse(rule, failure.getMessage(), failure);
    }

    private void checkTrust(X509Certificate leaf, List<X509Certificate> certificates, Instant now, Mode mode) {
        List<TrustAnchorRegistry.Anchor> anchors = registry.entries(TrustAnchorRegistry.MDOC_IACA);
        X509Certificate candidate = topmostNonAnchor(certificates, anchors);
        TrustAnchorRegistry.Anchor anchor = anchors.stream()
                .filter(candidateAnchor -> CertificateLinks.issuedBy(candidate, candidateAnchor.certificate()))
                .findFirst()
                .orElseThrow(() -> refuse(NO_TRUSTED_IACA, "the certificate " + candidate.getSubjectX500Principal()
                        + " (issuer " + candidate.getIssuerX500Principal() + ", at the top of the signer's chain) was"
                        + " not issued by any configured IACA " + anchors.stream().map(TrustAnchorRegistry.Anchor::id).toList()
                        + "; status lists are signed only under certify.pki.trust-anchors.mdoc-iaca (D16)"));
        Optional<X509CRL> crl = registry.crl(anchor.id());
        if (crl.isPresent()) {
            X509CRLEntry entry = crl.get().getRevokedCertificate(leaf.getSerialNumber());
            if (entry != null) {
                throw refuse(REVOKED, "the status list signer " + leaf.getSubjectX500Principal() + " (serial "
                        + leaf.getSerialNumber().toString(16) + ") is revoked by the CRL of the IACA " + anchor.id()
                        + " since " + entry.getRevocationDate().toInstant());
            }
            requireFresh(crl.get(), anchor, now);
        }
        requirePurpose(leaf, mode);
    }

    /**
     * The certificate a configured IACA had to issue: the chain's top certificate, or — when the chain carries the
     * anchor itself — the one below it (a verifier builds the path from the signer to the IACA it supplies, so the
     * anchor's own presence says nothing about who issued the signer).
     */
    private static X509Certificate topmostNonAnchor(List<X509Certificate> certificates, List<TrustAnchorRegistry.Anchor> anchors) {
        int index = certificates.size() - 1;
        while (index > 0 && isAnchor(certificates.get(index), anchors)) {
            index--;
        }
        return certificates.get(index);
    }

    private static boolean isAnchor(X509Certificate certificate, List<TrustAnchorRegistry.Anchor> anchors) {
        return anchors.stream().map(TrustAnchorRegistry.Anchor::certificate).anyMatch(certificate::equals);
    }

    /**
     * RFC 5280 6.3.3: a verifier that finds the anchor's CRL past its {@code nextUpdate} cannot establish the signer's
     * status and rejects the token, so signing past {@link TrustAnchorRegistry#staleCrlGrace()} would only produce a
     * list that fails verification. {@link AnnexBValidator#CLOCK_SKEW} is added to the window so a few seconds of clock
     * difference between this issuer and the IACA do not retire a list that still verifies.
     */
    private void requireFresh(X509CRL crl, TrustAnchorRegistry.Anchor anchor, Instant at) {
        if (crl.getNextUpdate() == null) {
            return; // validateCrl refuses a CRL without nextUpdate before it reaches the registry
        }
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        Duration grace = registry.staleCrlGrace();
        if (at.isAfter(nextUpdate.plus(grace).plus(AnnexBValidator.CLOCK_SKEW))) {
            throw refuse(CRL_STALE, "the CRL of the IACA " + anchor.id() + " passed its nextUpdate " + nextUpdate
                    + ", more than the grace " + grace + " (certify.pki.stale-crl-grace) and the clock skew "
                    + AnnexBValidator.CLOCK_SKEW + " before the signing instant " + at + "; a verifier rejects a status"
                    + " list whose IACA CRL is stale (RFC 5280 6.3.3): publish a new CRL");
        }
    }

    /**
     * The leaf's key usage and extended key usage for its mode: {@code digitalSignature} always, and the mDL Document
     * Signer EKU ({@value #DOCUMENT_SIGNER_EKU}) in {@link Mode#DOCUMENT_SIGNER} or {@code id-kp-oauthStatusSigning}
     * ({@value #STATUS_SIGNING_EKU}) in {@link Mode#DEDICATED} (TSL section 10; IANA assigned value 45 on 2026-06-12).
     * ISO/IEC 18013-5 second edition 12.3.6.3 leaves the status EKU optional for a list signed by the credential's own
     * key, and here that key is the Document Signer, whose EKU is the mDL one; a separate signer is authorised for this
     * purpose only, so it carries the status EKU alone (RFC 5280 section 4.2.1.12).
     */
    private static void requirePurpose(X509Certificate leaf, Mode mode) {
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
            throw refuse(PURPOSE, "the status list signer " + leaf.getSubjectX500Principal() + " does not assert key"
                    + " usage digitalSignature, so its signatures carry no authorisation (RFC 5280 section 4.2.1.3)");
        }
        String required = mode == Mode.DOCUMENT_SIGNER ? DOCUMENT_SIGNER_EKU : STATUS_SIGNING_EKU;
        List<String> extendedKeyUsage;
        try {
            extendedKeyUsage = leaf.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            throw refuse(PURPOSE, "the extended key usage of " + leaf.getSubjectX500Principal() + " cannot be read: "
                    + e.getMessage(), e);
        }
        if (extendedKeyUsage == null || !extendedKeyUsage.contains(required)) {
            throw refuse(PURPOSE, "the extended key usage " + extendedKeyUsage + " of " + leaf.getSubjectX500Principal()
                    + " lacks " + required + " (" + (mode == Mode.DOCUMENT_SIGNER
                    ? "the ISO/IEC 18013-5 Annex B Document Signer purpose, in document-signer mode"
                    : "id-kp-oauthStatusSigning, in dedicated mode") + ")");
        }
    }

    /**
     * The one exception a caller maps: a refusal of this policy (already an {@link IllegalStateException}) or a
     * {@link SigningException} from M-11a's envelope whose message starts with {@value #PREFIX}, wrapped as an
     * {@link IllegalStateException} with the same message and cause. Anything else is returned unchanged, so an
     * unrelated failure keeps its own type.
     *
     * <p>Renewal turns the result into the back-off and 503 path, issuance into
     * {@code FormatException("status_list_unavailable")}.
     */
    public static RuntimeException refusal(RuntimeException failure) {
        Objects.requireNonNull(failure, "failure");
        if (failure instanceof IllegalStateException) {
            return failure;
        }
        if (failure instanceof SigningException && failure.getMessage() != null
                && failure.getMessage().startsWith(PREFIX)) {
            return new IllegalStateException(failure.getMessage(), failure);
        }
        return failure;
    }

    private static IllegalStateException refuse(String rule, String message) {
        return new IllegalStateException(rule + ": " + message);
    }

    private static IllegalStateException refuse(String rule, String message, Throwable cause) {
        return new IllegalStateException(rule + ": " + message, cause);
    }
}
