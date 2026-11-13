package io.mosip.certify.format.mdoc;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateChainPolicy;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.FormatException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * The Document Signer policy an mDoc is held to before it is signed (docs/design/20-mdl-issuer.md M-06, decision
 * D16). Every refusal is {@code certificate_chain_invalid} with a message that starts with the rule it broke: one of
 * the rules below or an {@code IACA_*}/{@code DS_*} rule of {@link AnnexBValidator}.
 *
 * <p>Two parts:
 * <ul>
 *     <li>always, whatever is configured: the IssuerAuth carries an {@code x5chain} with a document signer that is not
 *     self-signed and without the trust anchor ({@link #requireX5chain}), the signing instant lies inside the DSC's
 *     validity, and every link of the chain verifies ({@link CertificateChainPolicy});</li>
 *     <li>when a {@link TrustAnchorRegistry} holds {@value TrustAnchorRegistry#MDOC_IACA} anchors ({@link #enforced}),
 *     fail closed on every surface: one of those IACAs issued the DSC, the IACA is valid at the signing instant and
 *     passes {@link AnnexBValidator#validateIaca}, the DSC passes {@link AnnexBValidator#validateDs} against it, and
 *     the IACA's CRL, when one is configured, does not list the DSC and is not past its {@code nextUpdate} by more
 *     than {@link TrustAnchorRegistry#staleCrlGrace()} ({@value #CRL_STALE}; decision log 2026-11-13, refining D16).</li>
 * </ul>
 * Without anchors the second part is skipped, so a deployment that signs mDocs with keymanager's master-signed
 * certificates (the draft-13 and compatibility surfaces, the recorded goldens) keeps its bytes (CLAUDE.md rule 1;
 * the decision log refines D16 that way). {@code issuing_country} against the DSC country stays in
 * {@link MdocDataModelValidator#validateAgainstCertificate}, the one place that rule lives.
 */
public final class MdocDscPolicy {

    public static final String X5CHAIN_MISSING = "X5CHAIN_MISSING";
    public static final String DSC_SELF_SIGNED = "DSC_SELF_SIGNED";
    public static final String X5CHAIN_NONE = "X5CHAIN_NONE";
    public static final String X5CHAIN_DROPS_INTERMEDIATES = "X5CHAIN_DROPS_INTERMEDIATES";
    public static final String X5CHAIN_CARRIES_ANCHOR = "X5CHAIN_CARRIES_ANCHOR";
    public static final String DSC_NOT_YET_VALID = "DSC_NOT_YET_VALID";
    public static final String DSC_EXPIRED = "DSC_EXPIRED";
    public static final String CHAIN_LINK_INVALID = "CHAIN_LINK_INVALID";
    public static final String DSC_NO_TRUSTED_IACA = "DSC_NO_TRUSTED_IACA";
    public static final String IACA_NOT_YET_VALID = "IACA_NOT_YET_VALID";
    public static final String IACA_EXPIRED = "IACA_EXPIRED";
    public static final String DSC_REVOKED = "DSC_REVOKED";
    /** The IACA's CRL passed its nextUpdate more than the stale-CRL grace before the signing instant. */
    public static final String CRL_STALE = "CRL_STALE";
    /** The dry run could not resolve the configured signing key, so no policy rule could be judged (fail closed). */
    public static final String KEY_UNRESOLVED = "KEY_UNRESOLVED";

    /** The rules this class names itself; the Annex B profile rules come from {@link AnnexBValidator#RULES}. */
    public static final Set<String> RULES = Set.of(X5CHAIN_MISSING, DSC_SELF_SIGNED, X5CHAIN_NONE,
            X5CHAIN_DROPS_INTERMEDIATES, X5CHAIN_CARRIES_ANCHOR, DSC_NOT_YET_VALID, DSC_EXPIRED, CHAIN_LINK_INVALID,
            DSC_NO_TRUSTED_IACA, IACA_NOT_YET_VALID, IACA_EXPIRED, DSC_REVOKED, CRL_STALE, KEY_UNRESOLVED);

    /** Profile results per (DSC, IACA) pair: neither validator depends on the instant, so a pair is judged once. */
    private static final int PROFILE_CACHE_SIZE = 64;

    private final TrustAnchorRegistry registry;
    private final Map<String, List<AnnexBValidator.Violation>> profileCache = new ConcurrentHashMap<>();

    public MdocDscPolicy(TrustAnchorRegistry registry) {
        this.registry = registry == null ? TrustAnchorRegistry.EMPTY : registry;
    }

    /** The policy without trust anchors: only the rules that apply whatever is configured. */
    public static MdocDscPolicy notEnforced() {
        return new MdocDscPolicy(TrustAnchorRegistry.EMPTY);
    }

    /** Whether the trust-anchor rules apply: the registry holds at least one {@code mdoc-iaca} anchor. */
    public boolean enforced() {
        return !registry.entries(TrustAnchorRegistry.MDOC_IACA).isEmpty();
    }

    /**
     * ISO/IEC 18013-5 9.1.2.4: the IssuerAuth's unprotected header carries {@code x5chain} (RFC 9360, label 33) with the
     * document signer certificate, and a verifier builds the path from it to the IACA it trusts. So the key must have a
     * chain, the configuration may not leave the chain out ({@code none}), may not cut it to the DSC alone ({@code leaf})
     * when intermediates stand between the DSC and the IACA, and may not carry the self-signed IACA ({@code full}; HAIP).
     * The signer itself may not be self-signed: {@code without-anchor} keeps a lone self-signed certificate, which no
     * Annex B Document Signer is.
     */
    public static void requireX5chain(JwsHeaderPolicy.ChainInclusion inclusion, CertificateChain chain) {
        if (chain == null || chain.isEmpty()) {
            throw refuse(X5CHAIN_MISSING, "the signing key has no certificate chain; ISO/IEC 18013-5"
                    + " 9.1.2.4 requires the IssuerAuth to carry the document signer certificate in x5chain (label 33)");
        }
        X509Certificate leaf = chain.leafFirst().get(0);
        if (CertificateLinks.selfIssued(leaf)) {
            // a lone self-issued certificate survives without-anchor (nothing above it to drop), so the IssuerAuth would
            // carry a self-signed signer; an ISO/IEC 18013-5 Annex B Document Signer is always issued by an IACA
            throw refuse(DSC_SELF_SIGNED, "the signing certificate " + leaf.getSubjectX500Principal()
                    + " is self-signed; an ISO/IEC 18013-5 Annex B document signer certificate is issued by an IACA,"
                    + " so the key needs a DSC chain (docs/design/06a-x509-pki-and-mdoc.md)");
        }
        switch (inclusion) {
            case NONE -> throw refuse(X5CHAIN_NONE, "x5chain none would leave the IssuerAuth"
                    + " without the document signer certificate, which ISO/IEC 18013-5 9.1.2.4 requires; use without-anchor");
            case LEAF -> {
                int intermediates = chain.withoutAnchor().leafFirst().size() - 1;
                if (intermediates > 0) {
                    throw refuse(X5CHAIN_DROPS_INTERMEDIATES, "x5chain leaf would drop the " + intermediates
                            + " intermediate certificate(s) between the document signer certificate and the IACA, so no"
                            + " verifier could build the path; use without-anchor");
                }
            }
            case FULL -> {
                X509Certificate root = chain.root().orElseThrow();
                if (CertificateLinks.selfIssued(root)) {
                    // HAIP forbids carrying the trust anchor; the verifier must supply the IACA itself (D9, 9.1.2.4)
                    throw refuse(X5CHAIN_CARRIES_ANCHOR, "x5chain FULL would carry the self-signed trust anchor "
                            + root.getSubjectX500Principal() + " in the IssuerAuth; an mDL carries at most the DSC and its"
                            + " intermediates (HAIP, without-anchor)");
                }
            }
            case WITHOUT_ANCHOR -> { }
        }
    }

    /**
     * The checks that need the signing instant, run after {@link #requireX5chain}: the DSC's validity, every link of the
     * chain, and, when {@link #enforced}, the trust anchor, the Annex B profiles and revocation.
     */
    public void check(CertificateChain chain, Instant at) {
        Objects.requireNonNull(at, "at");
        X509Certificate dsc = chain.leaf().orElseThrow(() -> refuse(X5CHAIN_MISSING, "the signing key has no certificate chain"));
        Instant notBefore = dsc.getNotBefore().toInstant();
        Instant notAfter = dsc.getNotAfter().toInstant();
        if (at.isBefore(notBefore)) {
            throw refuse(DSC_NOT_YET_VALID, "the document signer certificate " + dsc.getSubjectX500Principal()
                    + " is valid from " + notBefore + ", after the signing instant " + at);
        }
        if (at.isAfter(notAfter)) {
            throw refuse(DSC_EXPIRED, "the document signer certificate " + dsc.getSubjectX500Principal()
                    + " expired at " + notAfter + ", before the signing instant " + at);
        }
        try {
            CertificateChainPolicy.check(chain, at);
        } catch (SigningException e) {
            throw refuse(CHAIN_LINK_INVALID, e.getMessage(), e);
        }
        if (enforced()) {
            checkTrust(dsc, at);
        }
    }

    private void checkTrust(X509Certificate dsc, Instant at) {
        List<TrustAnchorRegistry.Anchor> anchors = registry.entries(TrustAnchorRegistry.MDOC_IACA);
        TrustAnchorRegistry.Anchor anchor = anchors.stream()
                .filter(candidate -> CertificateLinks.issuedBy(dsc, candidate.certificate()))
                .findFirst()
                .orElseThrow(() -> notIssuedByAnAnchor(dsc, anchors));
        X509Certificate iaca = anchor.certificate();
        if (at.isBefore(iaca.getNotBefore().toInstant())) {
            throw refuse(IACA_NOT_YET_VALID, "the IACA " + anchor.id() + " is valid from "
                    + iaca.getNotBefore().toInstant() + ", after the signing instant " + at);
        }
        if (at.isAfter(iaca.getNotAfter().toInstant())) {
            throw refuse(IACA_EXPIRED, "the IACA " + anchor.id() + " expired at " + iaca.getNotAfter().toInstant()
                    + ", before the signing instant " + at);
        }
        requireProfile(dsc, anchor);
        Optional<X509CRL> crl = registry.crl(anchor.id());
        if (crl.isPresent()) {
            BigInteger serial = dsc.getSerialNumber();
            X509CRLEntry entry = crl.get().getRevokedCertificate(serial);
            if (entry != null) {
                throw refuse(DSC_REVOKED, "the document signer certificate " + dsc.getSubjectX500Principal()
                        + " (serial " + serial.toString(16) + ") is revoked by the CRL of the IACA " + anchor.id()
                        + " since " + entry.getRevocationDate().toInstant());
            }
            requireFresh(crl.get(), anchor, at);
        }
    }

    /**
     * A DSC no configured IACA issued by {@link CertificateLinks#issuedBy}. When one of them signed it all the same (its
     * authority key identifier names another key, or neither the identifiers nor the names link), the Annex B rules it
     * breaks against that IACA are named ({@code DS_AKI_MISMATCH}…), not "no IACA": the operator's fix is the certificate.
     */
    private FormatException notIssuedByAnAnchor(X509Certificate dsc, List<TrustAnchorRegistry.Anchor> anchors) {
        for (TrustAnchorRegistry.Anchor candidate : anchors) {
            if (CertificateLinks.signedBy(dsc, candidate.certificate())) {
                List<AnnexBValidator.Violation> violations = profile(dsc, candidate.certificate());
                if (!violations.isEmpty()) {
                    return profileRefusal(dsc, candidate, violations);
                }
            }
        }
        return refuse(DSC_NO_TRUSTED_IACA, "the document signer certificate " + dsc.getSubjectX500Principal()
                + " (issuer " + dsc.getIssuerX500Principal() + ") was not issued by any configured IACA "
                + anchors.stream().map(TrustAnchorRegistry.Anchor::id).toList()
                + "; mDocs are signed only under certify.pki.trust-anchors.mdoc-iaca (D16)");
    }

    private void requireProfile(X509Certificate dsc, TrustAnchorRegistry.Anchor anchor) {
        List<AnnexBValidator.Violation> violations = profile(dsc, anchor.certificate());
        if (!violations.isEmpty()) {
            throw profileRefusal(dsc, anchor, violations);
        }
    }

    private static FormatException profileRefusal(X509Certificate dsc, TrustAnchorRegistry.Anchor anchor,
                                                  List<AnnexBValidator.Violation> violations) {
        String rules = String.join(", ", AnnexBValidator.ruleIds(violations));
        return refuse(rules, "the document signer certificate " + dsc.getSubjectX500Principal() + " and the IACA "
                + anchor.id() + " break ISO/IEC 18013-5:2021 Annex B: " + violations.stream()
                .map(AnnexBValidator.Violation::toString).collect(Collectors.joining("; ")));
    }

    /**
     * RFC 5280 6.3.3: a verifier that finds the IACA's CRL past its nextUpdate cannot establish the DSC's status and
     * rejects the mDL, so signing past {@link TrustAnchorRegistry#staleCrlGrace()} would only issue credentials that
     * fail verification (decision log 2026-11-13). Within the grace the known revocations above still apply.
     */
    private void requireFresh(X509CRL crl, TrustAnchorRegistry.Anchor anchor, Instant at) {
        if (crl.getNextUpdate() == null) {
            return; // validateCrl refuses a CRL without nextUpdate before it reaches the registry
        }
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        Duration grace = registry.staleCrlGrace();
        if (at.isAfter(nextUpdate.plus(grace))) {
            throw refuse(CRL_STALE, "the CRL of the IACA " + anchor.id() + " passed its nextUpdate " + nextUpdate
                    + ", more than the grace " + grace + " (certify.pki.stale-crl-grace) before the signing instant " + at
                    + "; a verifier rejects an mDL whose IACA CRL is stale (RFC 5280 6.3.3): publish a new CRL");
        }
    }

    private List<AnnexBValidator.Violation> profile(X509Certificate dsc, X509Certificate iaca) {
        String key = fingerprint(dsc) + ":" + fingerprint(iaca);
        List<AnnexBValidator.Violation> cached = profileCache.get(key);
        if (cached != null) {
            return cached;
        }
        List<AnnexBValidator.Violation> violations = new java.util.ArrayList<>(AnnexBValidator.validateIaca(iaca));
        violations.addAll(AnnexBValidator.validateDs(dsc, iaca));
        List<AnnexBValidator.Violation> result = List.copyOf(violations);
        if (profileCache.size() >= PROFILE_CACHE_SIZE) {
            profileCache.clear();
        }
        profileCache.put(key, result);
        return result;
    }

    private static String fingerprint(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw refuse(CHAIN_LINK_INVALID, "cannot encode " + certificate.getSubjectX500Principal(), e);
        }
    }

    private static FormatException refuse(String rule, String message) {
        return new FormatException(MdocConstants.ERROR_CHAIN, rule + ": " + message);
    }

    private static FormatException refuse(String rule, String message, Throwable cause) {
        return new FormatException(MdocConstants.ERROR_CHAIN, rule + ": " + message, cause);
    }
}
