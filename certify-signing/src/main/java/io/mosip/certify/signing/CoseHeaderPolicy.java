package io.mosip.certify.signing;

/**
 * Header rules for a COSE_Sign1: whether the chain travels as {@code x5chain} (label 33), whether a
 * {@code kid} (label 4) is set, and whether the result is tagged (tag 18).
 */
public record CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion x5chain, KidStrategy kid, boolean tagged, boolean kidInProtected) {

    public CoseHeaderPolicy {
        x5chain = x5chain == null ? JwsHeaderPolicy.ChainInclusion.NONE : x5chain;
    }

    /** kid, when set, goes to the unprotected header. */
    public CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion x5chain, KidStrategy kid, boolean tagged) {
        this(x5chain, kid, tagged, false);
    }

    /**
     * ISO/IEC 18013-5 IssuerAuth: the chain in {@code x5chain} (RFC 9360, label 33) without the trust anchor — a verifier
     * supplies the IACA itself, and HAIP forbids carrying it (9.1.2.4, docs/design/20-mdl-issuer.md G9) — no {@code kid},
     * untagged (the mdoc structure carries it).
     */
    public static CoseHeaderPolicy mdocIssuerAuth() {
        return new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, false);
    }

    /**
     * Claim-169 style CWT as keymanager issued it: kid in the protected header, no chain (the verifier resolves the
     * key through the issuer's JWKS), tagged. Including the chain is a wire change reserved for the new surface.
     */
    public static CoseHeaderPolicy cwt() {
        return new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.NONE, KidStrategy.PROVIDER, true, true);
    }
}
