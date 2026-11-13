package io.mosip.certify.signing;

import java.util.regex.Pattern;

/**
 * Header rules for a COSE_Sign1: whether the chain travels as {@code x5chain} (label 33), whether a
 * {@code kid} (label 4) is set, whether the result is tagged (tag 18), and — for the COSE profile of a
 * Status List Token — the {@code typ} (label 16) and whether the chain is integrity protected.
 *
 * <p>A {@code typ} is only meaningful together with a protected chain: draft-ietf-oauth-status-list-21 section 5.2
 * makes the protected {@code typ} and the protected {@code x5chain} one profile, and a token that names its type but
 * leaves the signer chain unprotected would be identified as a Status List Token while failing the header rules the
 * verifier applies to it (ISO/IEC 18013-5 second edition 12.3.6.3 requires the chain in the protected header).
 * {@code typ != null} with {@code x5chainInProtected == false} is therefore refused rather than silently encoded.
 */
public record CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion x5chain, KidStrategy kid, boolean tagged,
                               boolean kidInProtected, String typ, boolean x5chainInProtected) {

    /**
     * RFC 9596 section 2: {@code typ} is a media type, {@code type/subtype}, each a non-empty run of ASCII token
     * characters (RFC 6838 section 4.2, without the {@code *} wildcard). The CoAP Content-Format integer is
     * unassigned for {@code application/statuslist+cwt} (TSL section 14.8), so the text string is the only form usable.
     */
    private static final Pattern MEDIA_TYPE = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$");

    public CoseHeaderPolicy {
        x5chain = x5chain == null ? JwsHeaderPolicy.ChainInclusion.NONE : x5chain;
        if (x5chainInProtected && x5chain == JwsHeaderPolicy.ChainInclusion.NONE) {
            throw new IllegalArgumentException("x5chainInProtected needs x5chain to be included, not NONE");
        }
        if (typ != null && !x5chainInProtected) {
            throw new IllegalArgumentException("typ " + typ + " needs the chain in the protected header: the COSE profile of"
                    + " a Status List Token pairs the protected typ with the protected x5chain"
                    + " (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC 18013-5 second edition 12.3.6.3)");
        }
        if (typ != null && !MEDIA_TYPE.matcher(typ).matches()) {
            throw new IllegalArgumentException("typ is not a media type (RFC 9596 section 2): " + typ);
        }
    }

    /** kid, when set, goes to the unprotected header; no {@code typ}, chain unprotected. */
    public CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion x5chain, KidStrategy kid, boolean tagged) {
        this(x5chain, kid, tagged, false, null, false);
    }

    /** kid, when set, goes wherever {@code kidInProtected} says; no {@code typ}, chain unprotected. */
    public CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion x5chain, KidStrategy kid, boolean tagged, boolean kidInProtected) {
        this(x5chain, kid, tagged, kidInProtected, null, false);
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

    /**
     * The COSE profile of a Status List Token for {@code mso_mdoc} (draft-ietf-oauth-status-list-21 section 5.2, as
     * ISO/IEC 18013-5 second edition 12.3.6.3 requires of the MSO revocation list): a tagged COSE_Sign1 (tag 18, never
     * the CWT tag 61), protected header {@code {1: alg, 16: "application/statuslist+cwt", 33: x5chain}}, unprotected
     * header empty. TSL section 5.2 makes the protected {@code typ} REQUIRED and section 11.3 identifies the signer
     * through the same {@code x5chain} the Referenced Token uses, so no {@code kid} is set and the chain — the signer
     * chain without the IACA (HAIP forbids carrying the anchor, and ISO/IEC 18013-5 12.3.6.3 puts the chain used to
     * verify the signature in the protected header) — travels integrity protected.
     *
     * <p>This policy is refused at signing time ({@link SigningException}) when the key has no certificate or when the
     * chain it would carry is a self-signed certificate, rather than emitting a token no verifier can anchor: a Status
     * List Token's {@code x5chain} is the only statement of who signed it.
     */
    public static CoseHeaderPolicy statusListCwt() {
        return new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, true, false,
                "application/statuslist+cwt", true);
    }
}
