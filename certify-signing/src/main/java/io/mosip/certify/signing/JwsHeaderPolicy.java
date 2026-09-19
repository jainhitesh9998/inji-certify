package io.mosip.certify.signing;

import java.util.Map;

/**
 * Header rules for a JWS: which {@code typ}, how the key is identified, whether the certificate chain
 * travels in the header, and whether the payload is base64url-encoded (RFC 7797) or detached.
 */
public record JwsHeaderPolicy(String typ, KidStrategy kid, ChainInclusion x5c, boolean x5tS256,
                              boolean b64, boolean detached, Map<String, Object> extraHeaders) {

    /** {@code WITHOUT_ANCHOR}: every certificate but a self-signed root, as HAIP requires of {@code x5c} and {@code x5chain}. */
    public enum ChainInclusion { FULL, LEAF, WITHOUT_ANCHOR, NONE }

    public JwsHeaderPolicy {
        kid = kid == null ? KidStrategy.PROVIDER : kid;
        x5c = x5c == null ? ChainInclusion.NONE : x5c;
        extraHeaders = extraHeaders == null ? Map.of() : Map.copyOf(extraHeaders);
    }

    /** Compact JWS, base64url payload, provider kid, no chain: a plain JWT. */
    public static JwsHeaderPolicy compact(String typ) {
        return new JwsHeaderPolicy(typ, KidStrategy.PROVIDER, ChainInclusion.NONE, false, true, false, Map.of());
    }

    /** SD-JWT VC issuer JWS as Certify produces it today: {@code typ dc+sd-jwt}, full {@code x5c}, {@code x5t#S256}, provider kid. */
    public static JwsHeaderPolicy sdJwtVc() {
        return new JwsHeaderPolicy("dc+sd-jwt", KidStrategy.PROVIDER, ChainInclusion.FULL, true, true, false, Map.of());
    }

    /** Detached, unencoded-payload JWS ({@code b64:false}, {@code crit:["b64"]}) as legacy LD proofs use. */
    public static JwsHeaderPolicy detachedUnencoded() {
        return new JwsHeaderPolicy(null, KidStrategy.NONE, ChainInclusion.NONE, false, false, true, Map.of());
    }

    public JwsHeaderPolicy withTyp(String type) {
        return new JwsHeaderPolicy(type, kid, x5c, x5tS256, b64, detached, extraHeaders);
    }

    public JwsHeaderPolicy withKid(KidStrategy strategy) {
        return new JwsHeaderPolicy(typ, strategy, x5c, x5tS256, b64, detached, extraHeaders);
    }

    public JwsHeaderPolicy withX5c(ChainInclusion inclusion) {
        return new JwsHeaderPolicy(typ, kid, inclusion, x5tS256, b64, detached, extraHeaders);
    }
}
