package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.util.Map;

/** Builds a CWT (RFC 8392): a COSE_Sign1 over a CBOR claims map, optionally wrapped in tag 61. */
public final class CwtEnvelope {

    public static final int TAG_CWT = 61;

    private CwtEnvelope() {}

    /**
     * @param claims integer-keyed CWT claims (1 iss, 2 sub, 3 aud, 4 exp, 5 nbf, 6 iat, 7 cti, or private-use labels such as 169)
     */
    public static byte[] sign(Map<Integer, Object> claims, CoseHeaderPolicy policy, SigningKey key, Signer signer, boolean cwtTag) {
        CBORObject map = CBORObject.NewMap();
        claims.forEach((label, value) -> map.Add(CBORObject.FromObject(label), CBORObject.FromObject(value)));
        byte[] sign1 = CoseEnvelope.sign1(map.EncodeToBytes(), policy, key, signer);
        if (!cwtTag) {
            return sign1;
        }
        return CBORObject.FromObjectAndTag(CBORObject.DecodeFromBytes(sign1), TAG_CWT).EncodeToBytes();
    }
}
