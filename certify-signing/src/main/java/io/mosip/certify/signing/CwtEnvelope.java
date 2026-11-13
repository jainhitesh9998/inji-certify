package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.util.LinkedHashMap;
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

    /**
     * A CWT whose claims map is encoded in the caller's iteration order: draft-ietf-oauth-status-list-21 section 5.2
     * requires the Status List Token to be a CWT, ISO/IEC 18013-5 second edition 12.3.6.3 forbids the CWT tag 61 for the
     * MSO revocation list, and RFC 8949 section 4.2.1 puts the claim keys in a defined order ({@code 2, 4, 6, 65533,
     * 65534} for a status list). Tags are the policy's only: {@link CoseHeaderPolicy#statusListCwt()} tags the
     * COSE_Sign1 with 18 and this method never wraps the result in tag 61.
     *
     * @param claims integer-keyed claims already encoded, added in iteration order
     */
    public static byte[] signOrdered(LinkedHashMap<Integer, CBORObject> claims, CoseHeaderPolicy policy, SigningKey key,
                                     Signer signer) {
        CBORObject map = CBORObject.NewOrderedMap();
        claims.forEach((label, value) -> map.Add(CBORObject.FromObject(label), value));
        return CoseEnvelope.sign1(map.EncodeToBytes(), policy, key, signer);
    }
}
