package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.util.Arrays;
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
     * 65534} for a status list).
     *
     * <p>RFC 8949 section 4.2.1 orders map entries by the bytewise lexicographic order of their encoded keys — not
     * numerically, and not by the length-first legacy canonical form of section 4.2.3 (both happen to agree for the
     * integer keys here). The claims are checked against that order rather than re-sorted, because the caller owns the
     * key set: an out-of-order map is a caller defect, not something to hide. Tags are the policy's only:
     * {@link CoseHeaderPolicy#statusListCwt()} tags the COSE_Sign1 with 18, a policy that names a {@code typ} must be
     * tagged (a Status List Token is never untagged, TSL section 5.2), and this method never wraps the result in tag 61.
     *
     * @param claims integer-keyed claims already encoded, added in RFC 8949 section 4.2.1 order
     * @throws IllegalArgumentException when a claim key breaks that order, or when a policy that names a {@code typ} is
     *                                  untagged
     */
    public static byte[] signOrdered(LinkedHashMap<Integer, CBORObject> claims, CoseHeaderPolicy policy, SigningKey key,
                                     Signer signer) {
        if (policy.typ() != null && !policy.tagged()) {
            throw new IllegalArgumentException("a Status List Token is COSE_Sign1_Tagged (18) and never untagged"
                    + " (draft-ietf-oauth-status-list-21 section 5.2): policy typ " + policy.typ() + " is untagged");
        }
        CBORObject map = CBORObject.NewOrderedMap();
        byte[] previousKey = null;
        Integer previousLabel = null;
        for (Map.Entry<Integer, CBORObject> claim : claims.entrySet()) {
            byte[] encodedKey = CBORObject.FromObject(claim.getKey()).EncodeToBytes();
            if (previousKey != null && Arrays.compareUnsigned(previousKey, encodedKey) >= 0) {
                throw new IllegalArgumentException("CWT claim " + claim.getKey() + " cannot follow " + previousLabel
                        + ": claims are added in RFC 8949 section 4.2.1 order, the bytewise lexicographic order of the"
                        + " encoded keys");
            }
            map.Add(CBORObject.FromObject(claim.getKey()), claim.getValue());
            previousKey = encodedKey;
            previousLabel = claim.getKey();
        }
        return CoseEnvelope.sign1(map.EncodeToBytes(), policy, key, signer);
    }
}
