package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.util.List;

/**
 * Builds COSE_Sign1 (RFC 9052) envelopes over any {@link Signer}: the mdoc IssuerAuth structure and the
 * body of a CWT. The provider's native {@link Signer#signCose} is tried first.
 */
public final class CoseEnvelope {

    public static final int LABEL_ALG = 1;
    public static final int LABEL_KID = 4;
    public static final int LABEL_X5CHAIN = 33;
    public static final int TAG_COSE_SIGN1 = 18;

    private CoseEnvelope() {}

    public static byte[] sign1(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        return signer.signCose(new Signer.CoseInput(payload, externalAad, policy), key)
                .orElseGet(() -> sign1Locally(payload, externalAad, policy, key, signer));
    }

    public static byte[] sign1(byte[] payload, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        return sign1(payload, new byte[0], policy, key, signer);
    }

    static byte[] sign1Locally(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(CBORObject.FromObject(LABEL_ALG), CBORObject.FromObject(key.algorithm().coseId()));
        String kid = policy.kid() == null ? null : policy.kid().kidFor(key);
        if (kid != null && policy.kidInProtected()) {
            protectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject unprotectedHeader = CBORObject.NewMap();
        CertificateChain chain = key.chain();
        if (policy.x5chain() != JwsHeaderPolicy.ChainInclusion.NONE && !chain.isEmpty()) {
            List<byte[]> der = (policy.x5chain() == JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR ? chain.withoutAnchor() : chain).toDer();
            if (policy.x5chain() == JwsHeaderPolicy.ChainInclusion.LEAF || der.size() == 1) {
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN), CBORObject.FromObject(der.get(0)));
            } else {
                CBORObject array = CBORObject.NewArray();
                der.forEach(d -> array.Add(CBORObject.FromObject(d)));
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN), array);
            }
        }
        if (kid != null && !policy.kidInProtected()) {
            unprotectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }

        byte[] toBeSigned = sigStructure(protectedBytes, externalAad, payload);
        byte[] signature = signer.signRaw(toBeSigned, key, key.algorithm());

        CBORObject sign1 = CBORObject.NewArray()
                .Add(CBORObject.FromObject(protectedBytes))
                .Add(unprotectedHeader)
                .Add(CBORObject.FromObject(payload))
                .Add(CBORObject.FromObject(signature));
        if (policy.tagged()) {
            sign1 = CBORObject.FromObjectAndTag(sign1, TAG_COSE_SIGN1);
        }
        return sign1.EncodeToBytes();
    }

    /** {@code Sig_structure = ["Signature1", protected, external_aad, payload]} (RFC 9052 section 4.4). */
    public static byte[] sigStructure(byte[] protectedBytes, byte[] externalAad, byte[] payload) {
        return CBORObject.NewArray()
                .Add(CBORObject.FromObject("Signature1"))
                .Add(CBORObject.FromObject(protectedBytes))
                .Add(CBORObject.FromObject(externalAad == null ? new byte[0] : externalAad))
                .Add(CBORObject.FromObject(payload))
                .EncodeToBytes();
    }
}
