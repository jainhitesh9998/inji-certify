package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds COSE_Sign1 (RFC 9052) envelopes over any {@link Signer}: the mdoc IssuerAuth structure and the
 * body of a CWT. The provider's native {@link Signer#signCose} is tried first.
 */
public final class CoseEnvelope {

    public static final int LABEL_ALG = 1;
    public static final int LABEL_KID = 4;
    public static final int LABEL_TYP = 16;
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
        String kid = policy.kid() == null ? null : policy.kid().kidFor(key);
        CBORObject protectedHeader;
        CBORObject unprotectedHeader;
        if (policy.typ() != null || policy.x5chainInProtected()) {
            // the integrity-protected form of draft-ietf-oauth-status-list-21 section 5.2: 1 alg, 4 kid, 16 typ,
            // 33 x5chain, in RFC 8949 section 4.2.1 order (bytewise lexicographic on the encoded keys); nothing of
            // the chain stays unprotected
            protectedHeader = CBORObject.NewOrderedMap();
            protectedHeader.Add(CBORObject.FromObject(LABEL_ALG), CBORObject.FromObject(key.algorithm().coseId()));
            if (kid != null && policy.kidInProtected()) {
                protectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
            if (policy.typ() != null) {
                protectedHeader.Add(CBORObject.FromObject(LABEL_TYP), CBORObject.FromObject(policy.typ()));
            }
            protectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN), protectedChainValue(policy, key.chain()));
            unprotectedHeader = CBORObject.NewMap();
            if (kid != null && !policy.kidInProtected()) {
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        } else {
            // the unprotected form mdoc IssuerAuth and claim 169 use: byte for byte what 4f1ebcf1 produced (I2)
            protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(CBORObject.FromObject(LABEL_ALG), CBORObject.FromObject(key.algorithm().coseId()));
            if (kid != null && policy.kidInProtected()) {
                protectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
            unprotectedHeader = CBORObject.NewMap();
            if (policy.x5chain() != JwsHeaderPolicy.ChainInclusion.NONE && !key.chain().isEmpty()) {
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN), chainValue(policy, key.chain()));
            }
            if (kid != null && !policy.kidInProtected()) {
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_KID), CBORObject.FromObject(kid.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        }
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

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

    /**
     * The {@code x5chain} a Status List Token carries in its protected header: RFC 9360 section 2's value (one
     * certificate as a {@code bstr}, several as an array, end-entity first, {@code WITHOUT_ANCHOR} leaving a last
     * self-signed certificate out) over a signer chain that a verifier can anchor.
     *
     * <p>Unlike {@link CertificateChain#withoutAnchor()}, which keeps a lone self-signed certificate, this refuses:
     * the protected {@code x5chain} is a Status List Token's only statement of who signed it, so an empty chain or a
     * self-signed certificate in it is an error, never a token without a signer or one carrying its own trust anchor
     * (draft-ietf-oauth-status-list-21 section 5.2; ISO/IEC 18013-5 second edition 12.3.6.3 puts the chain used to
     * verify the signature in the protected header, and the trust point is the verifier's to supply, 12.3.6.2). The
     * message prefix is the {@code StatusListSignerPolicy} rule the caller would otherwise have failed on
     * (docs/design/wp/M-11-status-list-under-iaca.md section 4.7).
     */
    private static CBORObject protectedChainValue(CoseHeaderPolicy policy, CertificateChain chain) {
        if (chain == null || chain.isEmpty()) {
            throw new SigningException("STATUS_SIGNER_NO_CHAIN: the signing key has no certificate, so the protected"
                    + " x5chain of the Status List Token (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC 18013-5"
                    + " second edition 12.3.6.3) would be empty");
        }
        CertificateChain emitted = policy.x5chain() == JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR ? chain.withoutAnchor() : chain;
        for (X509Certificate certificate : emitted.leafFirst()) {
            if (CertificateLinks.selfIssued(certificate)) {
                throw new SigningException("STATUS_SIGNER_SELF_SIGNED: the protected x5chain of the Status List Token would"
                        + " carry the self-signed certificate " + certificate.getSubjectX500Principal() + "; the trust"
                        + " anchor is the verifier's to supply (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC"
                        + " 18013-5 second edition 12.3.6.2 and 12.3.6.3), so the signer needs a certificate issued by"
                        + " the IACA");
            }
        }
        return chainValue(policy, chain);
    }

    /**
     * The {@code x5chain} value of RFC 9360 section 2: one certificate as a {@code bstr}, several as an array of
     * {@code bstr}, end-entity first; {@code WITHOUT_ANCHOR} leaves a self-signed trust anchor out.
     */
    private static CBORObject chainValue(CoseHeaderPolicy policy, CertificateChain chain) {
        List<byte[]> der = (policy.x5chain() == JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR ? chain.withoutAnchor() : chain).toDer();
        if (policy.x5chain() == JwsHeaderPolicy.ChainInclusion.LEAF || der.size() == 1) {
            return CBORObject.FromObject(der.get(0));
        }
        CBORObject array = CBORObject.NewArray();
        der.forEach(d -> array.Add(CBORObject.FromObject(d)));
        return array;
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
