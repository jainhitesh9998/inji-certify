package io.mosip.certify.signing;

import com.upokecenter.cbor.CBORObject;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds COSE_Sign1 (RFC 9052) envelopes over any {@link Signer}: the mdoc IssuerAuth structure and the
 * body of a CWT. The provider's native {@link Signer#signCose} is tried first (no provider overrides it today, so the
 * envelopes are built here); for the protected Status List Token form the chain checks run before the provider is
 * asked, so a native builder cannot skip them.
 */
public final class CoseEnvelope {

    public static final int LABEL_ALG = 1;
    public static final int LABEL_KID = 4;
    public static final int LABEL_TYP = 16;
    public static final int LABEL_X5CHAIN = 33;
    public static final int TAG_COSE_SIGN1 = 18;

    private CoseEnvelope() {}

    public static byte[] sign1(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        // the refusals of the protected Status List Token form are decided before the provider is asked, so a provider
        // that builds the envelope itself (Signer.signCose) cannot skip them; no CBOR is built here, so every other
        // policy is byte-identical to 4f1ebcf1 (I2)
        List<byte[]> protectedChain = protectedChain(policy, key);
        return signer.signCose(new Signer.CoseInput(payload, externalAad, policy), key)
                .orElseGet(() -> sign1Locally(payload, externalAad, policy, key, signer, protectedChain));
    }

    public static byte[] sign1(byte[] payload, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        return sign1(payload, new byte[0], policy, key, signer);
    }

    static byte[] sign1Locally(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy, SigningKey key, Signer signer) {
        return sign1Locally(payload, externalAad, policy, key, signer, protectedChain(policy, key));
    }

    private static byte[] sign1Locally(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy, SigningKey key,
                                       Signer signer, List<byte[]> protectedChain) {
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
            protectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN), chainValue(protectedChain, policy.x5chain()));
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
                unprotectedHeader.Add(CBORObject.FromObject(LABEL_X5CHAIN),
                        chainValue(new CertificateChain(selectedCertificates(policy, key.chain())).toDer(), policy.x5chain()));
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

    /** Whether the policy is the integrity-protected Status List Token form (protected {@code typ} and/or chain). */
    private static boolean protectedForm(CoseHeaderPolicy policy) {
        return policy.typ() != null || policy.x5chainInProtected();
    }

    /**
     * The certificates a policy emits, in order, and nothing else: {@code LEAF} the end entity alone (an intermediate or
     * an anchor the provider holds but the policy does not emit is never inspected), {@code WITHOUT_ANCHOR} without a
     * last self-signed certificate, {@code FULL} the whole chain. Selected once, so the list that is checked is exactly
     * the list that is encoded.
     */
    private static List<X509Certificate> selectedCertificates(CoseHeaderPolicy policy, CertificateChain chain) {
        if (policy.x5chain() == JwsHeaderPolicy.ChainInclusion.NONE || chain == null || chain.isEmpty()) {
            return List.of();
        }
        return switch (policy.x5chain()) {
            case LEAF -> List.of(chain.leafFirst().get(0));
            case WITHOUT_ANCHOR -> chain.withoutAnchor().leafFirst();
            default -> chain.leafFirst();
        };
    }

    /**
     * The protected {@code x5chain} of a Status List Token, or {@code null} for every other policy: RFC 9360 section 2's
     * DER list over the certificates the policy emits, refused rather than emptied or self-anchored when there is
     * nothing a verifier can anchor. Unlike {@link CertificateChain#withoutAnchor()}, which keeps a lone self-signed
     * certificate, this refuses: the protected {@code x5chain} is a Status List Token's only statement of who signed it,
     * so a missing chain or a self-signed certificate in it is an error (draft-ietf-oauth-status-list-21 section 5.2;
     * ISO/IEC 18013-5 second edition 12.3.6.3 puts the chain used to verify the signature in the protected header, and
     * 12.3.6.2 makes the trust point the verifier's to supply). The message prefixes are the
     * {@code StatusListSignerPolicy} rules of docs/design/wp/M-11-status-list-under-iaca.md section 4.7:
     * {@code STATUS_SIGNER_SELF_SIGNED} when the leaf is self-signed, {@code STATUS_SIGNER_CARRIES_ANCHOR} when a
     * self-signed certificate sits further up the emitted chain.
     *
     * <p>Self-signed here means subject and issuer names equal, the same test {@code withoutAnchor()} uses, so a
     * self-issued key-rollover intermediate counts as self-signed — consistent with the rest of the signing library.
     */
    private static List<byte[]> protectedChain(CoseHeaderPolicy policy, SigningKey key) {
        if (!protectedForm(policy)) {
            return null;
        }
        CertificateChain chain = key.chain();
        if (chain == null || chain.isEmpty()) {
            throw new SigningException("STATUS_SIGNER_NO_CHAIN: the signing key has no certificate, so the protected"
                    + " x5chain of the Status List Token (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC 18013-5"
                    + " second edition 12.3.6.3) would be empty");
        }
        List<X509Certificate> emitted = selectedCertificates(policy, chain);
        if (emitted.isEmpty()) {
            throw new SigningException("STATUS_SIGNER_NO_CHAIN: the policy emits no certificate, so the protected x5chain"
                    + " of the Status List Token (draft-ietf-oauth-status-list-21 section 5.2) would be empty");
        }
        X509Certificate leaf = emitted.get(0);
        if (CertificateLinks.selfIssued(leaf)) {
            throw new SigningException("STATUS_SIGNER_SELF_SIGNED: the signing certificate "
                    + leaf.getSubjectX500Principal() + " is self-signed; the trust anchor is the verifier's to supply"
                    + " (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC 18013-5 second edition 12.3.6.2 and"
                    + " 12.3.6.3), so the signer needs a certificate issued by the IACA");
        }
        for (int index = 1; index < emitted.size(); index++) {
            X509Certificate certificate = emitted.get(index);
            if (CertificateLinks.selfIssued(certificate)) {
                throw new SigningException("STATUS_SIGNER_CARRIES_ANCHOR: the protected x5chain of the Status List Token"
                        + " would carry the self-signed certificate " + certificate.getSubjectX500Principal() + " at"
                        + " position " + index + "; the trust anchor is the verifier's to supply"
                        + " (draft-ietf-oauth-status-list-21 section 5.2, ISO/IEC 18013-5 second edition 12.3.6.2)");
            }
        }
        return new CertificateChain(emitted).toDer();
    }

    /** The {@code x5chain} value of RFC 9360 section 2 over a selection already made: one {@code bstr}, else an array. */
    private static CBORObject chainValue(List<byte[]> der, JwsHeaderPolicy.ChainInclusion inclusion) {
        if (inclusion == JwsHeaderPolicy.ChainInclusion.LEAF || der.size() == 1) {
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
