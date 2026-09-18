package io.mosip.certify.signing;

import io.ipfs.multibase.Multibase;

import java.util.Map;

/**
 * Proof encodings of the pre-Data-Integrity Linked Data suites. The caller canonicalizes and hashes the document
 * with the suite's canonicalizer (danubetech {@code Canonicalizer}); this class turns the hash into the suite's
 * {@code proofValue} or {@code jws}.
 */
public final class LdLegacyEnvelope {

    private LdLegacyEnvelope() {}

    /** {@code proofValue} of Ed25519Signature2020 and EcdsaSecp256r1Signature2019: multibase base58btc of the raw signature. */
    public static String proofValueBase58(byte[] canonicalizedHash, SigningKey key, Signer signer) {
        byte[] signature = signer.signRaw(canonicalizedHash, key, key.algorithm());
        return Multibase.encode(Multibase.Base.Base58BTC, signature);
    }

    /**
     * {@code jws} of RsaSignature2018, Ed25519Signature2018, EcdsaSecp256k1Signature2019 and EcdsaKoblitzSignature2016:
     * a detached JWS with the unencoded hash as payload (RFC 7797, {@code b64=false}, {@code crit=["b64"]}), carrying
     * {@code kid} and {@code x5t#S256} as keymanager did.
     */
    public static String detachedJws(byte[] canonicalizedHash, SigningKey key, Signer signer) {
        JwsHeaderPolicy policy = new JwsHeaderPolicy(null, KidStrategy.PROVIDER, JwsHeaderPolicy.ChainInclusion.NONE, true, false, true, Map.of());
        return JwsEnvelope.sign(canonicalizedHash, policy, key, signer);
    }
}
