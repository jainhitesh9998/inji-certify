package io.mosip.certify.signing;

import java.util.Optional;

/**
 * Produces signatures. {@link #signRaw} is mandatory and returns the signature in JOSE/COSE wire form
 * ({@code R||S} for ECDSA, PKCS#1 v1.5 or PSS bytes for RSA, the 64-byte signature for Ed25519), never DER.
 * A provider that builds whole envelopes natively (keymanager does) may override {@link #signJws} and
 * {@link #signCose}; the envelope builders try those first and fall back to {@link #signRaw}.
 */
public interface Signer {

    byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm);

    /** A complete compact or detached JWS built by the provider, if it can; empty means "use signRaw". */
    default Optional<String> signJws(JwsInput input, SigningKey key) {
        return Optional.empty();
    }

    /** A complete COSE_Sign1 built by the provider, if it can; empty means "use signRaw". */
    default Optional<byte[]> signCose(CoseInput input, SigningKey key) {
        return Optional.empty();
    }

    /** Payload and header policy handed to a provider that signs JWS natively. */
    record JwsInput(byte[] payload, JwsHeaderPolicy policy) {}

    /** Payload, external AAD and header policy handed to a provider that signs COSE natively. */
    record CoseInput(byte[] payload, byte[] externalAad, CoseHeaderPolicy policy) {}
}
