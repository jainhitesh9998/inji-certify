package io.mosip.certify.spi;

import java.util.Objects;

/**
 * The holder key a proof established, in Certify's own terms so no JOSE or JSON-LD library type crosses the SPI.
 *
 * @param kind      how the key is identified
 * @param value     the DID, the public JWK as JSON, or the COSE_Key as base64url, depending on {@code kind}
 * @param kid       the identifier to place in the credential ({@code credentialSubject.id}, {@code cnf.kid}), may equal {@code value}
 * @param proofType the proof type that established the binding ({@code jwt}, {@code cwt}, {@code ldp_vp}, {@code attestation}), or {@code null}
 */
public record HolderBinding(Kind kind, String value, String kid, String proofType) {

    public enum Kind { DID, JWK, COSE_KEY, NONE }

    public static final HolderBinding NONE = new HolderBinding(Kind.NONE, null, null, null);

    public HolderBinding {
        Objects.requireNonNull(kind, "kind");
    }

    public static HolderBinding did(String did, String proofType) {
        return new HolderBinding(Kind.DID, did, did, proofType);
    }

    public static HolderBinding jwk(String jwkJson, String kid, String proofType) {
        return new HolderBinding(Kind.JWK, jwkJson, kid, proofType);
    }

    public boolean isBound() {
        return kind != Kind.NONE;
    }
}
