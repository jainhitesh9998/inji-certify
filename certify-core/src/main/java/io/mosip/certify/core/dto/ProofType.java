package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum ProofType {
    JWT,
    /** OpenID4VCI 1.0 Appendix F.3: a key attestation without a proof of possession (new surface only). */
    ATTESTATION;

    @JsonCreator
    public static ProofType fromValue(String value) {
        return ProofType.valueOf(value.toUpperCase());
    }
}
