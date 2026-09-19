package io.mosip.certify.spi;

import java.util.List;
import java.util.Map;

/** Validates one proof type ({@code jwt}, {@code cwt}, {@code ldp_vp}, {@code attestation}) into a {@link HolderBinding}. */
public interface ProofValidator {

    String proofType();

    HolderBinding validate(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException;

    /**
     * Every holder one proof binds: one for a {@code jwt} proof, one per attested key for an {@code attestation} proof
     * or a {@code jwt} proof carrying a key attestation (OpenID4VCI 1.0 Appendix F). The default is the single binding.
     */
    default List<HolderBinding> validateAll(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException {
        return List.of(validate(proof, policy, nonce, context));
    }

    /**
     * One proof as received: a compact string for {@code jwt} and {@code cwt}, a JSON object for {@code ldp_vp}.
     */
    record ProofInput(String type, Object value) {}

    /**
     * What the configuration and the adapter require of the proof.
     *
     * @param allowedAlgorithms  JOSE/COSE algorithm names the configuration advertises for this proof type
     * @param audience           the credential issuer identifier the proof must name
     * @param requireNonce       whether a nonce claim is mandatory (nonce endpoint advertised, or c_nonce issued)
     * @param clientId           expected {@code iss} when the wallet authenticated as a client, or {@code null}
     * @param extra              adapter-specific settings (key attestation requirements, trusted issuers)
     */
    record ProofPolicy(List<String> allowedAlgorithms, String audience, boolean requireNonce, String clientId, Map<String, Object> extra) {}

    /** Checks and consumes the nonce a proof carries; the adapter decides where nonces live. */
    @FunctionalInterface
    interface NonceCheck {
        void check(String nonce) throws ProofValidationException;

        NonceCheck NONE = nonce -> {};
    }
}
