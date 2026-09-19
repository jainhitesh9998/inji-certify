package io.mosip.certify.proof;

import com.nimbusds.jose.jwk.JWK;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The OpenID4VCI 1.0 {@code attestation} proof type (Appendix F.3): the proof is a key attestation JWT (Appendix D)
 * without a proof of possession; when the issuer has a nonce endpoint the attestation's {@code nonce} must be the
 * {@code c_nonce}. One credential is issued per attested key (Appendix F: "SHOULD issue a Credential for each
 * cryptographic public key specified in the attested_keys claim"), each bound as the {@code did:jwk} of that key.
 * A configuration opts in by listing {@code attestation} in {@code proof_types_supported}.
 */
@Component
public class KeyAttestationProofValidator implements ProofValidator {

    public static final String PROOF_TYPE = "attestation";
    public static final String POLICY_PROOF_TYPES = "proof_types_supported";
    public static final String ALGORITHMS = "proof_signing_alg_values_supported";
    public static final String KEY_ATTESTATIONS_REQUIRED = "key_attestations_required";
    static final String ERROR_INVALID_NONCE = "invalid_nonce";

    private final KeyAttestationValidator attestations;

    public KeyAttestationProofValidator(KeyAttestationValidator attestations) {
        this.attestations = attestations;
    }

    @Override
    public String proofType() {
        return PROOF_TYPE;
    }

    @Override
    public HolderBinding validate(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException {
        return validateAll(proof, policy, nonce, context).get(0);
    }

    @Override
    public List<HolderBinding> validateAll(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException {
        if (proof == null || proof.value() == null || String.valueOf(proof.value()).isBlank()) {
            throw new ProofValidationException(KeyAttestationValidator.ERROR_INVALID_PROOF, "Empty attestation proof");
        }
        Map<String, Object> type = proofTypeSettings(policy, PROOF_TYPE);
        if (type == null) {
            throw new ProofValidationException(KeyAttestationValidator.ERROR_INVALID_PROOF, "The configuration does not support attestation proofs");
        }
        List<String> algorithms = type.get(ALGORITHMS) instanceof List<?> list ? list.stream().map(String::valueOf).toList() : List.of();
        Map<String, Object> required = requirement(type);
        KeyAttestationValidator.KeyAttestation attestation = attestations.validate(String.valueOf(proof.value()), algorithms, required, false);
        if (policy != null && policy.requireNonce()) {
            if (attestation.nonce() == null) {
                throw new ProofValidationException(ERROR_INVALID_NONCE, "Key attestation carries no nonce");
            }
            (nonce == null ? NonceCheck.NONE : nonce).check(attestation.nonce());
        }
        List<HolderBinding> holders = new ArrayList<>();
        for (JWK key : attestation.attestedKeys()) {
            holders.add(HolderBinding.did(didJwk(key), PROOF_TYPE));
        }
        return holders;
    }

    /** The configuration's {@code proof_types_supported.<type>} object from the policy, or {@code null}. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> proofTypeSettings(ProofPolicy policy, String proofType) {
        if (policy == null || policy.extra() == null || !(policy.extra().get(POLICY_PROOF_TYPES) instanceof Map<?, ?> types)) {
            return null;
        }
        return types.get(proofType) instanceof Map<?, ?> type ? (Map<String, Object>) type : null;
    }

    /** {@code key_attestations_required} of a proof type: an object (possibly empty) when attestations are required, else {@code null}. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> requirement(Map<String, Object> proofType) {
        return proofType != null && proofType.get(KEY_ATTESTATIONS_REQUIRED) instanceof Map<?, ?> required ? (Map<String, Object>) required : null;
    }

    /** The {@code did:jwk} of a public key, encoded as the legacy proof managers encode it so both proof types bind alike. */
    static String didJwk(JWK key) {
        return Constants.DID_JWK_PREFIX + Base64.getUrlEncoder().encodeToString(key.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8));
    }
}
