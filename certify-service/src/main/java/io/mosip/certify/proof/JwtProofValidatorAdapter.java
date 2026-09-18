package io.mosip.certify.proof;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * The SPI {@link ProofValidator} for OpenID4VCI {@code jwt} proofs, over today's {@link JwtProofValidator} so both
 * surfaces apply the same checks (typ, allowed algorithms, one key in the header, audience, iat, optional exp and
 * iss). The nonce is checked by the adapter's {@link NonceCheck} first; the legacy validator then compares the same
 * value. The holder is returned as the {@code did:jwk}/{@code did:key} the legacy code derives (P1-09).
 */
@Component
public class JwtProofValidatorAdapter implements ProofValidator {

    public static final String PROOF_TYPE = "jwt";
    public static final String ERROR_INVALID_PROOF = "invalid_proof";
    public static final String ERROR_INVALID_NONCE = "invalid_nonce";
    static final String HEADER_TYP = "openid4vci-proof+jwt";

    private final JwtProofValidator legacy;

    @Autowired
    public JwtProofValidatorAdapter(JwtProofValidator legacy) {
        this.legacy = legacy;
    }

    @Override
    public String proofType() {
        return PROOF_TYPE;
    }

    @Override
    public HolderBinding validate(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException {
        if (proof == null || proof.value() == null || String.valueOf(proof.value()).isBlank()) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Empty jwt proof");
        }
        String jwt = String.valueOf(proof.value());
        String nonceClaim;
        List<String> algorithms = policy == null || policy.allowedAlgorithms() == null ? List.of() : policy.allowedAlgorithms();
        try {
            SignedJWT parsed = (SignedJWT) JWTParser.parse(jwt);
            // the legacy validator reports header violations as a plain false; the new surface names them
            if (parsed.getHeader().getType() == null || !HEADER_TYP.equals(parsed.getHeader().getType().getType())) {
                throw new ProofValidationException(ErrorConstants.PROOF_HEADER_INVALID_TYP, "Proof typ must be " + HEADER_TYP);
            }
            if (parsed.getHeader().getAlgorithm() == null || !algorithms.contains(parsed.getHeader().getAlgorithm().getName())) {
                throw new ProofValidationException(ErrorConstants.PROOF_HEADER_INVALID_ALG, "Proof alg not allowed: " + parsed.getHeader().getAlgorithm());
            }
            Object claim = parsed.getJWTClaimsSet().getClaim("nonce");
            nonceClaim = claim == null ? null : claim.toString();
        } catch (ParseException | ClassCastException e) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Proof is not a signed JWT: " + e.getMessage());
        }
        if (policy != null && policy.requireNonce() && nonceClaim == null) {
            throw new ProofValidationException(ERROR_INVALID_NONCE, "Proof carries no nonce");
        }
        if (nonceClaim != null) {
            (nonce == null ? NonceCheck.NONE : nonce).check(nonceClaim);
        }
        Map<String, Object> configuration = Map.of("jwt", Map.of("proof_signing_alg_values_supported", algorithms));
        boolean valid;
        try {
            valid = legacy.validate(policy == null ? null : policy.clientId(), nonceClaim, jwt, configuration, policy == null ? null : policy.audience());
        } catch (InvalidRequestException e) {
            throw new ProofValidationException(e.getErrorCode(), "Proof rejected: " + e.getErrorCode());
        }
        if (!valid) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Proof signature or claims did not verify");
        }
        try {
            return HolderBinding.did(legacy.getKeyMaterial(jwt), PROOF_TYPE);
        } catch (InvalidRequestException e) {
            throw new ProofValidationException(ErrorConstants.PROOF_HEADER_INVALID_KEY, "Holder key could not be derived from the proof");
        }
    }
}
