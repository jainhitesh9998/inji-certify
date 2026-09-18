package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

/**
 * The draft-13 nonce rules of 0.14.0: the {@code c_nonce} bound to the access token (issued by the last
 * {@code invalid_proof} answer and cached under the token hash) wins; otherwise the token's own {@code c_nonce} claim
 * is valid for {@code c_nonce_expires_in} seconds after {@code iat}; a nonce from the shared nonce endpoint is
 * accepted too, so wallets that already moved to {@code POST /nonce} keep working.
 */
final class D13NonceCheck implements ProofValidator.NonceCheck {

    static final String ERROR_INVALID_NONCE = "invalid_nonce";
    static final String CLAIM_C_NONCE = "c_nonce";
    static final String CLAIM_C_NONCE_EXPIRES_IN = "c_nonce_expires_in";
    static final String CLAIM_IAT = "iat";

    private final Authorization authorization;
    private final VCICacheService cache;
    private final ProofValidator.NonceCheck shared;
    private final Clock clock;

    D13NonceCheck(Authorization authorization, VCICacheService cache, ProofValidator.NonceCheck shared, Clock clock) {
        this.authorization = authorization;
        this.cache = cache;
        this.shared = shared;
        this.clock = clock;
    }

    @Override
    public void check(String nonce) throws ProofValidationException {
        if (nonce == null || nonce.isBlank()) {
            throw new ProofValidationException(ERROR_INVALID_NONCE, "Proof carries no nonce");
        }
        long now = clock.instant().getEpochSecond();
        VCIssuanceTransaction bound = authorization.tokenHash() == null ? null : cache.getVCITransaction(authorization.tokenHash());
        if (bound != null) {
            if (nonce.equals(bound.getCNonce()) && bound.getCNonceExpireSeconds() > 0
                    && bound.getCNonceIssuedEpoch() + bound.getCNonceExpireSeconds() >= now) {
                return;
            }
        } else if (tokenNonceMatches(nonce, now)) {
            return;
        }
        try {
            shared.check(nonce);
        } catch (ProofValidationException e) {
            throw new ProofValidationException(ERROR_INVALID_NONCE, "c_nonce is invalid or expired");
        }
    }

    private boolean tokenNonceMatches(String nonce, long now) {
        Map<String, Object> claims = authorization.claims();
        Object tokenNonce = claims.get(CLAIM_C_NONCE);
        if (tokenNonce == null || !nonce.equals(tokenNonce.toString())) {
            return false;
        }
        long expiresIn = asEpoch(claims.get(CLAIM_C_NONCE_EXPIRES_IN), 0);
        long issued = asEpoch(claims.get(CLAIM_IAT), Long.MIN_VALUE / 2);
        return expiresIn > 0 && issued + expiresIn >= now;
    }

    static long asEpoch(Object value, long fallback) {
        if (value instanceof Instant instant) {
            return instant.getEpochSecond();
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }
}
