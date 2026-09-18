package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;

/** The c_nonce store of {@code POST /nonce}: a proof nonce must be one the issuer handed out and still be valid. */
@Component
public class CacheNonceCheck implements ProofValidator.NonceCheck {

    public static final String ERROR_INVALID_NONCE = "invalid_nonce";

    private final VCICacheService cache;
    private final Clock clock;

    @Autowired
    public CacheNonceCheck(VCICacheService cache) {
        this(cache, Clock.systemUTC());
    }

    CacheNonceCheck(VCICacheService cache, Clock clock) {
        this.cache = cache;
        this.clock = clock;
    }

    /** Drops a nonce the credential request has used, so the same proof cannot be replayed (OpenID4VCI 1.0, nonce endpoint). */
    public void consume(String nonce) {
        cache.evictNonceTransaction(nonce);
    }

    @Override
    public void check(String nonce) throws ProofValidationException {
        VCIssuanceTransaction transaction = cache.getNonceTransaction(nonce);
        if (transaction == null) {
            throw new ProofValidationException(ERROR_INVALID_NONCE, "c_nonce is invalid or expired");
        }
        int expireSeconds = transaction.getCNonceExpireSeconds();
        if (expireSeconds <= 0 || transaction.getCNonceIssuedEpoch() + expireSeconds < clock.instant().getEpochSecond()) {
            throw new ProofValidationException(ERROR_INVALID_NONCE, "c_nonce is expired");
        }
    }
}
