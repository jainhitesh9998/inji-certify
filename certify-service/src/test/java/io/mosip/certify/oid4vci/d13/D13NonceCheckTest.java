package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class D13NonceCheckTest {

    static final Instant NOW = Instant.parse("2026-09-19T10:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final ProofValidator.NonceCheck SHARED_REJECTS = nonce -> { throw new ProofValidationException("invalid_nonce", "unknown"); };

    static Authorization token(Map<String, Object> claims) {
        return new Authorization("bearer", claims, "hash");
    }

    static VCIssuanceTransaction transaction(String nonce, long issuedEpoch, int expireSeconds) {
        VCIssuanceTransaction t = new VCIssuanceTransaction();
        t.setCNonce(nonce);
        t.setCNonceIssuedEpoch(issuedEpoch);
        t.setCNonceExpireSeconds(expireSeconds);
        return t;
    }

    @Test
    void tokenCarriedNonceIsValidUntilIatPlusExpiry() {
        VCICacheService cache = mock(VCICacheService.class);
        Authorization fresh = token(Map.of("c_nonce", "n1", "c_nonce_expires_in", 300, "iat", NOW.getEpochSecond() - 10));
        assertDoesNotThrow(() -> new D13NonceCheck(fresh, cache, SHARED_REJECTS, CLOCK).check("n1"));
        Authorization expired = token(Map.of("c_nonce", "n1", "c_nonce_expires_in", 300, "iat", NOW.getEpochSecond() - 301));
        assertEquals("invalid_nonce", assertThrows(ProofValidationException.class, () -> new D13NonceCheck(expired, cache, SHARED_REJECTS, CLOCK).check("n1")).getErrorCode());
        Authorization instantIat = token(Map.of("c_nonce", "n1", "c_nonce_expires_in", 300L, "iat", NOW.minusSeconds(5)));
        assertDoesNotThrow(() -> new D13NonceCheck(instantIat, cache, SHARED_REJECTS, CLOCK).check("n1"));
        assertThrows(ProofValidationException.class, () -> new D13NonceCheck(fresh, cache, SHARED_REJECTS, CLOCK).check("other"));
    }

    @Test
    void tokenBoundNonceFromTheLastErrorReplacesTheTokenClaim() {
        VCICacheService cache = mock(VCICacheService.class);
        when(cache.getVCITransaction("hash")).thenReturn(transaction("bound", NOW.getEpochSecond() - 1, 300));
        Authorization auth = token(Map.of("c_nonce", "n1", "c_nonce_expires_in", 300, "iat", NOW.getEpochSecond()));
        D13NonceCheck check = new D13NonceCheck(auth, cache, SHARED_REJECTS, CLOCK);
        assertDoesNotThrow(() -> check.check("bound"));
        assertThrows(ProofValidationException.class, () -> check.check("n1"), "the token claim no longer counts once a nonce is bound");
        when(cache.getVCITransaction("hash")).thenReturn(transaction("bound", NOW.getEpochSecond() - 400, 300));
        assertThrows(ProofValidationException.class, () -> check.check("bound"), "expired bound nonce");
    }

    @Test
    void sharedNonceStoreIsTheFallback() {
        VCICacheService cache = mock(VCICacheService.class);
        ProofValidator.NonceCheck shared = nonce -> { if (!"from-endpoint".equals(nonce)) throw new ProofValidationException("invalid_nonce", "x"); };
        D13NonceCheck check = new D13NonceCheck(token(Map.of()), cache, shared, CLOCK);
        assertDoesNotThrow(() -> check.check("from-endpoint"));
        ProofValidationException e = assertThrows(ProofValidationException.class, () -> check.check("nope"));
        assertEquals("invalid_nonce", e.getErrorCode());
        assertEquals("c_nonce is invalid or expired", e.getMessage());
        assertThrows(ProofValidationException.class, () -> check.check(" "));
    }
}
