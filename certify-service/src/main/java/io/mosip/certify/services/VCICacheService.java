package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.NonceErrorConstants;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.PreAuthTransaction;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachePut;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class VCICacheService {

    @Autowired
    private CacheManager cacheManager;

    @Value("${spring.cache.type:simple}")
    private String cacheType;

    private static final String VCISSUANCE_CACHE = "vcissuance";
    private static final String PRE_AUTH_TXN_CACHE = "preAuthCacheTxn";
    private static final String NONCE_CACHE = "nonce";
    /**
     * Pushed authorization requests (RFC 9126) live in a cache of their own, never in {@code preAuthCodeCache}: the PAR
     * endpoint is unauthenticated and writes one entry per request, and the pre-authorized codes an offer is redeemed
     * with live in {@code preAuthCodeCache}. Sharing it let a PAR flood evict every live offer (F-21 review round 1);
     * this cache is bounded and expired by its own {@code mosip.certify.cache.size} / {@code cache.expire-in-seconds}
     * entries, which must cover {@code certify.as.par.expires-in} ({@code io.mosip.certify.as.AsCacheRequirements} refuses
     * to start otherwise).
     */
    public static final String PAR_REQUEST_CACHE = "parRequestCache";
    private static final String PAR_PREFIX = "par:";
    /**
     * The client-attestation proof-of-possession replay cache: one entry per accepted proof, bounded and expired by its
     * own entries. It is not in {@code preAuthCodeCache} either, for the reason PAR is not: an authenticated caller
     * writing it must never be able to evict an offer (F-21 review round 1). Required at startup once an attester is
     * configured ({@code io.mosip.certify.as.AsCacheRequirements}).
     */
    public static final String CLIENT_ATTESTATION_JTI_CACHE = "clientAttestationJtiCache";

    @PostConstruct
    public void validateCacheConfiguration() {
        log.info("Cache type configured: {}", cacheType);

        if ("simple".equalsIgnoreCase(cacheType)) {
            log.warn("CRITICAL WARNING: Simple cache configured for production deployment " +
                    "'simple' cache uses in-memory storage isolated to each pod, " +
                    "Multi-pod deployments will experience cache inconsistencies and MAY BREAK FUNCTIONALLY, " +
                    "Current configuration: spring.cache.type=simple (in-memory, non-distributed), " +
                    "Switch to Redis cache for multi-pod deployments, Set spring.cache.type=redis in your configuration ");
        } else if ("redis".equalsIgnoreCase(cacheType)) {
            log.info("Redis cache is configured - suitable for multi-pod deployment");
        } else {
            log.warn("Unknown cache type configured: {}. Please verify configuration.", cacheType);
        }
    }


    @CachePut(value = VCISSUANCE_CACHE, key = "#accessTokenHash")
    public VCIssuanceTransaction setVCITransaction(String accessTokenHash, VCIssuanceTransaction vcIssuanceTransaction) {
        return vcIssuanceTransaction;
    }

    public VCIssuanceTransaction getVCITransaction(String accessTokenHash) {
        Cache cache = cacheManager.getCache(VCISSUANCE_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", VCISSUANCE_CACHE);
            return null;
        }
        return cache.get(accessTokenHash, VCIssuanceTransaction.class);
    }

    @CachePut(value = PRE_AUTH_TXN_CACHE, key = "#accessTokenHash")
    public PreAuthTransaction setPreAuthTransaction(String accessTokenHash, PreAuthTransaction preAuthTransaction) {
        return preAuthTransaction;
    }

    public PreAuthTransaction getPreAuthTransaction(String accessTokenHash) {
        Cache cache = cacheManager.getCache(PRE_AUTH_TXN_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", PRE_AUTH_TXN_CACHE);
            return null;
        }
        return cache.get(accessTokenHash, PreAuthTransaction.class);
    }

    @CachePut(value = NONCE_CACHE, key = "'txn:' + #cNonce")
    public VCIssuanceTransaction setNonceTransaction(String cNonce, VCIssuanceTransaction transaction) {
        return transaction;
    }

    public VCIssuanceTransaction getNonceTransaction(String cNonce) {
        Cache cache = cacheManager.getCache(NONCE_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", NONCE_CACHE);
            throw new CertifyException(NonceErrorConstants.CACHE_NOT_AVAILABLE,
                    "Nonce cache is not configured. Please verify cache configuration.");
        }
        return cache.get("txn:" + cNonce, VCIssuanceTransaction.class);
    }

    /** Drops a nonce-endpoint nonce once the credential request it authorised has been answered. */
    public void evictNonceTransaction(String cNonce) {
        Cache cache = cacheManager.getCache(NONCE_CACHE);
        if (cache != null) {
            cache.evict("txn:" + cNonce);
        }
    }

    public void setPreAuthCodeData(String code, PreAuthCodeData data) {
        String key = Constants.PRE_AUTH_CODE_PREFIX + code;
        cacheManager.getCache("preAuthCodeCache").put(key, data);
    }

    /** A pushed authorization request (RFC 9126), in the bounded {@link #PAR_REQUEST_CACHE}, never in the offer cache. */
    public void setPushedAuthorizationRequest(String id, io.mosip.certify.as.PushedAuthorizationRequest request) {
        cacheManager.getCache(PAR_REQUEST_CACHE).put(PAR_PREFIX + id, request);
    }

    public io.mosip.certify.as.PushedAuthorizationRequest getPushedAuthorizationRequest(String id) {
        Cache cache = cacheManager.getCache(PAR_REQUEST_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", PAR_REQUEST_CACHE);
            return null;
        }
        Cache.ValueWrapper wrapper = cache.get(PAR_PREFIX + id);
        return wrapper != null ? (io.mosip.certify.as.PushedAuthorizationRequest) wrapper.get() : null;
    }

    /** Records a client attestation PoP jti; false when it was seen before (replay). The entry lives as long as the cache does. */
    public boolean claimClientAttestationJti(String jti, long windowSeconds) {
        Cache c = cacheManager.getCache(CLIENT_ATTESTATION_JTI_CACHE);
        if (c == null) {
            log.error("Cache {} not available: a client attestation proof cannot be checked for replay. Add it to "
                    + "mosip.certify.cache.names.", CLIENT_ATTESTATION_JTI_CACHE);
            return false;
        }
        return c.putIfAbsent("capop:" + jti, Long.valueOf(windowSeconds)) == null;
    }

    public void evictPushedAuthorizationRequest(String id) {
        Cache cache = cacheManager.getCache(PAR_REQUEST_CACHE);
        if (cache != null) {
            cache.evict(PAR_PREFIX + id);
        }
    }

    public PreAuthCodeData getPreAuthCodeData(String code) {
        String key = Constants.PRE_AUTH_CODE_PREFIX + code;
        Cache.ValueWrapper wrapper = cacheManager.getCache("preAuthCodeCache").get(key);
        return wrapper != null ? (PreAuthCodeData) wrapper.get() : null;
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        String key = Constants.CREDENTIAL_OFFER_PREFIX + offerId;
        Cache cache = cacheManager.getCache("credentialOfferCache");

        if (cache == null) {
            throw new IllegalStateException("credentialOfferCache not available");
        }

        Cache.ValueWrapper wrapper = cache.get(key);
        return wrapper != null ? (CredentialOfferResponse) wrapper.get() : null;
    }

    public void setCredentialOffer(String offerId, CredentialOfferResponse offer) {
        String key = Constants.CREDENTIAL_OFFER_PREFIX + offerId;
        Cache cache = cacheManager.getCache("credentialOfferCache");

        if (cache == null) {
            throw new IllegalStateException("credentialOfferCache not available");
        }

        // For Redis, use RedisCache.put with Duration
        if (cache instanceof RedisCache) {
            ((RedisCache) cache).put(key, offer);
        } else {
            // For simple cache, log warning and use basic put
            log.warn("TTL not supported for cache type: {}. Entry may not expire.", cacheType);
            cache.put(key, offer);
        }
    }

    /**
     * Get cached authorization server metadata
     */
    public boolean isPreAuthCodeUsed(String code) {
        String key = "used:" + code;
        Cache cache = cacheManager.getCache("preAuthCodeCache");
        if (cache == null) {
            log.error("Cache preAuthCodeCache not available");
            return false;
        }
        Cache.ValueWrapper wrapper = cache.get(key);
        return wrapper != null && Boolean.TRUE.equals(wrapper.get());
    }

    public boolean claimPreAuthCode(String preAuthCode) {
        synchronized (this) {
            PreAuthCodeData codeData = getPreAuthCodeData(preAuthCode);
            if (codeData == null || isPreAuthCodeUsed(preAuthCode)) {
                return false;
            }
            markPreAuthCodeAsUsed(preAuthCode);
            return true;
        }
    }

    /**
     * Mark a pre-authorized code as used to prevent reuse
     */
    public void markPreAuthCodeAsUsed(String code) {
        String key = "used:" + code;
        Cache cache = cacheManager.getCache("preAuthCodeCache");
        if (cache == null) {
            log.error("Cache preAuthCodeCache not available for marking code as used");
            return;
        }
        // Store in cache with same TTL as pre-auth code
        cache.put(key, true);

        // Also remove the pre-auth code data
        String codeKey = Constants.PRE_AUTH_CODE_PREFIX + code;
        cache.evict(codeKey);

        log.info("Pre-authorized code marked as used");
    }


}