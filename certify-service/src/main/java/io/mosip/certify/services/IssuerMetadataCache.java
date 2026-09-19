package io.mosip.certify.services;

import io.mosip.certify.core.spi.CredentialRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

/**
 * The issuer-metadata cache ({@link CredentialRegistry#CACHE_NAME}) as the configuration APIs evict it: through the
 * {@link CacheManager} and tolerant of a deployment whose {@code mosip.certify.cache.names} predates the name (a
 * {@code @CacheEvict} on a cache the manager does not know fails the whole request; the registry already reads the
 * cache the same tolerant way).
 */
@Slf4j
@Component
public class IssuerMetadataCache {

    private final CacheManager cacheManager;

    public IssuerMetadataCache(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void evict() {
        Cache cache = cacheManager.getCache(CredentialRegistry.CACHE_NAME);
        if (cache == null) {
            log.debug("Cache '{}' is not configured; nothing to evict", CredentialRegistry.CACHE_NAME);
            return;
        }
        cache.clear();
    }
}
