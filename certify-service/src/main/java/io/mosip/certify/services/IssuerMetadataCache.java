package io.mosip.certify.services;

import io.mosip.certify.core.spi.CredentialRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The issuer-metadata cache ({@link CredentialRegistry#CACHE_NAME}) as the configuration APIs evict it: through the
 * {@link CacheManager} and tolerant of a deployment whose {@code mosip.certify.cache.names} predates the name (a
 * {@code @CacheEvict} on a cache the manager does not know fails the whole request; the registry already reads the
 * cache the same tolerant way).
 *
 * <p>The cache holds every entry built from the configuration rows: the compatibility issuer metadata and the default
 * tenant's {@code /oid4vci} claim orders. A write clears it at once and, inside a transaction, again once the transaction
 * has committed: a request that read the rows between the first clear and the commit would otherwise have cached what
 * the transaction was replacing (F-10 review round 2).
 */
@Slf4j
@Component
public class IssuerMetadataCache {

    private final CacheManager cacheManager;

    public IssuerMetadataCache(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void evict() {
        clear();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    clear();
                }
            });
        }
    }

    private void clear() {
        Cache cache = cacheManager.getCache(CredentialRegistry.CACHE_NAME);
        if (cache == null) {
            log.debug("Cache '{}' is not configured; nothing to evict", CredentialRegistry.CACHE_NAME);
            return;
        }
        cache.clear();
    }
}
