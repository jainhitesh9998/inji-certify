package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.utils.VCIssuanceUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

/**
 * Caches the issuer-metadata view programmatically through the {@link CacheManager} (no self-invocation
 * pitfalls of {@code @Cacheable}); {@code CredentialConfigurationServiceImpl} evicts {@link #CACHE_NAME}
 * on every write.
 */
@Slf4j
@Service
public class CredentialRegistryImpl implements CredentialRegistry {

    static final String KEY = "issuer-metadata";

    private final CredentialConfigurationService credentialConfigurationService;
    private final CacheManager cacheManager;
    private boolean warnedMissingCache;

    public CredentialRegistryImpl(CredentialConfigurationService credentialConfigurationService, CacheManager cacheManager) {
        this.credentialConfigurationService = credentialConfigurationService;
        this.cacheManager = cacheManager;
    }

    @Override
    public CredentialIssuerMetadataDTO issuerMetadata() {
        Cache cache = cacheManager.getCache(CACHE_NAME);
        if (cache == null) {
            if (!warnedMissingCache) {
                warnedMissingCache = true;
                log.warn("Cache '{}' is not configured; issuer metadata is rebuilt on every request. Add it to mosip.certify.cache.names.", CACHE_NAME);
            }
            return credentialConfigurationService.fetchCredentialIssuerMetadata();
        }
        return cache.get(KEY, credentialConfigurationService::fetchCredentialIssuerMetadata);
    }

    @Override
    public Optional<CredentialConfigurationSupported> resolve(String scope, String credentialConfigurationId) {
        return VCIssuanceUtil.getScopeCredentialMapping(scope, credentialConfigurationId, issuerMetadata());
    }

    @Override
    public Optional<CredentialConfigurationSupported> byId(String credentialConfigurationId) {
        Map<String, CredentialConfigurationSupportedDTO> supported = issuerMetadata().getCredentialConfigurationSupportedDTO();
        if (supported == null || credentialConfigurationId == null) {
            return Optional.empty();
        }
        CredentialConfigurationSupportedDTO dto = supported.get(credentialConfigurationId);
        return dto == null ? Optional.empty()
                : Optional.of(VCIssuanceUtil.toCredentialConfigurationSupported(credentialConfigurationId, dto));
    }

    @Override
    public void evict() {
        Cache cache = cacheManager.getCache(CACHE_NAME);
        if (cache != null) {
            cache.clear();
        }
    }
}
