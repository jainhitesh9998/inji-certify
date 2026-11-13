package io.mosip.certify.oid4vci;

import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.DisplayConfig;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * F-10 review round 1, item 8: the {@code /oid4vci} document's claim orders come from configurations already read, not
 * from a second registry read per request: a tenant's from the list its document was built from, the default tenant's
 * from the issuer-metadata cache, read again only after a configuration write cleared it.
 */
class TenantIssuerMetadataClaimOrderTest {

    final ConfigurationRegistry registry = mock(ConfigurationRegistry.class);
    final ConcurrentMapCacheManager caches = new ConcurrentMapCacheManager(CredentialRegistry.CACHE_NAME);
    final TenantIssuerMetadata metadata = new TenantIssuerMetadata(registry, List.of(), null, null, caches);

    @Test
    void theDefaultTenantsOrdersAreReadOnceUntilTheMetadataCacheIsCleared() {
        when(registry.all(TenantContext.DEFAULT_TENANT_ID)).thenReturn(List.of(
                configuration("mDL", List.of("family_name", "given_name")), configuration("Farmer", null)));

        Map<String, List<String>> expected = Map.of("mDL", List.of("family_name", "given_name"));
        assertEquals(expected, metadata.defaultClaimOrders());
        assertEquals(expected, metadata.defaultClaimOrders());
        verify(registry, times(1)).all(TenantContext.DEFAULT_TENANT_ID);

        caches.getCache(CredentialRegistry.CACHE_NAME).clear(); // what IssuerMetadataCache.evict does on every configuration write
        metadata.defaultClaimOrders();
        verify(registry, times(2)).all(TenantContext.DEFAULT_TENANT_ID);
    }

    @Test
    void aRegistryThatCannotBeReadLeavesTheClaimsOrderedByPath() {
        when(registry.all(TenantContext.DEFAULT_TENANT_ID)).thenThrow(new IllegalStateException("database down"));
        assertEquals(Map.of(), metadata.defaultClaimOrders());
    }

    @Test
    void aTenantsOrdersComeFromTheConfigurationsItsDocumentWasBuiltFrom() {
        List<CredentialConfiguration> read = List.of(configuration("mDL", List.of("portrait")));
        assertEquals(Map.of("mDL", List.of("portrait")), TenantIssuerMetadata.claimOrders(read));
        verify(registry, times(0)).all(org.mockito.ArgumentMatchers.anyString());
    }

    static CredentialConfiguration configuration(String id, List<String> order) {
        return new CredentialConfiguration(TenantContext.DEFAULT_TENANT_ID, id, "scope", "mso_mdoc", null, null,
                new SigningConfig(KeyRef.parse("keymanager:ISSUER/EC"), SignatureAlgorithm.ES256, null, null, null, null),
                null, null, null, order == null ? null : new DisplayConfig(List.of(), order, Map.of()), Map.of());
    }
}
