package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.cache.support.NoOpCacheManager;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CredentialRegistryImplTest {

    private final CredentialConfigurationService service = mock(CredentialConfigurationService.class);
    private CredentialIssuerMetadataDTO metadata;

    @BeforeEach
    void setUp() {
        metadata = new CredentialIssuerMetadataDTO();
        CredentialConfigurationSupportedDTO farmer = new CredentialConfigurationSupportedDTO();
        farmer.setFormat("ldp_vc");
        farmer.setScope("sample_vc_ldp");
        CredentialDefinition definition = new CredentialDefinition();
        definition.setType(List.of("VerifiableCredential", "FarmerCredential"));
        definition.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        farmer.setCredentialDefinition(definition);
        farmer.setProofTypesSupported(Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
        CredentialConfigurationSupportedDTO sdJwt = new CredentialConfigurationSupportedDTO();
        sdJwt.setFormat("dc+sd-jwt");
        sdJwt.setScope("sample_sd_jwt");
        sdJwt.setVct("FarmerCredential");
        metadata.setCredentialConfigurationSupportedDTO(Map.of("FarmerCredential", farmer, "FarmerSdJwt", sdJwt));
        when(service.fetchCredentialIssuerMetadata()).thenReturn(metadata);
    }

    @Test
    void metadataIsBuiltOnceUntilEvicted() {
        CredentialRegistry registry = new CredentialRegistryImpl(service, new ConcurrentMapCacheManager(CredentialRegistry.CACHE_NAME));
        registry.issuerMetadata();
        registry.issuerMetadata();
        registry.resolve("sample_vc_ldp", "FarmerCredential");
        verify(service, times(1)).fetchCredentialIssuerMetadata();

        registry.evict();
        registry.issuerMetadata();
        verify(service, times(2)).fetchCredentialIssuerMetadata();
    }

    @Test
    void resolveKeepsTheIssuanceSemantics() {
        CredentialRegistry registry = new CredentialRegistryImpl(service, new ConcurrentMapCacheManager(CredentialRegistry.CACHE_NAME));
        CredentialConfigurationSupported farmer = registry.resolve("sample_vc_ldp", "FarmerCredential").orElseThrow();
        assertEquals("ldp_vc", farmer.getFormat());
        assertEquals(List.of("VerifiableCredential", "FarmerCredential"), farmer.getTypes());
        assertEquals("FarmerCredential", farmer.getId());
        assertTrue(registry.resolve("other_scope", "FarmerCredential").isEmpty(), "scope mismatch is empty");
        assertThrows(CertifyException.class, () -> registry.resolve("sample_vc_ldp", "Unknown"), "unknown id is invalid_credential_request");
        assertEquals("FarmerCredential", registry.byId("FarmerSdJwt").orElseThrow().getVct());
        assertEquals(Optional.empty(), registry.byId("Unknown"));
    }

    @Test
    void withoutTheCacheEveryCallRebuildsButStillWorks() {
        CredentialRegistry registry = new CredentialRegistryImpl(service, new NoOpCacheManager());
        registry.issuerMetadata();
        registry.issuerMetadata();
        verify(service, times(2)).fetchCredentialIssuerMetadata();
    }
}
