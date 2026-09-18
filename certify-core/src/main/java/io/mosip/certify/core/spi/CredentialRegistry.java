package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;

import java.util.Optional;

/**
 * The one place the core looks up credential configurations (docs/design/05-target-architecture.md).
 * Today it serves the issuer-metadata view of the active configurations from a cache that is evicted on
 * every configuration write, so a credential request no longer costs a {@code findAll()}; in Phase 1 it
 * returns the domain {@code CredentialConfiguration} and the metadata DTO moves into the protocol adapters.
 */
public interface CredentialRegistry {

    /** Cache holding the issuer metadata; configured in {@code mosip.certify.cache.names} of every deployment. */
    String CACHE_NAME = "issuerMetadataCache";

    /** Issuer metadata built from the active configurations; cached until the next configuration write. */
    CredentialIssuerMetadataDTO issuerMetadata();

    /**
     * The configuration a credential request names, provided the access token's scope matches it.
     * Empty when the scope does not match; throws {@code CertifyException(invalid_credential_request)}
     * when no active configuration has that id (unchanged semantics of the issuance services).
     */
    Optional<CredentialConfigurationSupported> resolve(String scope, String credentialConfigurationId);

    /** The active configuration with this id, regardless of scope. */
    Optional<CredentialConfigurationSupported> byId(String credentialConfigurationId);

    /** Drops the cached view; configuration writes do this through {@code @CacheEvict}. */
    void evict();
}
