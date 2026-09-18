package io.mosip.certify.issuance;

import io.mosip.certify.spi.CredentialConfiguration;

import java.util.List;
import java.util.Optional;

/** The core's lookup of credential configurations; the persistence module implements it over credential_config. */
public interface ConfigurationRegistry {

    Optional<CredentialConfiguration> byId(String tenantId, String credentialConfigurationId);

    Optional<CredentialConfiguration> bySelector(String tenantId, String format, String selectorKey);

    List<CredentialConfiguration> all(String tenantId);
}
