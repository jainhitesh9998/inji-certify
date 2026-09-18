package io.mosip.certify.spi;

/**
 * Where the subject's data comes from (successor of {@code DataProviderPlugin}). Several may be registered;
 * a configuration names the one it uses through {@link CredentialConfiguration#dataSourceId()}.
 */
public interface CredentialDataSource {

    String id();

    ClaimSet fetch(IssuanceContext context, CredentialConfiguration configuration) throws DataSourceException;
}
