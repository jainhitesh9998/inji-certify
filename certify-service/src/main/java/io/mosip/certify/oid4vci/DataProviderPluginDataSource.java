package io.mosip.certify.oid4vci;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.IssuanceContext;
import org.json.JSONObject;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/** Today's {@link DataProviderPlugin} as the core's data source: the access token claims are the identity details. */
@Component
public class DataProviderPluginDataSource implements CredentialDataSource {

    public static final String ID = "data-provider-plugin";
    public static final String ERROR_UNAVAILABLE = "data_provider_unavailable";

    private final ObjectProvider<DataProviderPlugin> plugin;

    public DataProviderPluginDataSource(ObjectProvider<DataProviderPlugin> plugin) {
        this.plugin = plugin;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ClaimSet fetch(IssuanceContext context, CredentialConfiguration configuration) throws DataSourceException {
        DataProviderPlugin dataProviderPlugin = plugin.getIfAvailable();
        if (dataProviderPlugin == null) {
            throw new DataSourceException(ERROR_UNAVAILABLE, "No DataProviderPlugin is configured (plugin mode " + configuration.strategy() + ")");
        }
        Map<String, Object> identityDetails = new HashMap<>(context.authorization().claims());
        identityDetails.put("accessTokenHash", context.authorization().tokenHash());
        try {
            JSONObject data = dataProviderPlugin.fetchData(identityDetails);
            return new ClaimSet(data.toMap(), Map.of("source", ID));
        } catch (DataProviderExchangeException e) {
            throw new DataSourceException(e.getErrorCode() == null ? "data_provider_error" : e.getErrorCode(), e.getMessage(), e);
        }
    }
}
