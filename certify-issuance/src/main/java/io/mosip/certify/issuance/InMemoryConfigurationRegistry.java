package io.mosip.certify.issuance;

import io.mosip.certify.spi.CredentialConfiguration;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Registry over a map in registration order: the CLI, tests and the conformance profile use it. */
public class InMemoryConfigurationRegistry implements ConfigurationRegistry {

    private final Map<String, CredentialConfiguration> byKey = Collections.synchronizedMap(new LinkedHashMap<>());

    public InMemoryConfigurationRegistry register(CredentialConfiguration configuration) {
        byKey.put(configuration.tenantId() + "/" + configuration.id(), configuration);
        return this;
    }

    @Override
    public Optional<CredentialConfiguration> byId(String tenantId, String credentialConfigurationId) {
        return Optional.ofNullable(byKey.get(tenantId + "/" + credentialConfigurationId));
    }

    /** A (tenant, format, selector) triple must name one configuration; two matches is a configuration error, not a coin toss. */
    @Override
    public Optional<CredentialConfiguration> bySelector(String tenantId, String format, String selectorKey) {
        List<CredentialConfiguration> matches;
        synchronized (byKey) {
            matches = byKey.values().stream()
                    .filter(c -> c.tenantId().equals(tenantId) && c.format().equals(format)
                            && c.formatConfig() != null && selectorKey.equals(c.formatConfig().selectorKey()))
                    .toList();
        }
        if (matches.size() > 1) {
            throw new IllegalStateException("Selector " + format + "/" + selectorKey + " matches " + matches.size()
                    + " configurations in tenant " + tenantId + ": " + matches.stream().map(CredentialConfiguration::id).toList());
        }
        return matches.stream().findFirst();
    }

    @Override
    public List<CredentialConfiguration> all(String tenantId) {
        synchronized (byKey) {
            return byKey.values().stream().filter(c -> c.tenantId().equals(tenantId)).toList();
        }
    }
}
