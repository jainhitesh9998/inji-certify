package io.mosip.certify.oid4vci;

import io.mosip.certify.issuance.AuthorizationPolicy;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.issuance.DefaultIssuanceService;
import io.mosip.certify.issuance.FormatterRegistry;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.ExternalIssuer;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.TemplateEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * The new core assembled from the beans the service already has: the registry over {@code credential_config},
 * every {@link CredentialFormatter} and {@link TemplateEngine} on the classpath, the key providers, the data-provider
 * plugin, the jwt proof adapter. Listeners and status providers arrive with P1-10.
 */
@Configuration
public class Oid4vciIssuanceConfiguration {

    @Bean
    public IssuanceService oid4vciIssuanceService(ConfigurationRegistry configurations, List<CredentialFormatter> formatters,
                                                  KeyProviderRegistry keyProviders, List<CredentialDataSource> dataSources,
                                                  List<ExternalIssuer> externalIssuers, List<ProofValidator> proofValidators,
                                                  List<TemplateEngine> templateEngines, List<StatusProvider> statusProviders,
                                                  List<IssuanceListener> listeners, Environment environment) {
        // the validity the legacy issuance applies to templated credentials (mosip.certify.data-provider-plugin.vc-expiry-duration)
        Duration validity = Duration.parse(environment.getProperty("mosip.certify.data-provider-plugin.vc-expiry-duration", "P730D").toUpperCase());
        return new DefaultIssuanceService(configurations, new FormatterRegistry(formatters), keyProviders, dataSources, externalIssuers,
                proofValidators, templateEngines, statusProviders, listeners, AuthorizationPolicy.SCOPE, Clock.systemUTC(), validity);
    }
}
