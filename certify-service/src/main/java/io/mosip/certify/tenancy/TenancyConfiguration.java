package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.TenantResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** The {@link TenantResolver} of this deployment: fixed to {@code default} unless tenancy is enabled with another resolver. */
@Configuration
@EnableConfigurationProperties(TenancyProperties.class)
public class TenancyConfiguration {

    @Bean
    @ConditionalOnMissingBean(TenantResolver.class)
    public TenantResolver tenantResolver(TenancyProperties properties) {
        if (properties.enabled() && TenancyProperties.RESOLVER_HOST.equalsIgnoreCase(properties.resolver())) {
            return new HostTenantResolver(properties);
        }
        if (properties.enabled() && !TenancyProperties.RESOLVER_FIXED.equalsIgnoreCase(properties.resolver())) {
            throw new IllegalStateException("certify.tenancy.resolver must be 'fixed' or 'host': " + properties.resolver());
        }
        return TenantResolver.fixed(TenantContext.DEFAULT);
    }
}
