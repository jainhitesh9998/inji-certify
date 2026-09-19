package io.mosip.certify.vcapi;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The VC-API adapter exists only when {@code certify.protocol.vc-api.enabled} is set: its properties, its client
 * authentication filter and (outside the {@code test} profile, like every security chain) its security chain in
 * {@link VcApiSecurityConfiguration}.
 */
@Configuration
@EnableConfigurationProperties(VcApiProperties.class)
@ConditionalOnProperty(prefix = VcApiProperties.PREFIX, name = "enabled", havingValue = "true")
public class VcApiConfiguration {

    @Bean
    public VcApiClientAuthFilter vcApiClientAuthFilter(VcApiProperties properties) {
        return new VcApiClientAuthFilter(properties);
    }
}
