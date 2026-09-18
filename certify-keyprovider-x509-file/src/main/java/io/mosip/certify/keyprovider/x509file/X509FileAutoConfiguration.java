package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Registers the {@code x509-file} provider when {@code certify.keyprovider.x509-file.enabled=true}; it joins the
 * {@code KeyProviderRegistry} and the JWKS next to keymanager (CLAUDE.md rule 10).
 */
@AutoConfiguration
@EnableConfigurationProperties(X509FileProperties.class)
@ConditionalOnProperty(prefix = "certify.keyprovider.x509-file", name = "enabled", havingValue = "true")
public class X509FileAutoConfiguration {

    @Bean
    public JcaKeyProvider x509FileKeyProvider(X509FileProperties properties) {
        return X509FileKeyProviders.open(properties);
    }
}
