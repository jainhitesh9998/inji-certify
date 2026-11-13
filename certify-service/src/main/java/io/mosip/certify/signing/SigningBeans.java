package io.mosip.certify.signing;

import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.certify.issuance.KeyProviderRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/** The registry over every {@link KeyProvider} bean; signing code asks it for the provider a KeyRef names. */
@Configuration
@EnableConfigurationProperties({CwtSigningProperties.class, SigningKeyExpiryProperties.class})
public class SigningBeans {

    @Bean
    public KeyProviderRegistry keyProviderRegistry(List<KeyProvider> providers) {
        return new KeyProviderRegistry(providers);
    }

    @Bean
    public KeyPublisher keyPublisher(List<KeyProvider> providers) {
        return new KeyPublisher(providers);
    }

    /**
     * Expiry visibility for the current signing certificates (M-05): the warning and the
     * {@code certify.signing.key.expires_in_days} gauge. Micrometer is a service dependency, never a provider one.
     * Creating the bean reads no provider: the first report runs on {@code ApplicationReadyEvent}, after keymanager has
     * provisioned its keys, and is then reconciled every {@code certify.signing.key-expiry.reconcile-interval}.
     */
    @Bean
    public SigningKeyExpiry signingKeyExpiry(List<KeyProvider> providers, ObjectProvider<MeterRegistry> meterRegistry,
                                             SigningKeyExpiryProperties properties) {
        return new SigningKeyExpiry(providers, meterRegistry.getIfAvailable(), properties);
    }
}
