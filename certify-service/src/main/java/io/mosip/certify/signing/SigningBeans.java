package io.mosip.certify.signing;

import io.mosip.certify.issuance.KeyProviderRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/** The registry over every {@link KeyProvider} bean; signing code asks it for the provider a KeyRef names. */
@Configuration
public class SigningBeans {

    @Bean
    public KeyProviderRegistry keyProviderRegistry(List<KeyProvider> providers) {
        return new KeyProviderRegistry(providers);
    }
}
