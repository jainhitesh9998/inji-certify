package io.mosip.certify.issuance;

import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Routes a {@link KeyRef} to the provider named in it; two providers can be active at once. */
public class KeyProviderRegistry {

    private final Map<String, KeyProvider> providers;

    public KeyProviderRegistry(List<KeyProvider> providers) {
        this.providers = providers.stream().collect(Collectors.toUnmodifiableMap(KeyProvider::id, Function.identity()));
    }

    public KeyProvider provider(String id) {
        KeyProvider provider = providers.get(id);
        if (provider == null) {
            throw new SigningException("No key provider registered with id '" + id + "' (have " + providers.keySet() + ")");
        }
        return provider;
    }

    public SigningContext signingContext(SigningConfig config) {
        KeyRef ref = config.keyRef();
        KeyProvider provider = provider(ref.provider());
        SigningKey key = provider.resolve(ref);
        return new SigningContext(config, key, provider);
    }

    public List<KeyProvider> all() {
        return List.copyOf(providers.values());
    }
}
