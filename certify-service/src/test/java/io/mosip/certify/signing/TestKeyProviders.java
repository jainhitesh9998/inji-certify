package io.mosip.certify.signing;

import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;

import java.util.List;

/** A {@code keymanager}-named JCA provider with generated keys, so unit tests exercise real signatures without keymanager. */
public final class TestKeyProviders {

    private TestKeyProviders() {}

    /** A registry whose "keymanager" provider holds one generated key per (alias, algorithm) pair. */
    public static KeyProviderRegistry registry(Object... aliasAlgorithmPairs) {
        JcaKeyProvider provider = new JcaKeyProvider("keymanager");
        for (int i = 0; i < aliasAlgorithmPairs.length; i += 2) {
            provider.generate((String) aliasAlgorithmPairs[i], (SignatureAlgorithm) aliasAlgorithmPairs[i + 1], "CN=test " + aliasAlgorithmPairs[i], "vc-signing");
        }
        return new KeyProviderRegistry(List.of(provider));
    }

    public static KeyProvider provider(KeyProviderRegistry registry) {
        return registry.provider("keymanager");
    }
}
