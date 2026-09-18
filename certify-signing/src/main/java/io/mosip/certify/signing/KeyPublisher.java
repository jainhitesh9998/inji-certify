package io.mosip.certify.signing;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives what verifiers fetch, JWKS today and DID documents and trust lists later, from
 * {@link KeyProvider#publicKeys(KeyFilter)} of every registered provider, so keys are described once.
 */
public final class KeyPublisher {

    private final List<KeyProvider> providers;

    public KeyPublisher(List<KeyProvider> providers) {
        this.providers = List.copyOf(providers);
    }

    public List<PublicKeyDescriptor> descriptors(KeyFilter filter) {
        List<PublicKeyDescriptor> out = new ArrayList<>();
        for (KeyProvider provider : providers) {
            out.addAll(provider.publicKeys(filter));
        }
        return out;
    }

    /** A JWK Set of every key matching the filter (public parts only). */
    public JWKSet jwks(KeyFilter filter) {
        List<JWK> keys = descriptors(filter).stream().map(PublicKeyDescriptor::toJwk).map(JWK::toPublicJWK).toList();
        return new JWKSet(keys);
    }
}
