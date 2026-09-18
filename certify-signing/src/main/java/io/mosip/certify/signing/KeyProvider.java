package io.mosip.certify.signing;

import java.util.List;
import java.util.Set;

/**
 * Where keys live. MOSIP kernel-keymanager is the default implementation; others hold keys in a PKCS#12
 * file, a PKCS#11 token, a cloud KMS or any other key-management library. A provider is also the
 * {@link Signer} for its own keys.
 */
public interface KeyProvider extends Signer {

    /** Stable id used as the {@code provider} part of a {@link KeyRef}, e.g. {@code keymanager}, {@code jca}. */
    String id();

    /** Resolves a reference to a key, applying the provider's rotation rules when no version is named. */
    SigningKey resolve(KeyRef ref);

    /** Every public key this provider is willing to publish (JWKS, DID document, trust lists). */
    List<PublicKeyDescriptor> publicKeys(KeyFilter filter);

    Set<SignatureAlgorithm> supportedAlgorithms();

    /** Creates the keys a deployment needs when the provider can; default is to do nothing. */
    default void ensureKeys(List<KeyRequirement> required) {}

    /**
     * Every key the alias has had, current one included: what a DID document or a JWKS lists so credentials signed
     * before a rotation still verify. Providers without rotation history return the current key only.
     */
    default List<PublicKeyDescriptor> publicKeys(KeyRef ref) {
        return List.of(resolve(ref).descriptor());
    }
}
