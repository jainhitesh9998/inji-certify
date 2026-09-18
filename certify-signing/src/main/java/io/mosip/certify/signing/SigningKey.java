package io.mosip.certify.signing;

import java.util.Objects;

/**
 * A resolved key: the reference that named it, what the provider publishes about it, and the provider's
 * private handle (a JCA {@code PrivateKey}, an HSM object id, a KMS ARN) that only that provider reads.
 */
public record SigningKey(KeyRef ref, PublicKeyDescriptor descriptor, Object providerHandle) {

    public SigningKey {
        Objects.requireNonNull(ref, "ref");
        Objects.requireNonNull(descriptor, "descriptor");
    }

    public SignatureAlgorithm algorithm() { return descriptor.algorithm(); }

    public String kid() { return descriptor.kid(); }

    public CertificateChain chain() { return descriptor.chain(); }
}
