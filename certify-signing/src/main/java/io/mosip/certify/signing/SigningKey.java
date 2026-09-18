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

    /**
     * The same key used with another algorithm of the same family, e.g. PS256 over an RSA key whose provider
     * reports RS256. EC and Ed25519 keys sign with exactly one algorithm, so anything else is refused.
     */
    public SigningKey withAlgorithm(SignatureAlgorithm algorithm) {
        SignatureAlgorithm natural = descriptor.algorithm();
        if (algorithm == natural) {
            return this;
        }
        if (!(natural.isRsa() && algorithm.isRsa())) {
            throw new SigningException("Key " + ref + " (" + natural.joseName() + ") cannot sign with " + algorithm.joseName());
        }
        PublicKeyDescriptor d = descriptor;
        return new SigningKey(ref, new PublicKeyDescriptor(d.kid(), algorithm, d.publicKey(), d.chain(), d.notBefore(), d.notAfter(), d.purpose()), providerHandle);
    }
}
