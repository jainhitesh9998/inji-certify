package io.mosip.certify.signing;

import java.time.Instant;
import java.util.Optional;

/** Selects keys from {@link KeyProvider#publicKeys(KeyFilter)}; every field is optional. */
public record KeyFilter(String purpose, SignatureAlgorithm algorithm, Instant validAt) {

    public static final KeyFilter ALL = new KeyFilter(null, null, null);

    public static KeyFilter purpose(String purpose) { return new KeyFilter(purpose, null, null); }

    public static KeyFilter validNow() { return new KeyFilter(null, null, Instant.now()); }

    public boolean matches(PublicKeyDescriptor descriptor) {
        return (purpose == null || purpose.equals(descriptor.purpose()))
                && (algorithm == null || algorithm == descriptor.algorithm())
                && (validAt == null || descriptor.isValidAt(validAt));
    }

    public Optional<String> purposeOpt() { return Optional.ofNullable(purpose); }
}
