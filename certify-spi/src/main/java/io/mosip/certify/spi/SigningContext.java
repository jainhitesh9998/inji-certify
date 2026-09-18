package io.mosip.certify.spi;

import io.mosip.certify.signing.Signer;
import io.mosip.certify.signing.SigningKey;

import java.util.Objects;

/** The resolved key and its signer, handed to a formatter's sign step together with the configuration's policy. */
public record SigningContext(SigningConfig config, SigningKey key, Signer signer) {

    public SigningContext {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(signer, "signer");
    }
}
