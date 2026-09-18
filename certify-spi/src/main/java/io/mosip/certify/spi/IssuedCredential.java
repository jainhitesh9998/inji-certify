package io.mosip.certify.spi;

import java.util.Map;
import java.util.Objects;

/**
 * A signed credential as the wire wants it: a JSON document (map) for {@code ldp_vc}, a compact string for
 * JWT-based formats and base64url CBOR for mDoc; {@code credentialId} is what the ledger and status track.
 */
public record IssuedCredential(String format, Object credential, String credentialId, Map<String, Object> attributes) {

    public IssuedCredential {
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(credential, "credential");
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
