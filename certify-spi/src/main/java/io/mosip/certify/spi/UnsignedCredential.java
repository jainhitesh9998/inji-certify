package io.mosip.certify.spi;

import java.util.Map;
import java.util.Objects;

/**
 * A credential before its proof: a JSON document (as a map) for JSON-based formats, or bytes for CBOR-based
 * ones, plus format attributes the signing step needs (e.g. selective-disclosure paths, mDoc namespaces).
 */
public record UnsignedCredential(String format, Object document, Map<String, Object> attributes) {

    public UnsignedCredential {
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(document, "document");
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> asMap() {
        if (document instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw new IllegalStateException(format + " credential is not a JSON document");
    }

    public UnsignedCredential withDocument(Object newDocument) {
        return new UnsignedCredential(format, newDocument, attributes);
    }

    public UnsignedCredential withAttribute(String name, Object value) {
        Map<String, Object> copy = new java.util.HashMap<>(attributes);
        copy.put(name, value);
        return new UnsignedCredential(format, document, copy);
    }
}
