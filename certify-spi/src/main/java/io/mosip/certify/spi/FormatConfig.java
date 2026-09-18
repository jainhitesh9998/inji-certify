package io.mosip.certify.spi;

import java.util.Map;

/**
 * Format-specific part of a credential configuration, parsed and validated by the owning
 * {@link CredentialFormatter#parseConfig(Map)}. The generic implementation keeps the raw map for formats
 * that do not need a typed view yet.
 */
public interface FormatConfig {

    /** The raw JSON-compatible map the configuration was created from. */
    Map<String, Object> raw();

    /** Identifies the credential within its format for uniqueness: types+context, vct, or doctype. */
    String selectorKey();

    record Generic(Map<String, Object> raw, String selectorKey) implements FormatConfig {
        public Generic {
            raw = raw == null ? Map.of() : Map.copyOf(raw);
        }
    }
}
