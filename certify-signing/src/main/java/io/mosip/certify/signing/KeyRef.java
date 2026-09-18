package io.mosip.certify.signing;

import java.util.Objects;
import java.util.Optional;

/**
 * Opaque reference to a signing key: which provider holds it and the provider's own alias for it.
 * Written as {@code provider:alias} or {@code provider:alias@version}, e.g.
 * {@code keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN} or {@code jca:dev-es256}.
 * A reference without a version resolves to the provider's current key (rotation happens inside the provider).
 */
public record KeyRef(String provider, String alias, String version) {

    public KeyRef {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(alias, "alias");
        if (provider.isBlank() || alias.isBlank()) {
            throw new IllegalArgumentException("KeyRef needs a provider and an alias");
        }
    }

    public KeyRef(String provider, String alias) {
        this(provider, alias, null);
    }

    public Optional<String> versionOpt() {
        return Optional.ofNullable(version);
    }

    public static KeyRef parse(String text) {
        Objects.requireNonNull(text, "text");
        int colon = text.indexOf(':');
        if (colon <= 0 || colon == text.length() - 1) {
            throw new IllegalArgumentException("KeyRef must look like provider:alias[@version], got '" + text + "'");
        }
        String provider = text.substring(0, colon);
        String rest = text.substring(colon + 1);
        int at = rest.lastIndexOf('@');
        if (at > 0) {
            return new KeyRef(provider, rest.substring(0, at), rest.substring(at + 1));
        }
        return new KeyRef(provider, rest, null);
    }

    @Override
    public String toString() {
        return provider + ":" + alias + (version == null ? "" : "@" + version);
    }
}
