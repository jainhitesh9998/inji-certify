package io.mosip.certify.keyprovider.keymanager;

import io.mosip.certify.signing.KeyRef;

import java.util.Objects;

/**
 * A keymanager key is addressed by an application id and a reference id; the {@link KeyRef} alias spells them
 * {@code APPID} (empty reference id) or {@code APPID/REFID}, so {@code keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN}
 * names the key today's {@code key-alias-mapper} entry {@code {'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}} names.
 */
public record KeymanagerAlias(String applicationId, String referenceId) {

    public KeymanagerAlias {
        Objects.requireNonNull(applicationId, "applicationId");
        if (applicationId.isBlank()) {
            throw new IllegalArgumentException("Keymanager alias needs an application id");
        }
        referenceId = referenceId == null ? "" : referenceId;
    }

    public static KeymanagerAlias parse(String alias) {
        int slash = alias.indexOf('/');
        if (slash < 0) {
            return new KeymanagerAlias(alias, "");
        }
        return new KeymanagerAlias(alias.substring(0, slash), alias.substring(slash + 1));
    }

    public static KeymanagerAlias of(KeyRef ref) {
        return parse(ref.alias());
    }

    public KeyRef toKeyRef() {
        return new KeyRef(KeymanagerKeyProvider.ID, toString());
    }

    @Override
    public String toString() {
        return referenceId.isEmpty() ? applicationId : applicationId + "/" + referenceId;
    }
}
