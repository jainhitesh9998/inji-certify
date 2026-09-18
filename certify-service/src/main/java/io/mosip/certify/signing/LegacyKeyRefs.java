package io.mosip.certify.signing;

/** Translates today's credential_config key columns (key_manager_app_id, key_manager_ref_id) into a keymanager {@link KeyRef}. */
public final class LegacyKeyRefs {

    private LegacyKeyRefs() {}

    public static KeyRef keymanager(String applicationId, String referenceId) {
        String alias = referenceId == null || referenceId.isEmpty() ? applicationId : applicationId + "/" + referenceId;
        return new KeyRef("keymanager", alias);
    }
}
