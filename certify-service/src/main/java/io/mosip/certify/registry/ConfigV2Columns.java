package io.mosip.certify.registry;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.entity.CredentialConfig;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The v2 JSONB columns of a {@code credential_config} row derived from its legacy columns, exactly as the 1.1.0
 * migration backfills them (V1_1_0_000__config_v2_and_tenancy.sql): the v1 config API calls this before every save
 * so both shapes stay in step until the sunset release.
 */
public final class ConfigV2Columns {

    public static final int VERSION_V2 = 2;
    public static final String PROVIDER_KEYMANAGER = "keymanager";
    public static final String MECHANISM_BITSTRING = "BitstringStatusList";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ConfigV2Columns() {}

    public static void fill(CredentialConfig row) {
        row.setFormatConfig(formatConfig(row));
        row.setSigningConfig(signingConfig(row));
        row.setStatusConfig(statusConfig(row));
        if (row.getTenantId() == null || row.getTenantId().isBlank()) {
            row.setTenantId("default");
        }
        if (row.getIssuanceStrategy() == null || row.getIssuanceStrategy().isBlank()) {
            row.setIssuanceStrategy("TEMPLATE");
        }
        row.setConfigVersion(VERSION_V2);
    }

    public static Map<String, Object> formatConfig(CredentialConfig row) {
        Map<String, Object> out = new LinkedHashMap<>();
        put(out, "context", split(row.getContext()));
        put(out, "types", split(row.getCredentialType()));
        put(out, "vct", row.getSdJwtVct());
        put(out, "doctype", row.getDocType());
        put(out, "sdClaims", split(row.getSdClaim()));
        put(out, "claims", plain(row.getClaims()));
        put(out, "mdocClaims", plain(row.getMsoMdocClaims()));
        put(out, "sdJwtClaims", plain(row.getSdJwtClaims()));
        return out;
    }

    public static Map<String, Object> signingConfig(CredentialConfig row) {
        Map<String, Object> out = new LinkedHashMap<>();
        String appId = row.getKeyManagerAppId();
        if (appId != null && appId.contains(":")) {
            put(out, "provider", appId.substring(0, appId.indexOf(':')));
            put(out, "alias", appId.substring(appId.indexOf(':') + 1));
        } else {
            put(out, "provider", PROVIDER_KEYMANAGER);
            put(out, "alias", appId == null ? null : appId + "/" + (row.getKeyManagerRefId() == null ? "" : row.getKeyManagerRefId()));
        }
        put(out, "alg", row.getSignatureAlgo());
        put(out, "cryptosuite", row.getSignatureCryptoSuite());
        put(out, "didUrl", row.getDidUrl());
        return out;
    }

    public static Map<String, Object> statusConfig(CredentialConfig row) {
        if (row.getCredentialStatusPurposes() == null || row.getCredentialStatusPurposes().isEmpty()) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mechanism", MECHANISM_BITSTRING);
        out.put("purposes", List.copyOf(row.getCredentialStatusPurposes()));
        return out;
    }

    private static List<String> split(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            return null;
        }
        return Arrays.stream(commaSeparated.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static Map<String, Object> plain(Object value) {
        return value == null ? null : MAPPER.convertValue(value, new TypeReference<Map<String, Object>>() {});
    }

    private static void put(Map<String, Object> out, String key, Object value) {
        if (value != null) {
            out.put(key, value);
        }
    }
}
