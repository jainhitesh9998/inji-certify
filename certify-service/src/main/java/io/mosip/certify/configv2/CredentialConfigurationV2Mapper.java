package io.mosip.certify.configv2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import io.mosip.certify.registry.ConfigV2Columns;
import io.mosip.certify.services.CredentialConfigurationServiceImpl;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Between the v2 model and a {@code credential_config} row. A write fills the JSONB columns and mirrors every legacy
 * column the compatibility surfaces and the metadata builders read (docs/design/08-database.md: both shapes until 2.0.0).
 */
final class CredentialConfigurationV2Mapper {

    private static final TypeReference<Map<String, Claims>> CLAIMS = new TypeReference<>() {};
    private static final TypeReference<Map<String, Map<String, Claims>>> NAMESPACED_CLAIMS = new TypeReference<>() {};
    private static final TypeReference<List<MetaDataDisplay>> DISPLAY = new TypeReference<>() {};
    private static final TypeReference<List<Map<String, Object>>> LIST_OF_MAPS = new TypeReference<>() {};

    private final ObjectMapper mapper;

    CredentialConfigurationV2Mapper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    void apply(CredentialConfigurationV2 body, CredentialConfig row, CredentialConfigurationServiceImpl.ProtocolDefaults defaults) {
        row.setScope(body.getScope());
        row.setCredentialFormat(body.getFormat());
        Map<String, Object> format = body.getFormatConfig() == null ? new LinkedHashMap<>() : new LinkedHashMap<>(body.getFormatConfig());
        row.setFormatConfig(format);
        row.setContext(join(format.get("context")));
        row.setCredentialType(join(format.get("types")));
        row.setSdJwtVct(str(format.get("vct")));
        row.setDocType(str(format.get("doctype")));
        row.setSdClaim(join(format.get("sdClaims")));
        row.setClaims(convert(format.get("claims"), CLAIMS));
        row.setMsoMdocClaims(convert(format.get("mdocClaims"), NAMESPACED_CLAIMS));
        row.setSdJwtClaims(convert(format.get("sdJwtClaims"), CLAIMS));

        CredentialConfigurationV2.Signing signing = body.getSigning();
        String provider = signing.getProvider() == null || signing.getProvider().isBlank() ? ConfigV2Columns.PROVIDER_KEYMANAGER : signing.getProvider();
        Map<String, Object> signingConfig = new LinkedHashMap<>();
        signingConfig.put("provider", provider);
        signingConfig.put("alias", signing.getAlias());
        put(signingConfig, "alg", signing.getAlg());
        put(signingConfig, "cryptosuite", signing.getCryptosuite());
        put(signingConfig, "didUrl", signing.getDidUrl());
        row.setSigningConfig(signingConfig);
        if (ConfigV2Columns.PROVIDER_KEYMANAGER.equals(provider)) {
            int slash = signing.getAlias().indexOf('/');
            row.setKeyManagerAppId(slash < 0 ? signing.getAlias() : signing.getAlias().substring(0, slash));
            row.setKeyManagerRefId(slash < 0 ? null : signing.getAlias().substring(slash + 1));
        } else {
            row.setKeyManagerAppId(provider + ":" + signing.getAlias()); // the provider-prefixed column of P3-01
            row.setKeyManagerRefId(null);
        }
        row.setSignatureAlgo(signing.getAlg());
        row.setSignatureCryptoSuite(signing.getCryptosuite());
        row.setDidUrl(signing.getDidUrl());

        CredentialConfigurationV2.Status status = body.getStatus();
        if (status != null && status.getPurposes() != null && !status.getPurposes().isEmpty()) {
            Map<String, Object> statusConfig = new LinkedHashMap<>();
            statusConfig.put("mechanism", status.getMechanism() == null ? ConfigV2Columns.MECHANISM_BITSTRING : status.getMechanism());
            statusConfig.put("purposes", List.copyOf(status.getPurposes()));
            row.setStatusConfig(statusConfig);
            row.setCredentialStatusPurposes(List.copyOf(status.getPurposes()));
        } else {
            row.setStatusConfig(null);
            row.setCredentialStatusPurposes(null);
        }

        CredentialConfigurationV2.Display display = body.getDisplay();
        row.setDisplay(display == null ? null : convert(display.getDisplay(), DISPLAY));
        row.setOrder(display == null ? null : display.getOrder());

        CredentialConfigurationV2.Protocol protocol = body.getProtocol() == null ? new CredentialConfigurationV2.Protocol() : body.getProtocol();
        row.setCryptographicBindingMethodsSupported(protocol.getCryptographicBindingMethodsSupported() != null
                ? protocol.getCryptographicBindingMethodsSupported() : defaults.cryptographicBindingMethodsSupported());
        // the legacy column names the suite for Data Integrity formats and the JOSE algorithm otherwise, as the v1 API writes it
        row.setCredentialSigningAlgValuesSupported(protocol.getCredentialSigningAlgValuesSupported() != null
                ? protocol.getCredentialSigningAlgValuesSupported()
                : List.of(signing.getCryptosuite() != null ? signing.getCryptosuite() : signing.getAlg()));
        row.setProofTypesSupported(protocol.getProofTypesSupported() != null ? protocol.getProofTypesSupported() : defaults.proofTypesSupported());
        row.setProtocolOverrides(protocol.getOverrides());

        row.setQrSettings(body.getQr() == null ? null : body.getQr().getSettings());
        row.setQrSignatureAlgo(body.getQr() == null ? null : body.getQr().getSignatureAlgo());
        row.setPluginConfigurations(body.getPluginConfigurations());
        row.setIssuanceStrategy(body.getIssuanceStrategy() == null || body.getIssuanceStrategy().isBlank() ? "TEMPLATE" : body.getIssuanceStrategy().trim().toUpperCase());
        row.setDataSourceId(body.getDataSourceId());
        row.setConfigVersion(ConfigV2Columns.VERSION_V2);
    }

    CredentialConfigurationV2 read(CredentialConfig row, CredentialTemplate template) {
        CredentialConfigurationV2 dto = new CredentialConfigurationV2();
        dto.setId(row.getCredentialConfigKeyId());
        dto.setTenantId(row.getTenantId());
        dto.setScope(row.getScope());
        dto.setFormat(row.getCredentialFormat());
        dto.setFormatConfig(row.getFormatConfig() != null ? row.getFormatConfig() : ConfigV2Columns.formatConfig(row));
        Map<String, Object> signingConfig = row.getSigningConfig() != null ? row.getSigningConfig() : ConfigV2Columns.signingConfig(row);
        CredentialConfigurationV2.Signing signing = new CredentialConfigurationV2.Signing();
        signing.setProvider(str(signingConfig.get("provider")));
        signing.setAlias(str(signingConfig.get("alias")));
        signing.setAlg(str(signingConfig.get("alg")));
        signing.setCryptosuite(str(signingConfig.get("cryptosuite")));
        signing.setDidUrl(str(signingConfig.get("didUrl")));
        dto.setSigning(signing);
        if (template != null) {
            CredentialConfigurationV2.Template t = new CredentialConfigurationV2.Template();
            t.setEngine(template.getEngine());
            t.setMode(template.getMode());
            t.setContent(template.getContent());
            t.setVersion(template.getVersion());
            dto.setTemplate(t);
        } else if (row.getVcTemplate() != null && !row.getVcTemplate().isBlank()) {
            CredentialConfigurationV2.Template t = new CredentialConfigurationV2.Template();
            t.setEngine(CredentialTemplate.ENGINE_VELOCITY);
            t.setMode(CredentialTemplate.MODE_FULL_DOCUMENT);
            t.setContent(decode(row.getVcTemplate()));
            dto.setTemplate(t);
        }
        dto.setIssuanceStrategy(row.getIssuanceStrategy());
        dto.setDataSourceId(row.getDataSourceId());
        Map<String, Object> statusConfig = row.getStatusConfig() != null ? row.getStatusConfig() : ConfigV2Columns.statusConfig(row);
        if (statusConfig != null && statusConfig.get("purposes") instanceof List<?> purposes && !purposes.isEmpty()) {
            CredentialConfigurationV2.Status status = new CredentialConfigurationV2.Status();
            status.setMechanism(str(statusConfig.get("mechanism")));
            status.setPurposes(purposes.stream().map(String::valueOf).toList());
            dto.setStatus(status);
        }
        CredentialConfigurationV2.Display display = new CredentialConfigurationV2.Display();
        display.setDisplay(convert(row.getDisplay(), LIST_OF_MAPS));
        display.setOrder(row.getOrder());
        dto.setDisplay(display);
        CredentialConfigurationV2.Protocol protocol = new CredentialConfigurationV2.Protocol();
        protocol.setCryptographicBindingMethodsSupported(row.getCryptographicBindingMethodsSupported());
        protocol.setCredentialSigningAlgValuesSupported(row.getCredentialSigningAlgValuesSupported());
        protocol.setProofTypesSupported(row.getProofTypesSupported());
        protocol.setOverrides(row.getProtocolOverrides());
        dto.setProtocol(protocol);
        if (row.getQrSettings() != null || row.getQrSignatureAlgo() != null) {
            CredentialConfigurationV2.Qr qr = new CredentialConfigurationV2.Qr();
            qr.setSettings(row.getQrSettings());
            qr.setSignatureAlgo(row.getQrSignatureAlgo());
            dto.setQr(qr);
        }
        dto.setPluginConfigurations(row.getPluginConfigurations());
        dto.setConfigId(row.getConfigId());
        dto.setActive(Constants.ACTIVE.equalsIgnoreCase(row.getStatus()));
        dto.setConfigVersion(row.getConfigVersion());
        dto.setCreatedTimes(row.getCreatedTimes());
        dto.setUpdatedTimes(row.getUpdatedTimes());
        return dto;
    }

    static String join(Object value) {
        if (value instanceof List<?> values) {
            return values.isEmpty() ? null : String.join(",", values.stream().map(String::valueOf).toList());
        }
        return value == null || value.toString().isBlank() ? null : value.toString();
    }

    static String str(Object value) {
        return value == null ? null : value.toString();
    }

    static String encode(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    static String decode(String blob) {
        try {
            return new String(Base64.getDecoder().decode(blob), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return blob;
        }
    }

    private <T> T convert(Object value, TypeReference<T> type) {
        return value == null ? null : mapper.convertValue(value, type);
    }

    private static void put(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }
}
