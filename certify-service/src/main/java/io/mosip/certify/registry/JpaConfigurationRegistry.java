package io.mosip.certify.registry;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.DisplayConfig;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.StatusConfig;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.TenantContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The new core's {@link ConfigurationRegistry} over today's {@code credential_config} rows (P1-11 prerequisite).
 * Nothing is written; the mapping fixes how a row reads as a {@link CredentialConfiguration}:
 * <ul>
 *   <li>selector: {@code ldp_vc} → {@code context|credentialType} as stored, {@code dc+sd-jwt}/{@code vc+sd-jwt} → vct,
 *       {@code mso_mdoc} → docType;</li>
 *   <li>template: the base64 Velocity template, mode FULL_DOCUMENT, or NONE when the row has none;</li>
 *   <li>signing: {@code keymanager:APPID/REFID}, the row's algorithm (or the first of its signing-alg values), cryptosuite, didUrl;</li>
 *   <li>strategy: TEMPLATE in {@code DataProvider} plugin mode, EXTERNAL when a VCIssuance plugin builds the credential;</li>
 *   <li>status: Bitstring Status List with the row's purposes; display: display, order and claims metadata.</li>
 * </ul>
 * Single tenant: any tenant other than {@code default} sees nothing. Only {@code active} rows are visible.
 */
@Component
public class JpaConfigurationRegistry implements ConfigurationRegistry {

    public static final String STATUS_MECHANISM_BITSTRING = "BitstringStatusList";
    public static final String TEMPLATE_ENGINE_VELOCITY = "velocity";
    private static final String SELECTOR_SEPARATOR = "|";

    private final CredentialConfigRepository repository;
    private final ObjectMapper objectMapper;
    private final String pluginMode;

    public JpaConfigurationRegistry(CredentialConfigRepository repository, ObjectMapper objectMapper,
                                    @Value("${mosip.certify.plugin-mode:DataProvider}") String pluginMode) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.pluginMode = pluginMode;
    }

    @Override
    public Optional<CredentialConfiguration> byId(String tenantId, String credentialConfigurationId) {
        if (!TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            return Optional.empty();
        }
        return repository.findByCredentialConfigKeyId(credentialConfigurationId).filter(this::active).map(this::toConfiguration);
    }

    @Override
    public Optional<CredentialConfiguration> bySelector(String tenantId, String format, String selectorKey) {
        if (!TenantContext.DEFAULT_TENANT_ID.equals(tenantId) || format == null || selectorKey == null) {
            return Optional.empty();
        }
        Optional<CredentialConfig> row = switch (format) {
            case VCFormats.LDP_VC -> {
                int separator = selectorKey.indexOf(SELECTOR_SEPARATOR);
                yield separator < 0 ? Optional.empty()
                        : repository.findByCredentialFormatAndCredentialTypeAndContext(format, selectorKey.substring(separator + 1), selectorKey.substring(0, separator));
            }
            case VCFormats.DC_SD_JWT, "vc+sd-jwt" -> repository.findByCredentialFormatAndSdJwtVct(format, selectorKey);
            case VCFormats.MSO_MDOC -> repository.findByCredentialFormatAndDocType(format, selectorKey);
            default -> Optional.empty();
        };
        return row.filter(this::active).map(this::toConfiguration);
    }

    @Override
    public List<CredentialConfiguration> all(String tenantId) {
        if (!TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            return List.of();
        }
        return repository.findAll().stream().filter(this::active).map(this::toConfiguration).toList();
    }

    private boolean active(CredentialConfig row) {
        return row.getStatus() == null || Constants.ACTIVE.equalsIgnoreCase(row.getStatus());
    }

    /** How one row reads for the new core; package-private so tests can check it on a plain entity. */
    CredentialConfiguration toConfiguration(CredentialConfig row) {
        return isV2(row) ? fromV2Columns(row) : fromLegacyColumns(row);
    }

    /** The read path prefers the JSONB model once the row carries it (config_version >= 2), docs/design/08-database.md. */
    public static boolean isV2(CredentialConfig row) {
        return row.getConfigVersion() != null && row.getConfigVersion() >= ConfigV2Columns.VERSION_V2
                && row.getFormatConfig() != null && row.getSigningConfig() != null;
    }

    @SuppressWarnings("unchecked")
    private CredentialConfiguration fromV2Columns(CredentialConfig row) {
        String format = row.getCredentialFormat();
        Map<String, Object> model = row.getFormatConfig();
        Map<String, Object> raw = new LinkedHashMap<>();
        String selector;
        switch (format) {
            case VCFormats.LDP_VC -> {
                raw.put("context", join(model.get("context")));
                raw.put("credentialType", join(model.get("types")));
                selector = raw.get("context") + SELECTOR_SEPARATOR + raw.get("credentialType");
            }
            case VCFormats.DC_SD_JWT, "vc+sd-jwt" -> {
                raw.put("vct", model.get("vct"));
                raw.put("sdClaim", join(model.get("sdClaims")));
                raw.put("sdJwtClaims", model.get("sdJwtClaims") == null ? Map.of() : model.get("sdJwtClaims")); // the legacy path reads an unset column as an empty map
                selector = String.valueOf(model.get("vct"));
            }
            case VCFormats.MSO_MDOC -> {
                raw.put("docType", model.get("doctype"));
                raw.put("msoMdocClaims", model.get("mdocClaims") == null ? Map.of() : model.get("mdocClaims"));
                selector = String.valueOf(model.get("doctype"));
            }
            default -> selector = row.getCredentialConfigKeyId();
        }
        commonRaw(row, raw);
        FormatConfig formatConfig = new FormatConfig.Generic(raw, selector);

        Map<String, Object> signingModel = row.getSigningConfig();
        String jose = signingModel.get("alg") == null ? null : signingModel.get("alg").toString();
        if ((jose == null || jose.isBlank()) && row.getCredentialSigningAlgValuesSupported() != null && !row.getCredentialSigningAlgValuesSupported().isEmpty()) {
            jose = row.getCredentialSigningAlgValuesSupported().get(0);
        }
        String algorithmName = jose;
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(jose == null ? "" : jose)
                .orElseThrow(() -> new IllegalStateException("credential_config " + row.getCredentialConfigKeyId() + " names no usable signature algorithm: " + algorithmName));
        String provider = signingModel.get("provider") == null ? ConfigV2Columns.PROVIDER_KEYMANAGER : signingModel.get("provider").toString();
        String alias = signingModel.get("alias") == null ? "" : signingModel.get("alias").toString();
        KeyRef keyRef = KeyRef.parse(provider + ":" + alias);
        String cryptosuite = signingModel.get("cryptosuite") == null ? null : blankToNull(signingModel.get("cryptosuite").toString());
        String didUrl = signingModel.get("didUrl") == null ? row.getDidUrl() : signingModel.get("didUrl").toString();
        SigningConfig signing = new SigningConfig(keyRef, algorithm, cryptosuite, null, null, didUrl);

        StatusConfig status = StatusConfig.NONE;
        if (row.getStatusConfig() != null && row.getStatusConfig().get("purposes") instanceof List<?> purposes && !purposes.isEmpty()) {
            Object mechanism = row.getStatusConfig().get("mechanism");
            status = new StatusConfig(mechanism == null ? STATUS_MECHANISM_BITSTRING : mechanism.toString(), purposes.stream().map(String::valueOf).toList());
        }
        IssuanceStrategy strategy = strategyOf(row);
        Map<ProtocolVersion, Map<String, Object>> overrides = new LinkedHashMap<>();
        if (row.getProtocolOverrides() != null) {
            row.getProtocolOverrides().forEach((key, value) -> {
                try {
                    if (value instanceof Map<?, ?> map) {
                        overrides.put(ProtocolVersion.valueOf(key), (Map<String, Object>) map);
                    }
                } catch (IllegalArgumentException ignored) {
                    // an override for a protocol this build does not know is left where it is
                }
            });
        }
        String tenantId = row.getTenantId() == null || row.getTenantId().isBlank() ? TenantContext.DEFAULT_TENANT_ID : row.getTenantId();
        return new CredentialConfiguration(tenantId, row.getCredentialConfigKeyId(), row.getScope(), format, formatConfig,
                template(row), signing, strategy, blankToNull(row.getDataSourceId()), status, display(row), Map.copyOf(overrides));
    }

    /** Backfilled rows keep the default TEMPLATE, so the plugin mode still decides unless the column names another strategy. */
    private IssuanceStrategy strategyOf(CredentialConfig row) {
        String column = row.getIssuanceStrategy();
        if (column != null && !column.isBlank() && !IssuanceStrategy.TEMPLATE.name().equalsIgnoreCase(column)) {
            try {
                return IssuanceStrategy.valueOf(column.trim().toUpperCase());
            } catch (IllegalArgumentException ignored) {
                // fall through to the plugin mode
            }
        }
        return "DataProvider".equalsIgnoreCase(pluginMode) ? IssuanceStrategy.TEMPLATE : IssuanceStrategy.EXTERNAL;
    }

    private static String join(Object list) {
        if (list instanceof List<?> values) {
            return values.isEmpty() ? null : String.join(",", values.stream().map(String::valueOf).toList());
        }
        return list == null ? null : list.toString();
    }

    private void commonRaw(CredentialConfig row, Map<String, Object> raw) {
        raw.put("cryptographicBindingMethodsSupported", row.getCryptographicBindingMethodsSupported());
        raw.put("credentialSigningAlgValuesSupported", row.getCredentialSigningAlgValuesSupported());
        raw.put("proofTypesSupported", row.getProofTypesSupported());
        raw.put("qrSettings", row.getQrSettings());
        raw.put("qrSignatureAlgo", row.getQrSignatureAlgo());
        raw.put("pluginConfigurations", row.getPluginConfigurations());
        raw.values().removeIf(java.util.Objects::isNull); // unset optional columns; FormatConfig copies the map and refuses nulls
    }

    private TemplateRef template(CredentialConfig row) {
        boolean templated = row.getVcTemplate() != null && !row.getVcTemplate().isBlank();
        return templated
                ? new TemplateRef(TEMPLATE_ENGINE_VELOCITY, row.getCredentialConfigKeyId(), null, TemplateRef.Mode.FULL_DOCUMENT, row.getVcTemplate(),
                        Map.of(Constants.DID_URL, row.getDidUrl() == null ? "" : row.getDidUrl()))
                : TemplateRef.NONE;
    }

    private DisplayConfig display(CredentialConfig row) {
        return new DisplayConfig(convertList(row.getDisplay()), row.getOrder(), convert(row.getClaims()));
    }

    private CredentialConfiguration fromLegacyColumns(CredentialConfig row) {
        String format = row.getCredentialFormat();
        Map<String, Object> raw = new LinkedHashMap<>();
        String selector;
        switch (format) {
            case VCFormats.LDP_VC -> {
                raw.put("context", row.getContext());
                raw.put("credentialType", row.getCredentialType());
                selector = row.getContext() + SELECTOR_SEPARATOR + row.getCredentialType();
            }
            case VCFormats.DC_SD_JWT, "vc+sd-jwt" -> {
                raw.put("vct", row.getSdJwtVct());
                raw.put("sdClaim", row.getSdClaim());
                raw.put("sdJwtClaims", convert(row.getSdJwtClaims()));
                selector = row.getSdJwtVct();
            }
            case VCFormats.MSO_MDOC -> {
                raw.put("docType", row.getDocType());
                raw.put("msoMdocClaims", convert(row.getMsoMdocClaims()));
                selector = row.getDocType();
            }
            default -> selector = row.getCredentialConfigKeyId();
        }
        commonRaw(row, raw);
        FormatConfig formatConfig = new FormatConfig.Generic(raw, selector);
        TemplateRef template = template(row);

        String jose = row.getSignatureAlgo();
        if ((jose == null || jose.isBlank()) && row.getCredentialSigningAlgValuesSupported() != null && !row.getCredentialSigningAlgValuesSupported().isEmpty()) {
            jose = row.getCredentialSigningAlgValuesSupported().get(0);
        }
        String algorithmName = jose;
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(jose == null ? "" : jose)
                .orElseThrow(() -> new IllegalStateException("credential_config " + row.getCredentialConfigKeyId() + " names no usable signature algorithm: " + algorithmName));
        // a provider-prefixed key column ("x509-file:issuer-es256") names another KeyProvider; plain columns are keymanager's
        KeyRef keyRef = row.getKeyManagerAppId() != null && row.getKeyManagerAppId().contains(":")
                ? KeyRef.parse(row.getKeyManagerAppId())
                : LegacyKeyRefs.keymanager(row.getKeyManagerAppId(), row.getKeyManagerRefId());
        SigningConfig signing = new SigningConfig(keyRef, algorithm, blankToNull(row.getSignatureCryptoSuite()), null, null, row.getDidUrl());

        IssuanceStrategy strategy = "DataProvider".equalsIgnoreCase(pluginMode) ? IssuanceStrategy.TEMPLATE : IssuanceStrategy.EXTERNAL;
        StatusConfig status = row.getCredentialStatusPurposes() == null || row.getCredentialStatusPurposes().isEmpty()
                ? StatusConfig.NONE : new StatusConfig(STATUS_MECHANISM_BITSTRING, row.getCredentialStatusPurposes());
        return new CredentialConfiguration(TenantContext.DEFAULT_TENANT_ID, row.getCredentialConfigKeyId(), row.getScope(), format, formatConfig,
                template, signing, strategy, null, status, display(row), Map.of());
    }

    private Map<String, Object> convert(Object value) {
        return value == null ? Map.of() : objectMapper.convertValue(value, new TypeReference<Map<String, Object>>() {});
    }

    private List<Map<String, Object>> convertList(Object value) {
        return value == null ? List.of() : objectMapper.convertValue(value, new TypeReference<List<Map<String, Object>>>() {});
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
