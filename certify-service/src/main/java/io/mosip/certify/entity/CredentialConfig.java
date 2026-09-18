package io.mosip.certify.entity;


import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Type;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Entity
@NoArgsConstructor
@Table(name = "credential_config",uniqueConstraints = {
        @UniqueConstraint(name = "uk_credential_config_key_id", columnNames = "credential_config_key_id")
})
public class CredentialConfig {

    @Id
    @Column(name = "config_id", nullable = false, updatable = false)
    private String configId;

    private String status;

    private String vcTemplate;

    @NotNull(message = "Invalid request")
    @Column(name = "credential_config_key_id", unique = true, nullable = false)
    private String credentialConfigKeyId;

    private String context;

    private String credentialType;

    private String credentialFormat;

    @Comment("URL for the public key. Should point to the exact key. Supports DID document or public key")
    private String didUrl;

    @Comment("AppId of the keymanager")
    private String keyManagerAppId;

    @Comment("RefId of the keymanager")
    private String keyManagerRefId;

    @Comment("This for VC signature or proof algorithm")
    private String signatureAlgo; //Can be called as Proof algorithm

    @Comment("This is the crypto suite used for VC signature or proof generation")
    private String signatureCryptoSuite;

    @Comment("This is a comma seperated list for selective disclosure.")
    private String sdClaim;

    @NotNull(message = "Invalid request")
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "display", columnDefinition = "jsonb")
    private List<MetaDataDisplay> display;

    @Column(name = "display_order", columnDefinition = "TEXT[]")
    private List<String> order;

    @NotNull(message = "Invalid request")
    private String scope;

    @NotNull(message = "Invalid request")
    @Column(name = "cryptographic_binding_methods_supported", columnDefinition = "TEXT[]")
    private List<String> cryptographicBindingMethodsSupported;

    @NotNull(message = "Invalid request")
    @Column(name = "credential_signing_alg_values_supported", columnDefinition = "TEXT[]")
    private List<String> credentialSigningAlgValuesSupported;

    @NotNull(message = "Invalid request")
    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "proof_types_supported", columnDefinition = "jsonb")
    private Map<String, Object> proofTypesSupported;

    @Column(name = "doctype")
    private String docType;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "claims", columnDefinition = "jsonb")
    private Map<String, Claims> claims;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "mso_mdoc_claims", columnDefinition = "jsonb")
    private Map<String, Map<String, Claims>> msoMdocClaims;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "sd_jwt_claims", columnDefinition = "jsonb")
    private Map<String, Claims> sdJwtClaims;

    @Column(name = "sd_jwt_vct")
    private String sdJwtVct;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "plugin_configurations", columnDefinition = "jsonb")
    private List<Map<String, String>> pluginConfigurations;

    @Column(name = "credential_status_purpose", columnDefinition = "TEXT[]")
    private List<String> credentialStatusPurposes;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "qr_settings", columnDefinition = "jsonb")
    private List<Map<String, Object>> qrSettings;

    @Column(name = "qr_signature_algo")
    private String qrSignatureAlgo;

    // ---- v2 model (1.1.0 migration, docs/design/08-database.md): beside the legacy columns until the 2.0.0 sunset.
    // The v1 config API writes both shapes (ConfigV2Columns); the registry reads the JSONB shape when config_version >= 2.
    @Column(name = "tenant_id", nullable = false)
    private String tenantId = "default";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "format_config", columnDefinition = "jsonb")
    private Map<String, Object> formatConfig;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "signing_config", columnDefinition = "jsonb")
    private Map<String, Object> signingConfig;

    @Column(name = "template_id")
    private String templateId;

    @Column(name = "template_version")
    private Integer templateVersion;

    @Column(name = "issuance_strategy", nullable = false)
    private String issuanceStrategy = "TEMPLATE";

    @Column(name = "data_source_id")
    private String dataSourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "status_config", columnDefinition = "jsonb")
    private Map<String, Object> statusConfig;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "protocol_overrides", columnDefinition = "jsonb")
    private Map<String, Object> protocolOverrides;

    @Column(name = "config_version", nullable = false)
    private Integer configVersion = 1;

    @NotNull
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;

}
