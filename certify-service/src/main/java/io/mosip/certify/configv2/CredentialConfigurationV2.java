package io.mosip.certify.configv2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * The v2 configuration model: the 1.1.0 JSONB columns as the API sees them (docs/design/08-database.md). The read-only
 * fields at the end are filled by the service; {@code sampleClaims} is write-only and drives the dry run at save time.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationV2 {

    private String id;
    private String tenantId;
    private String scope;
    private String format;
    /** The format's own settings: {@code context}, {@code types}, {@code claims} for ldp_vc; {@code vct}, {@code sdClaims}, {@code sdJwtClaims}; {@code doctype}, {@code mdocClaims}. */
    private Map<String, Object> formatConfig;
    private Signing signing;
    private Template template;
    private String issuanceStrategy;
    private String dataSourceId;
    private Status status;
    private Display display;
    private Protocol protocol;
    private Qr qr;
    private List<Map<String, String>> pluginConfigurations;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Map<String, Object> sampleClaims;

    private String configId;
    private Boolean active;
    private Integer configVersion;
    private LocalDateTime createdTimes;
    private LocalDateTime updatedTimes;

    /** {@code provider:alias} as the core's {@code KeyRef}; keymanager aliases are {@code APP_ID/REF_ID}. */
    @Data
    public static class Signing {
        private String provider;
        private String alias;
        private String alg;
        private String cryptosuite;
        private String didUrl;
        /** How much of the key's chain the SD-JWT {@code x5c} and mDoc {@code x5chain} carry: {@code full}, {@code leaf}, {@code without-anchor} (HAIP) or {@code none}; the formatter's default when absent. */
        private String x5c;
    }

    /** Template text as stored in {@code credential_template}; a changed content saves the next version. */
    @Data
    public static class Template {
        private String engine;
        private String mode;
        private String content;
        private Integer version;
    }

    @Data
    public static class Status {
        private String mechanism;
        private List<String> purposes;
    }

    @Data
    public static class Display {
        private List<Map<String, Object>> display;
        private List<String> order;
    }

    /** What the issuer metadata advertises for this configuration; the deployment defaults apply when absent. */
    @Data
    public static class Protocol {
        private List<String> cryptographicBindingMethodsSupported;
        private List<String> credentialSigningAlgValuesSupported;
        private Map<String, Object> proofTypesSupported;
        private Map<String, Object> overrides;
    }

    @Data
    public static class Qr {
        private List<Map<String, Object>> settings;
        private String signatureAlgo;
    }

    public record PreviewRequest(Map<String, Object> claims, Holder holder) {}

    public record Holder(String kind, String value, String proofType) {}

    public record PreviewResponse(String format, Object credential, Map<String, Object> attributes) {}
}
