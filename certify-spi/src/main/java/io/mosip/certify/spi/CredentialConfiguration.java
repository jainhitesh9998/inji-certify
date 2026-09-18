package io.mosip.certify.spi;

import java.util.Map;
import java.util.Objects;

/**
 * The domain view of one credential configuration, independent of any protocol version or storage shape
 * (docs/design/05-target-architecture.md). Adapters render it into their metadata; the core issues from it.
 *
 * @param tenantId          {@link TenantContext#DEFAULT_TENANT_ID} until multi-tenancy is enabled
 * @param id                the stable {@code credential_configuration_id}
 * @param scope             OAuth scope that authorizes this configuration
 * @param format            canonical formatter id ({@code ldp_vc}, {@code dc+sd-jwt}, {@code mso_mdoc}, ...)
 * @param formatConfig      typed, format-specific settings
 * @param template          how claims are rendered, or {@link TemplateRef#NONE}
 * @param signing           key, algorithm, suite and header policy
 * @param strategy          how the unsigned credential is obtained
 * @param dataSourceId      the {@link CredentialDataSource#id()} or {@link ExternalIssuer#id()} used, or {@code null} for the default
 * @param status            status mechanism, or {@link StatusConfig#NONE}
 * @param display           wallet-facing metadata
 * @param protocolOverrides per-protocol metadata fragments that override the rendered defaults
 */
public record CredentialConfiguration(String tenantId, String id, String scope, String format, FormatConfig formatConfig,
                                      TemplateRef template, SigningConfig signing, IssuanceStrategy strategy, String dataSourceId,
                                      StatusConfig status, DisplayConfig display,
                                      Map<ProtocolVersion, Map<String, Object>> protocolOverrides) {

    public CredentialConfiguration {
        tenantId = tenantId == null ? TenantContext.DEFAULT_TENANT_ID : tenantId;
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(signing, "signing");
        template = template == null ? TemplateRef.NONE : template;
        strategy = strategy == null ? IssuanceStrategy.TEMPLATE : strategy;
        status = status == null ? StatusConfig.NONE : status;
        display = display == null ? DisplayConfig.NONE : display;
        protocolOverrides = protocolOverrides == null ? Map.of() : Map.copyOf(protocolOverrides);
    }

    public boolean requiresHolderBinding() {
        return strategy != IssuanceStrategy.SUPPLIED;
    }
}
