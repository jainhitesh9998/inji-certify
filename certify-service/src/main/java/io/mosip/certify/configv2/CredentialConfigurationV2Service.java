package io.mosip.certify.configv2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.issuance.FormatterRegistry;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.oid4vci.Oid4vciIssuer;
import io.mosip.certify.registry.JpaConfigurationRegistry;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.CredentialTemplateRepository;
import io.mosip.certify.services.CredentialConfigurationServiceImpl;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.tenancy.TenantContexts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * The v2 configuration API (docs/design/09-api-compatibility.md): rows are written in the JSONB model with every legacy
 * column mirrored, templates are versioned in {@code credential_template}, and a body that carries {@code sampleClaims}
 * is rendered through the core before it is committed, so a broken template never reaches a wallet.
 */
@Slf4j
@Service
public class CredentialConfigurationV2Service {

    static final HolderBinding PREVIEW_HOLDER = HolderBinding.did("did:example:preview-holder", "jwt");

    private final CredentialConfigRepository configurations;
    private final CredentialTemplateRepository templates;
    private final JpaConfigurationRegistry registry;
    private final FormatterRegistry formatters;
    private final Set<String> templateEngines;
    private final Set<String> statusMechanisms;
    private final IssuanceService issuanceService;
    private final CredentialConfigurationServiceImpl legacyService;
    private final TenantContexts tenants;
    private final Oid4vciIssuer issuer;
    private final AuthorizationContext authorizationContext;
    private final CredentialConfigurationV2Mapper mapper;
    private final io.mosip.certify.services.IssuerMetadataCache issuerMetadataCache;

    public CredentialConfigurationV2Service(CredentialConfigRepository configurations, CredentialTemplateRepository templates,
                                            JpaConfigurationRegistry registry, List<CredentialFormatter> formatters, List<TemplateEngine> templateEngines,
                                            List<StatusProvider> statusProviders, IssuanceService issuanceService,
                                            CredentialConfigurationServiceImpl legacyService, TenantContexts tenants, Oid4vciIssuer issuer,
                                            AuthorizationContext authorizationContext, ObjectMapper objectMapper,
                                          io.mosip.certify.services.IssuerMetadataCache issuerMetadataCache) {
        this.issuerMetadataCache = issuerMetadataCache;
        this.configurations = configurations;
        this.templates = templates;
        this.registry = registry;
        this.formatters = new FormatterRegistry(formatters);
        this.templateEngines = templateEngines.stream().map(TemplateEngine::id).collect(Collectors.toUnmodifiableSet());
        this.statusMechanisms = statusProviders.stream().map(StatusProvider::mechanism).collect(Collectors.toUnmodifiableSet());
        this.issuanceService = issuanceService;
        this.legacyService = legacyService;
        this.tenants = tenants;
        this.issuer = issuer;
        this.authorizationContext = authorizationContext;
        this.mapper = new CredentialConfigurationV2Mapper(objectMapper);
    }

    @Transactional
    public CredentialConfigurationV2 create(CredentialConfigurationV2 body) {
        String tenant = tenant();
        if (body.getId() == null || body.getId().isBlank()) {
            throw ConfigV2Exception.invalid("id is required");
        }
        if (body.getTenantId() != null && !body.getTenantId().equals(tenant)) {
            throw ConfigV2Exception.invalid("tenantId must be the tenant of the request (" + tenant + ")");
        }
        if (configurations.findByTenantIdAndCredentialConfigKeyId(tenant, body.getId()).isPresent()) {
            throw new ConfigV2Exception(409, ConfigV2Exception.CONFIGURATION_EXISTS, "A configuration with id " + body.getId() + " exists");
        }
        validate(body, tenant, null);
        CredentialConfig row = new CredentialConfig();
        row.setConfigId(UUID.randomUUID().toString());
        row.setStatus(Constants.ACTIVE);
        row.setCreatedTimes(LocalDateTime.now());
        row.setTenantId(tenant);
        row.setCredentialConfigKeyId(body.getId());
        mapper.apply(body, row, legacyService.protocolDefaults(body.getFormat()));
        storeTemplate(body.getTemplate(), row);
        row = configurations.save(row);
        dryRun(row, body.getSampleClaims());
        log.info("Added credential configuration {} ({}) for tenant {}", row.getCredentialConfigKeyId(), row.getConfigId(), tenant);
        issuerMetadataCache.evict();
        return read(row);
    }

    @Transactional(readOnly = true)
    public CredentialConfigurationV2 get(String id) {
        return read(find(tenant(), id));
    }

    @Transactional(readOnly = true)
    public List<CredentialConfigurationV2> list() {
        return configurations.findByTenantId(tenant()).stream().map(this::read).toList();
    }

    @Transactional
    public CredentialConfigurationV2 update(String id, CredentialConfigurationV2 body) {
        String tenant = tenant();
        CredentialConfig row = find(tenant, id);
        if (body.getId() != null && !body.getId().equals(id)) {
            throw ConfigV2Exception.invalid("id in the body must match the path");
        }
        body.setId(id);
        validate(body, tenant, row);
        mapper.apply(body, row, legacyService.protocolDefaults(body.getFormat()));
        storeTemplate(body.getTemplate(), row);
        row.setUpdatedTimes(LocalDateTime.now());
        row = configurations.save(row);
        dryRun(row, body.getSampleClaims());
        log.info("Updated credential configuration {} ({}) for tenant {}", row.getCredentialConfigKeyId(), row.getConfigId(), tenant);
        issuerMetadataCache.evict();
        return read(row);
    }

    @Transactional
    public void delete(String id) {
        CredentialConfig row = find(tenant(), id);
        configurations.delete(row); // template versions stay: the row can be recreated against them
        log.info("Deleted credential configuration {} ({})", row.getCredentialConfigKeyId(), row.getConfigId());
        issuerMetadataCache.evict();
    }

    @Transactional(readOnly = true)
    public CredentialConfigurationV2.PreviewResponse preview(String id, CredentialConfigurationV2.PreviewRequest request) {
        CredentialConfig row = find(tenant(), id);
        CredentialConfiguration configuration = registry.toConfiguration(row);
        HolderBinding holder = request == null || request.holder() == null ? PREVIEW_HOLDER : holderOf(request.holder());
        Map<String, Object> claims = request == null || request.claims() == null ? Map.of() : request.claims();
        UnsignedCredential unsigned = render(configuration, ClaimSet.of(claims), holder);
        return new CredentialConfigurationV2.PreviewResponse(unsigned.format(), unsigned.document(), unsigned.attributes());
    }

    private void validate(CredentialConfigurationV2 body, String tenant, CredentialConfig existing) {
        String format = body.getFormat();
        if (format == null || format.isBlank() || formatters.forFormat(format).isEmpty()) {
            throw new ConfigV2Exception(400, ConfigV2Exception.UNSUPPORTED_FORMAT, "No formatter for format " + format);
        }
        CredentialConfigurationV2.Signing signing = body.getSigning();
        if (signing == null || signing.getAlias() == null || signing.getAlias().isBlank()) {
            throw ConfigV2Exception.invalid("signing.alias is required");
        }
        if (signing.getAlg() == null || SignatureAlgorithm.fromJose(signing.getAlg()).isEmpty()) {
            throw new ConfigV2Exception(400, ConfigV2Exception.UNSUPPORTED_SIGNATURE_ALGORITHM, "Unknown signature algorithm " + signing.getAlg());
        }
        if (signing.getX5c() != null && !signing.getX5c().isBlank()) {
            try {
                io.mosip.certify.registry.JpaConfigurationRegistry.chainInclusion(signing.getX5c());
            } catch (IllegalStateException e) {
                throw ConfigV2Exception.invalid(e.getMessage());
            }
        }
        Map<String, Object> formatConfig = body.getFormatConfig() == null ? Map.of() : body.getFormatConfig();
        String exclude = existing == null ? null : existing.getConfigId();
        switch (format) {
            case "ldp_vc" -> {
                String context = CredentialConfigurationV2Mapper.join(formatConfig.get("context"));
                String types = CredentialConfigurationV2Mapper.join(formatConfig.get("types"));
                if (context == null || types == null || signing.getCryptosuite() == null || signing.getCryptosuite().isBlank()) {
                    throw ConfigV2Exception.invalid("formatConfig.context, formatConfig.types and signing.cryptosuite are required for ldp_vc");
                }
                configurations.findByTenantIdAndCredentialFormatAndCredentialTypeAndContext(tenant, format, types, context)
                        .filter(other -> !other.getConfigId().equals(exclude))
                        .ifPresent(other -> { throw conflict("types and context", other); });
            }
            case "dc+sd-jwt", "vc+sd-jwt" -> {
                String vct = CredentialConfigurationV2Mapper.str(formatConfig.get("vct"));
                if (vct == null || vct.isBlank()) {
                    throw ConfigV2Exception.invalid("formatConfig.vct is required for " + format);
                }
                configurations.findByTenantIdAndCredentialFormatAndSdJwtVct(tenant, format, vct)
                        .filter(other -> !other.getConfigId().equals(exclude))
                        .ifPresent(other -> { throw conflict("vct", other); });
            }
            case "mso_mdoc" -> {
                String doctype = CredentialConfigurationV2Mapper.str(formatConfig.get("doctype"));
                if (doctype == null || doctype.isBlank()) {
                    throw ConfigV2Exception.invalid("formatConfig.doctype is required for mso_mdoc");
                }
                configurations.findByTenantIdAndCredentialFormatAndDocType(tenant, format, doctype)
                        .filter(other -> !other.getConfigId().equals(exclude))
                        .ifPresent(other -> { throw conflict("doctype", other); });
            }
            default -> { }
        }
        IssuanceStrategy strategy = strategyOf(body.getIssuanceStrategy());
        CredentialConfigurationV2.Template template = body.getTemplate();
        boolean bodyHasTemplate = template != null && template.getContent() != null && !template.getContent().isBlank();
        boolean rowHasTemplate = existing != null && (existing.getTemplateId() != null || (existing.getVcTemplate() != null && !existing.getVcTemplate().isBlank()));
        if (strategy == IssuanceStrategy.TEMPLATE && !bodyHasTemplate && !rowHasTemplate) {
            throw ConfigV2Exception.invalid("template.content is required for the TEMPLATE strategy");
        }
        if (template != null) {
            String engine = template.getEngine() == null ? CredentialTemplate.ENGINE_VELOCITY : template.getEngine();
            if (!templateEngines.contains(engine)) {
                throw new ConfigV2Exception(400, ConfigV2Exception.UNKNOWN_TEMPLATE_ENGINE, "No template engine " + engine + "; available: " + templateEngines);
            }
            if (template.getMode() != null) {
                try {
                    TemplateRef.Mode.valueOf(template.getMode().trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw ConfigV2Exception.invalid("template.mode must be one of " + List.of(TemplateRef.Mode.values()));
                }
            }
        }
        CredentialConfigurationV2.Status status = body.getStatus();
        if (status != null && status.getPurposes() != null && !status.getPurposes().isEmpty()) {
            if (status.getPurposes().size() > 1) {
                throw ConfigV2Exception.invalid("Only one status purpose is supported");
            }
            List<String> allowed = legacyService.protocolDefaults(format).allowedStatusPurposes();
            if (allowed != null && !allowed.isEmpty() && !allowed.containsAll(status.getPurposes())) {
                throw ConfigV2Exception.invalid("Allowed status purposes: " + allowed);
            }
            if (status.getMechanism() != null && !statusMechanisms.isEmpty() && !statusMechanisms.contains(status.getMechanism())) {
                throw ConfigV2Exception.invalid("Unknown status mechanism " + status.getMechanism() + "; available: " + statusMechanisms);
            }
        }
    }

    private static IssuanceStrategy strategyOf(String value) {
        if (value == null || value.isBlank()) {
            return IssuanceStrategy.TEMPLATE;
        }
        try {
            return IssuanceStrategy.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw ConfigV2Exception.invalid("issuanceStrategy must be one of " + List.of(IssuanceStrategy.values()));
        }
    }

    private static ConfigV2Exception conflict(String what, CredentialConfig other) {
        return new ConfigV2Exception(409, ConfigV2Exception.CONFIGURATION_EXISTS,
                "A configuration with the same " + what + " exists: " + other.getCredentialConfigKeyId());
    }

    /** A changed content (or engine or mode) becomes the next version of the row's template; the same content keeps its version. */
    private void storeTemplate(CredentialConfigurationV2.Template template, CredentialConfig row) {
        if (template == null || template.getContent() == null || template.getContent().isBlank()) {
            return;
        }
        String engine = template.getEngine() == null ? CredentialTemplate.ENGINE_VELOCITY : template.getEngine();
        String mode = template.getMode() == null ? CredentialTemplate.MODE_FULL_DOCUMENT : template.getMode().trim().toUpperCase();
        String checksum = DigestUtils.md5DigestAsHex(template.getContent().getBytes(StandardCharsets.UTF_8));
        Optional<CredentialTemplate> latest = templates.findFirstByIdOrderByVersionDesc(row.getConfigId());
        CredentialTemplate stored;
        if (latest.isPresent() && checksum.equals(latest.get().getChecksum()) && engine.equals(latest.get().getEngine()) && mode.equals(latest.get().getMode())) {
            stored = latest.get();
        } else {
            stored = new CredentialTemplate();
            stored.setId(row.getConfigId());
            stored.setVersion(latest.map(t -> t.getVersion() + 1).orElse(1));
            stored.setTenantId(row.getTenantId());
            stored.setEngine(engine);
            stored.setMode(mode);
            stored.setContent(template.getContent());
            stored.setChecksum(checksum);
            stored.setCreatedTimes(LocalDateTime.now());
            stored = templates.save(stored);
        }
        row.setTemplateId(stored.getId());
        row.setTemplateVersion(stored.getVersion());
        // the legacy path renders vc_template with Velocity as a full document; anything else is only for the new core
        boolean legacyRenderable = CredentialTemplate.ENGINE_VELOCITY.equals(engine) && CredentialTemplate.MODE_FULL_DOCUMENT.equals(mode);
        row.setVcTemplate(legacyRenderable ? CredentialConfigurationV2Mapper.encode(template.getContent()) : null);
    }

    private void dryRun(CredentialConfig row, Map<String, Object> sampleClaims) {
        if (sampleClaims == null) {
            return;
        }
        render(registry.toConfiguration(row), ClaimSet.of(sampleClaims), PREVIEW_HOLDER);
    }

    private UnsignedCredential render(CredentialConfiguration configuration, ClaimSet claims, HolderBinding holder) {
        IssuanceContext context = new IssuanceContext(tenants.forRequest(configuration.tenantId(), issuer.identifier(), null),
                Authorization.NONE, List.of(holder), ProtocolVersion.OID4VCI_1_0, "preview-" + UUID.randomUUID(), Instant.now(), Map.of());
        try {
            return issuanceService.preview(configuration, claims, context, holder);
        } catch (RuntimeException e) {
            log.warn("Configuration {} did not render: {}", configuration.id(), e.getMessage());
            throw new ConfigV2Exception(400, ConfigV2Exception.TEMPLATE_RENDER_FAILED, e.getMessage());
        }
    }

    private static HolderBinding holderOf(CredentialConfigurationV2.Holder holder) {
        if (holder.value() == null || holder.value().isBlank()) {
            return PREVIEW_HOLDER;
        }
        String proofType = holder.proofType() == null ? "jwt" : holder.proofType();
        return "JWK".equalsIgnoreCase(holder.kind()) ? HolderBinding.jwk(holder.value(), null, proofType) : HolderBinding.did(holder.value(), proofType);
    }

    private CredentialConfig find(String tenant, String id) {
        return configurations.findByTenantIdAndCredentialConfigKeyId(tenant, id)
                .orElseThrow(() -> new ConfigV2Exception(404, ConfigV2Exception.CONFIGURATION_NOT_FOUND, "No configuration " + id + " for tenant " + tenant));
    }

    private CredentialConfigurationV2 read(CredentialConfig row) {
        CredentialTemplate template = row.getTemplateId() == null || row.getTemplateVersion() == null ? null
                : templates.findByIdAndVersion(row.getTemplateId(), row.getTemplateVersion()).orElse(null);
        return mapper.read(row, template);
    }

    private String tenant() {
        String tenant = authorizationContext.getTenantId();
        return tenant == null || tenant.isBlank() ? "default" : tenant;
    }
}
