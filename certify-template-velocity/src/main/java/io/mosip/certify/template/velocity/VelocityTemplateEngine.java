package io.mosip.certify.template.velocity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * {@link TemplateEngine} over Velocity for the new issuance core. The model reaches the template the way today's
 * templates expect it: every claim by name, {@code _issuer}, {@code _holderId}, {@code validFrom}/{@code validUntil}
 * (also as {@code _validFrom}/{@code _validUntil}), the template's own params, and the two tools. The rendered text
 * must be a JSON object.
 */
public class VelocityTemplateEngine implements TemplateEngine {

    public static final String ID = "velocity";
    public static final String ERROR_TEMPLATE_RENDER = "template_render_failed";
    /** The timestamp form Certify has always written into credentials. */
    static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC); // Constants.UTC_DATETIME_PATTERN, as the legacy issuance writes validFrom/validUntil

    private final VelocityRenderer renderer;
    private final ObjectMapper objectMapper;

    public VelocityTemplateEngine(VelocityRenderer renderer, ObjectMapper objectMapper) {
        this.renderer = renderer;
        this.objectMapper = objectMapper;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Set<TemplateRef.Mode> modes() {
        return Set.of(TemplateRef.Mode.FULL_DOCUMENT, TemplateRef.Mode.CLAIMS_ONLY);
    }

    @Override
    public RenderedDocument render(TemplateRef template, TemplateModel model) {
        if (template.content() == null || template.content().isBlank()) {
            throw new FormatException(ERROR_TEMPLATE_RENDER, "Template " + template.templateId() + " has no content");
        }
        Map<String, Object> parameters = new HashMap<>(model.claims().claims());
        parameters.putAll(model.params());
        String issuer = issuerOf(model);
        if (issuer != null) {
            parameters.put("_issuer", issuer);
        }
        if (model.holder() != null && model.holder().isBound()) {
            parameters.put("_holderId", model.holder().value());
        }
        if (model.validity() != null) {
            if (model.validity().validFrom() != null) {
                String validFrom = TIMESTAMP.format(model.validity().validFrom());
                parameters.put("validFrom", validFrom);
                parameters.put("_validFrom", validFrom);
            }
            if (model.validity().validUntil() != null) {
                String validUntil = TIMESTAMP.format(model.validity().validUntil());
                parameters.put("validUntil", validUntil);
                parameters.put("_validUntil", validUntil);
            }
        }
        String rendered = renderer.evaluate(templateText(template), parameters, String.valueOf(template.templateId()));
        try {
            return new RenderedDocument(objectMapper.readValue(rendered, new TypeReference<Map<String, Object>>() {}));
        } catch (Exception e) {
            throw new FormatException(ERROR_TEMPLATE_RENDER, "Template " + template.templateId() + " did not render a JSON object: " + e.getMessage(), e);
        }
    }

    /** The tenant's issuer DID or identifier, else the configuration's {@code didUrl} template parameter (legacy rows). */
    static String issuerOf(TemplateModel model) {
        if (model.tenant() != null) {
            if (model.tenant().issuerDid() != null) {
                return model.tenant().issuerDid();
            }
            if (model.tenant().issuerIdentifier() != null) {
                return model.tenant().issuerIdentifier();
            }
        }
        Object didUrl = model.params().get("didUrl");
        return didUrl == null || String.valueOf(didUrl).isBlank() ? null : String.valueOf(didUrl);
    }

    /** Configurations store the template base64-encoded; inline templates are plain text. */
    static String templateText(TemplateRef template) {
        String content = template.content().trim();
        if (content.startsWith("{") || content.startsWith("[")) {
            return content;
        }
        try {
            return new String(Base64.getDecoder().decode(content), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return content;
        }
    }
}
