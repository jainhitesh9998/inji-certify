package io.mosip.certify.template.jsonmap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A template is a JSON document. Every string value may hold placeholders:
 * <ul>
 *   <li>{@code ${name}}: the claim {@code name}; when the whole string is one placeholder the claim's JSON value is
 *       inserted with its type (number, boolean, object, array), otherwise it is interpolated as text;</li>
 *   <li>{@code ${name|fallback}}: the fallback text when the claim is absent; without one a missing claim fails;</li>
 *   <li>{@code ${a.b}}: a nested claim;</li>
 *   <li>{@code ${_issuer}}, {@code ${_holderId}}, {@code ${_validFrom}}, {@code ${_validUntil}}: issuance context;</li>
 *   <li>{@code ${param:name}}: a template parameter from the configuration.</li>
 * </ul>
 * An object entry {@code "$claims": true} spreads every claim into that object (the CLAIMS_ONLY shape); an entry
 * {@code "$claims": ["a", "b"]} spreads only those. Nothing in a template is executed.
 */
public class JsonMapTemplateEngine implements TemplateEngine {

    public static final String ID = "jsonmap";
    public static final String ERROR_TEMPLATE_RENDER = "template_render_failed";
    public static final String ERROR_MISSING_CLAIM = "template_missing_claim";
    static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC); // Constants.UTC_DATETIME_PATTERN, as the legacy issuance writes validFrom/validUntil
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}|]+)(?:\\|([^}]*))?}");
    private static final String SPREAD = "$claims";

    private final ObjectMapper objectMapper;

    public JsonMapTemplateEngine(ObjectMapper objectMapper) {
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
        Map<String, Object> document;
        try {
            document = objectMapper.readValue(templateText(template), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new FormatException(ERROR_TEMPLATE_RENDER, "Template " + template.templateId() + " is not a JSON object: " + e.getMessage(), e);
        }
        Map<String, Object> values = new LinkedHashMap<>(model.claims().claims());
        if (model.tenant() != null) {
            String issuer = model.tenant().issuerDid() != null ? model.tenant().issuerDid() : model.tenant().issuerIdentifier();
            if (issuer != null) {
                values.put("_issuer", issuer);
            }
        }
        if (model.holder() != null && model.holder().isBound()) {
            values.put("_holderId", model.holder().value());
        }
        if (model.validity() != null) {
            if (model.validity().validFrom() != null) {
                values.put("_validFrom", TIMESTAMP.format(model.validity().validFrom()));
            }
            if (model.validity().validUntil() != null) {
                values.put("_validUntil", TIMESTAMP.format(model.validity().validUntil()));
            }
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> rendered = (Map<String, Object>) fill(document, values, model.params(), model.claims().claims());
        return new RenderedDocument(rendered);
    }

    private Object fill(Object node, Map<String, Object> values, Map<String, Object> params, Map<String, Object> claims) {
        if (node instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                if (SPREAD.equals(key)) {
                    spread(entry.getValue(), claims, out);
                } else {
                    out.put(key, fill(entry.getValue(), values, params, claims));
                }
            }
            return out;
        }
        if (node instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) {
                out.add(fill(item, values, params, claims));
            }
            return out;
        }
        if (node instanceof String text) {
            return substitute(text, values, params);
        }
        return node;
    }

    private void spread(Object selector, Map<String, Object> claims, Map<String, Object> out) {
        if (selector instanceof List<?> names) {
            for (Object name : names) {
                String claim = String.valueOf(name);
                if (!claims.containsKey(claim)) {
                    throw new FormatException(ERROR_MISSING_CLAIM, "Claim '" + claim + "' listed in $claims is absent");
                }
                out.put(claim, claims.get(claim));
            }
        } else {
            out.putAll(claims);
        }
    }

    private Object substitute(String text, Map<String, Object> values, Map<String, Object> params) {
        Matcher matcher = PLACEHOLDER.matcher(text);
        if (!matcher.find()) {
            return text;
        }
        // a lone placeholder keeps the value's JSON type
        if (matcher.start() == 0 && matcher.end() == text.length()) {
            return resolve(matcher.group(1).trim(), matcher.group(2), values, params);
        }
        StringBuilder out = new StringBuilder();
        matcher.reset();
        int last = 0;
        while (matcher.find()) {
            out.append(text, last, matcher.start());
            Object value = resolve(matcher.group(1).trim(), matcher.group(2), values, params);
            out.append(value instanceof String s ? s : toJsonText(value));
            last = matcher.end();
        }
        out.append(text.substring(last));
        return out.toString();
    }

    private Object resolve(String name, String fallback, Map<String, Object> values, Map<String, Object> params) {
        Object value;
        if (name.startsWith("param:")) {
            value = params.get(name.substring("param:".length()));
        } else {
            value = path(values, name);
        }
        if (value == null) {
            if (fallback != null) {
                return fallback;
            }
            throw new FormatException(ERROR_MISSING_CLAIM, "Claim '" + name + "' is absent and the template gives no fallback");
        }
        return value;
    }

    private static Object path(Map<String, Object> values, String name) {
        if (values.containsKey(name)) {
            return values.get(name);
        }
        Object current = values;
        for (String segment : name.split("\\.")) {
            if (!(current instanceof Map<?, ?> map) || !map.containsKey(segment)) {
                return null;
            }
            current = map.get(segment);
        }
        return current;
    }

    private String toJsonText(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    /** Configurations store the template base64-encoded; inline templates are plain text. */
    static String templateText(TemplateRef template) {
        String content = template.content().trim();
        if (content.startsWith("{")) {
            return content;
        }
        try {
            return new String(Base64.getDecoder().decode(content), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return content;
        }
    }
}
