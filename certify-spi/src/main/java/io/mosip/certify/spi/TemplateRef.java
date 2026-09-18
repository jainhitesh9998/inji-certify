package io.mosip.certify.spi;

import java.util.Map;

/**
 * Which template renders the claims of a configuration and how.
 *
 * @param engine     {@link TemplateEngine#id()}, e.g. {@code velocity}
 * @param templateId identifier in the template store, or {@code null} when {@code content} is inline
 * @param version    template version, or {@code null} for the current one
 * @param mode       whether the template produces the whole document or only the claims
 * @param content    inline template text (today's {@code vc_template}), or {@code null} when stored by id
 * @param params     engine parameters (today's {@code envConfigs})
 */
public record TemplateRef(String engine, String templateId, Integer version, Mode mode, String content, Map<String, Object> params) {

    public enum Mode { FULL_DOCUMENT, CLAIMS_ONLY, NONE }

    public static final TemplateRef NONE = new TemplateRef(null, null, null, Mode.NONE, null, Map.of());

    public TemplateRef {
        mode = mode == null ? Mode.FULL_DOCUMENT : mode;
        params = params == null ? Map.of() : Map.copyOf(params);
    }

    public static TemplateRef inline(String engine, String content, Mode mode) {
        return new TemplateRef(engine, null, null, mode, content, Map.of());
    }
}
