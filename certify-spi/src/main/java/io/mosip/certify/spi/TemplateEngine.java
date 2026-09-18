package io.mosip.certify.spi;

import java.util.Map;
import java.util.Set;

/** Renders claims into a document (Velocity today; a JSON mapping engine later). Never reads configuration itself. */
public interface TemplateEngine {

    String id();

    Set<TemplateRef.Mode> modes();

    RenderedDocument render(TemplateRef template, TemplateModel model);

    /** Immutable, documented rendering input; replaces the ad-hoc map of {@code _}-prefixed keys. */
    record TemplateModel(ClaimSet claims, TenantContext tenant, HolderBinding holder, Validity validity,
                         CredentialConfiguration configuration, Map<String, Object> params) {}

    record Validity(java.time.Instant validFrom, java.time.Instant validUntil) {}

    /** The rendered JSON document as a map (engines parse their own output). */
    record RenderedDocument(Map<String, Object> document) {}
}
