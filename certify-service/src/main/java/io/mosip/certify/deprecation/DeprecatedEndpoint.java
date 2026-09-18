package io.mosip.certify.deprecation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an HTTP handler (or a whole controller) as deprecated.
 *
 * <p>{@link DeprecationInterceptor} then answers every call with {@code Deprecation} (RFC 9745),
 * {@code Sunset} (RFC 8594) and {@code Link} headers, counts it under the Micrometer meter
 * {@code certify.deprecated.calls{endpoint=name}}, logs at most once per interval, and honours the
 * kill switch {@code mosip.certify.deprecated.<name>.enabled=false} by answering {@code 410 Gone}.
 * See docs/design/09-api-compatibility.md.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface DeprecatedEndpoint {

    /** Stable identifier used in the property key, the metric tag and the release notes, e.g. {@code issuance-vd11}. */
    String name();

    /** ISO-8601 date the deprecation was announced; becomes the {@code Deprecation} header value. */
    String since();

    /** ISO-8601 date after which the endpoint may be removed; empty means not scheduled yet. Becomes {@code Sunset}. */
    String sunset() default "";

    /** Replacement endpoint (absolute URL or path) or a short description; advertised as a {@code successor-version} link when it is a URL. */
    String replacement() default "";

    /** Documentation URL for this deprecation; defaults to {@code mosip.certify.deprecation.docs-url}. */
    String docs() default "";
}
