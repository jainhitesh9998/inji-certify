package io.mosip.certify.oid4vci.d13;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a handler that shares its path with the compatibility surface and takes over only when the request body is
 * a draft-13 credential request ({@code format} present, no {@code credential_configuration_id}); see
 * {@link D13BodyCondition} and {@link D13BodyBufferFilter}.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface D13Body {}
