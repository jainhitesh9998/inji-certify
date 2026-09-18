package io.mosip.certify.deprecation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Marks {@link DeprecatedEndpoint} handlers as {@code deprecated: true} in the generated OpenAPI document.
 * Only active when springdoc is on the classpath.
 */
@Configuration
@ConditionalOnClass(name = "org.springdoc.core.customizers.OperationCustomizer")
public class DeprecationOpenApiConfig {

    @Bean
    public org.springdoc.core.customizers.OperationCustomizer deprecatedEndpointOperationCustomizer() {
        return (operation, handlerMethod) -> {
            if (DeprecationInterceptor.resolve(handlerMethod) != null) {
                operation.setDeprecated(Boolean.TRUE);
            }
            return operation;
        };
    }
}
