package io.mosip.certify.deprecation;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Registers {@link DeprecationInterceptor} for every handler. */
@Configuration
public class DeprecationConfig implements WebMvcConfigurer {

    private final DeprecationInterceptor deprecationInterceptor;

    public DeprecationConfig(DeprecationInterceptor deprecationInterceptor) {
        this.deprecationInterceptor = deprecationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(deprecationInterceptor);
    }
}
