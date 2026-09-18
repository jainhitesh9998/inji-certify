package io.mosip.certify.oid4vci.d13;

import org.springframework.boot.autoconfigure.web.servlet.WebMvcRegistrations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/** Wires the draft-13 adapter: its typed settings and the body-aware request mapping. */
@Configuration
@EnableConfigurationProperties(D13Properties.class)
public class D13Configuration {

    @Bean
    public WebMvcRegistrations d13WebMvcRegistrations() {
        return new WebMvcRegistrations() {
            @Override
            public RequestMappingHandlerMapping getRequestMappingHandlerMapping() {
                return new D13RequestMappingHandlerMapping();
            }
        };
    }
}
