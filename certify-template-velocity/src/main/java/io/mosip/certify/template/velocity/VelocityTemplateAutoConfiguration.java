package io.mosip.certify.template.velocity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/** Registers the Velocity renderer and the SPI engine wherever this module is on the classpath (CLAUDE.md rule 10). */
@AutoConfiguration
public class VelocityTemplateAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public VelocityRenderer velocityRenderer() {
        return new VelocityRenderer();
    }

    @Bean
    @ConditionalOnMissingBean(name = "velocityTemplateEngine")
    public VelocityTemplateEngine velocityTemplateEngine(VelocityRenderer renderer, ObjectMapper objectMapper) {
        return new VelocityTemplateEngine(renderer, objectMapper);
    }
}
