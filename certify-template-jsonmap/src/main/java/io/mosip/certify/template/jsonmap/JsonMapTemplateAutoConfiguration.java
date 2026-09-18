package io.mosip.certify.template.jsonmap;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/** Registers the jsonmap engine wherever this module is on the classpath (CLAUDE.md rule 10). */
@AutoConfiguration
public class JsonMapTemplateAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "jsonMapTemplateEngine")
    public JsonMapTemplateEngine jsonMapTemplateEngine(ObjectMapper objectMapper) {
        return new JsonMapTemplateEngine(objectMapper);
    }
}
