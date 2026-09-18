package io.mosip.certify.format.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/** Registers the SD-JWT formatter wherever this module is on the classpath (CLAUDE.md rule 10). */
@AutoConfiguration
public class SdJwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SdJwtFormatter.class)
    public SdJwtFormatter sdJwtFormatter(ObjectMapper objectMapper) {
        return new SdJwtFormatter(objectMapper);
    }
}
