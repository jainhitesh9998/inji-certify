package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/** Registers the mDoc formatter wherever this module is on the classpath (CLAUDE.md rule 10). */
@AutoConfiguration
@EnableConfigurationProperties(MdocProperties.class)
public class MdocAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(MdocFormatter.class)
    public MdocFormatter mdocFormatter(ObjectMapper objectMapper, MdocProperties properties) {
        return new MdocFormatter(objectMapper, properties);
    }
}
