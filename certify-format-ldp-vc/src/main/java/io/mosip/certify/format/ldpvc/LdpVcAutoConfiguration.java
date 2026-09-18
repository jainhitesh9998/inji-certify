package io.mosip.certify.format.ldpvc;

import com.apicatalog.jsonld.loader.DocumentLoader;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/** Registers the ldp_vc formatter over the application's JSON-LD {@link DocumentLoader} bean (CLAUDE.md rule 10). */
@AutoConfiguration
public class LdpVcAutoConfiguration {

    @Bean
    @ConditionalOnBean(DocumentLoader.class)
    @ConditionalOnMissingBean(LdpVcFormatter.class)
    public LdpVcFormatter ldpVcFormatter(DocumentLoader documentLoader) {
        return new LdpVcFormatter(documentLoader);
    }
}
