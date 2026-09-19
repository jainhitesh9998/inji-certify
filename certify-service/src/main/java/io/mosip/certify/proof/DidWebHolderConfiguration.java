package io.mosip.certify.proof;

import io.mosip.certify.oid4vci.Oid4vciProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** {@code did:web} holder keys are resolved only when {@code certify.protocol.oid4vci-v1.did-web-holders.enabled} is set. */
@Configuration
@ConditionalOnProperty(prefix = "certify.protocol.oid4vci-v1.did-web-holders", name = "enabled", havingValue = "true")
public class DidWebHolderConfiguration {

    @Bean
    public DidDocumentFetcher didDocumentFetcher(Oid4vciProperties properties) {
        return DidDocumentFetcher.https(properties.didWebHolders().timeout());
    }

    @Bean
    public DIDwebProofManager didWebProofManager(DidDocumentFetcher fetcher) {
        return new DIDwebProofManager(fetcher);
    }
}
