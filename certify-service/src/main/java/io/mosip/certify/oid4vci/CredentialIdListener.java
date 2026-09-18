package io.mosip.certify.oid4vci;

import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.UnsignedCredential;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * The credential {@code id} the legacy issuance assigns ({@code mosip.certify.data-provider-plugin.id-field-prefix-uri}
 * + UUID) for {@code ldp_vc} documents that have none; the ledger keys entries by it.
 */
@Component
public class CredentialIdListener implements IssuanceListener {

    static final String ID = "id";
    private final String idPrefix;

    public CredentialIdListener(Environment environment) {
        this.idPrefix = environment.getProperty("mosip.certify.data-provider-plugin.id-field-prefix-uri", "");
    }

    @Override
    public UnsignedCredential beforeSign(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        if (idPrefix.isBlank() || !"ldp_vc".equals(credential.format()) || !(credential.document() instanceof Map<?, ?> document) || document.containsKey(ID)) {
            return credential;
        }
        Map<String, Object> withId = new LinkedHashMap<>();
        withId.put(ID, idPrefix + UUID.randomUUID());
        withId.putAll(credential.asMap());
        return credential.withDocument(withId);
    }
}
