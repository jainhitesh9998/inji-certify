package io.mosip.certify.oid4vci;

import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.UnsignedCredential;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bitstring Status List entries for {@code ldp_vc} through today's status-list service (same lists, same indices,
 * same {@code credentialStatus} shape). As on the compatibility surface, only VC 2.0 documents get an entry.
 */
@Component
public class BitstringStatusProvider implements StatusProvider {

    public static final String MECHANISM = "BitstringStatusList";
    static final String VCDM2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    static final String CREDENTIAL_STATUS = "credentialStatus";

    private final StatusListCredentialService statusLists;

    public BitstringStatusProvider(StatusListCredentialService statusLists) {
        this.statusLists = statusLists;
    }

    @Override
    public String mechanism() {
        return MECHANISM;
    }

    @Override
    public boolean supports(String format) {
        return "ldp_vc".equals(format);
    }

    @Override
    public UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        Map<String, Object> document = credential.asMap();
        Object contexts = document.get("@context");
        boolean vc2 = contexts instanceof List<?> list && list.stream().anyMatch(VCDM2_CONTEXT::equals);
        if (!vc2 || configuration.status().purposes().isEmpty()) {
            return credential;
        }
        JSONObject json = new JSONObject(document);
        try {
            statusLists.addCredentialStatus(json, configuration.status().purposes().get(0));
        } catch (RuntimeException e) {
            throw new FormatException("status_list_unavailable", "Could not assign a status list entry: " + e.getMessage(), e);
        }
        Map<String, Object> withStatus = new LinkedHashMap<>(document);
        withStatus.put(CREDENTIAL_STATUS, json.getJSONObject(CREDENTIAL_STATUS).toMap());
        return credential.withDocument(withStatus);
    }

    @Override
    public void update(StatusUpdate update) {
        throw new UnsupportedOperationException("Status updates go through /credentials/status until the StatusProvider covers them (P5)");
    }
}
