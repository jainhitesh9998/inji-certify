package io.mosip.certify.status;

import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.UnsignedCredential;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * {@code status_config.mechanism = TokenStatusList}: an SD-JWT VC payload or an mDoc MSO gains
 * {@code status.status_list = {idx, uri}} (draft-ietf-oauth-status-list sections 6.1 and 6.2), the list being served at
 * {@code uri} as {@code application/statuslist+jwt}.
 */
@Component
public class TokenStatusListProvider implements StatusProvider {

    public static final String MECHANISM = "TokenStatusList";
    static final Set<String> FORMATS = Set.of("dc+sd-jwt", "vc+sd-jwt", "mso_mdoc");

    private final TokenStatusListService lists;

    public TokenStatusListProvider(TokenStatusListService lists) {
        this.lists = lists;
    }

    @Override
    public String mechanism() {
        return MECHANISM;
    }

    @Override
    public boolean supports(String format) {
        return FORMATS.contains(format);
    }

    @Override
    public UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        if (configuration.status().purposes().isEmpty()) {
            return credential;
        }
        TokenStatusListService.Entry entry;
        try {
            entry = lists.allocate(configuration.status().purposes().get(0));
        } catch (RuntimeException e) {
            throw new FormatException("status_list_unavailable", "Could not assign a token status list entry: " + e.getMessage(), e);
        }
        Map<String, Object> document = new LinkedHashMap<>(credential.asMap());
        document.put("status", Map.of("status_list", Map.of("idx", entry.idx(), "uri", entry.uri())));
        return credential.withDocument(document);
    }

    @Override
    public void update(StatusUpdate update) {
        throw new UnsupportedOperationException("Status updates go through /credentials/status and the batch job");
    }
}
