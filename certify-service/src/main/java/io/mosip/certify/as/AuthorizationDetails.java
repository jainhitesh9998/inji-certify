package io.mosip.certify.as;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The {@code authorization_details} parameter (RFC 9396 as OpenID4VCI 1.0 section 5.1.1 uses it): a JSON array of {@code openid_credential} entries. */
final class AuthorizationDetails {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AuthorizationDetails() {}

    static List<String> credentialConfigurationIds(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        List<Map<String, Object>> entries;
        try {
            entries = MAPPER.readValue(json, new TypeReference<List<Map<String, Object>>>() {});
        } catch (Exception e) {
            throw new AsException(400, "invalid_request", "authorization_details is not a JSON array: " + e.getMessage());
        }
        List<String> ids = new ArrayList<>();
        for (Map<String, Object> entry : entries) {
            if (!AuthorizationCodeService.AUTHORIZATION_DETAILS_TYPE.equals(entry.get("type"))) {
                throw new AsException(400, "invalid_request", "authorization_details entries must be of type openid_credential");
            }
            Object id = entry.get("credential_configuration_id");
            if (id == null || id.toString().isBlank()) {
                throw new AsException(400, "invalid_request", "authorization_details entries must name credential_configuration_id");
            }
            ids.add(id.toString());
        }
        return ids;
    }
}
