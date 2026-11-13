package io.mosip.certify.as;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The {@code authorization_details} parameter (RFC 9396 as OpenID4VCI 1.0 section 5.1.1 uses it): a JSON array of
 * {@code openid_credential} entries.
 *
 * <p>Every entry is validated, and the value is bounded, because the PAR endpoint is unauthenticated and stores what it
 * is given: a request may carry {@code scope} <em>and</em> {@code authorization_details}, and the details then select
 * nothing, but they are still stored and echoed into the pushed request. Unbounded or unvalidated input there is a way
 * to fill the cache with junk (F-21 review round 1). A refusal is RFC 9126 {@code invalid_request}.
 */
final class AuthorizationDetails {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The longest {@code authorization_details} value a pushed request may carry (the entries are ids, not documents). */
    static final int MAX_LENGTH = 4096;

    /** The most entries one request may name. */
    static final int MAX_ENTRIES = 20;

    private AuthorizationDetails() {}

    static List<String> credentialConfigurationIds(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        if (json.length() > MAX_LENGTH) {
            throw new AsException(400, "invalid_request",
                    "authorization_details is longer than " + MAX_LENGTH + " characters");
        }
        List<Map<String, Object>> entries;
        try {
            entries = MAPPER.readValue(json, new TypeReference<List<Map<String, Object>>>() {});
        } catch (Exception e) {
            throw new AsException(400, "invalid_request", "authorization_details is not a JSON array: " + e.getMessage());
        }
        if (entries.size() > MAX_ENTRIES) {
            throw new AsException(400, "invalid_request",
                    "authorization_details names more than " + MAX_ENTRIES + " entries");
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
