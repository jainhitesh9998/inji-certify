package io.mosip.certify.as;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

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

    /** Strict about what follows the array: {@code [...]x} is not a JSON array, it is a malformed value. */
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    /** The longest {@code authorization_details} value a pushed request may carry (the entries are ids, not documents). */
    static final int MAX_LENGTH = 4096;

    /** The most entries one request may name. */
    static final int MAX_ENTRIES = 20;

    private AuthorizationDetails() {}

    /**
     * The {@code credential_configuration_id} of every entry. RFC 9396 section 2 makes the parameter a JSON array of
     * objects, each with a string {@code type}; OpenID4VCI 1.0 section 5.1.1 makes {@code type} {@code openid_credential}
     * and {@code credential_configuration_id} a string. Anything else - {@code null}, {@code [null]}, an entry that is
     * not an object, an id that is a number or an object - is {@code invalid_request} (F-21 review round 2: those were a
     * NullPointerException, a 500, or an id coerced through {@code toString()}).
     */
    static List<String> credentialConfigurationIds(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        if (json.length() > MAX_LENGTH) {
            throw invalid("authorization_details is longer than " + MAX_LENGTH + " characters");
        }
        JsonNode entries;
        try {
            entries = MAPPER.readTree(json);
        } catch (Exception e) {
            throw invalid("authorization_details is not JSON: " + e.getMessage());
        }
        if (entries == null || !entries.isArray()) {
            throw invalid("authorization_details must be a JSON array of objects");
        }
        if (entries.size() > MAX_ENTRIES) {
            throw invalid("authorization_details names more than " + MAX_ENTRIES + " entries");
        }
        List<String> ids = new ArrayList<>();
        for (JsonNode entry : entries) {
            if (!entry.isObject()) {
                throw invalid("authorization_details entries must be JSON objects");
            }
            JsonNode type = entry.get("type");
            if (type == null || !type.isTextual() || !AuthorizationCodeService.AUTHORIZATION_DETAILS_TYPE.equals(type.textValue())) {
                throw invalid("authorization_details entries must be of type openid_credential");
            }
            JsonNode id = entry.get("credential_configuration_id");
            if (id == null || !id.isTextual() || id.textValue().isBlank()) {
                throw invalid("authorization_details entries must name credential_configuration_id as a string");
            }
            ids.add(id.textValue());
        }
        return ids;
    }

    private static AsException invalid(String description) {
        return new AsException(400, "invalid_request", description);
    }
}
