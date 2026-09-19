package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.*;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Request DTO for Pre-Authorized Code generation
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PreAuthorizedRequest {
    @NotBlank(message = "Credential configuration ID is required")
    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    /** The identity data the offer carries; required unless {@code subject} names a record the data provider resolves. */
    @JsonProperty("claims")
    private Map<String, Object> claims;

    /**
     * The subject identifier the data provider resolves (the CSV row id, the individual id): becomes the access
     * token's {@code sub}, as an authorization server would set it, so plugins that look the record up by
     * {@code sub} work in the pre-authorized code flow too.
     */
    @JsonProperty("subject")
    private String subject;

    /** Bean validation keeps refusing an offer that carries neither claims nor a subject. */
    @com.fasterxml.jackson.annotation.JsonIgnore
    @jakarta.validation.constraints.AssertTrue(message = "Claims are required")
    public boolean isClaimsOrSubjectPresent() {
        return (claims != null && !claims.isEmpty()) || (subject != null && !subject.isBlank());
    }

    @Min(value = 60, message = "Minimum expiry is 60 seconds")
    @Max(value = 86400, message = "Maximum expiry is 24 hours")
    @JsonProperty("expires_in")
    private Integer expiresIn;

    @Pattern(regexp = "^[A-Za-z0-9]{4,8}$", message = "Transaction code must be 4-8 alphanumeric characters")
    @JsonProperty("tx_code")
    private String txCode;
}