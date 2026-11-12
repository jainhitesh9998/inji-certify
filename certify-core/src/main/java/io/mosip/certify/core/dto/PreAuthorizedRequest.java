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

    /**
     * The surface the offer targets: {@code oid4vci} names the OpenID4VCI 1.0 surface's identifier in
     * {@code credential_issuer} (so the wallet uses {@code /oid4vci/credential}), {@code legacy} keeps the
     * compatibility identifier. Absent, the deployment's default applies
     * ({@code certify.protocol.oid4vci-v1.offers.default-issuer}, {@code legacy} unless set).
     *
     * <p>Not the token's {@code iss}: an offer does not carry an issuer claim, this only selects which of the two
     * issuer surfaces the offer (and the access token it yields) addresses. The value is matched case-insensitively by
     * {@code OfferSurface.from}, as the configured default is when it binds.
     */
    @Pattern(regexp = "^(?i:oid4vci|legacy)$", message = "issuer must be 'oid4vci' or 'legacy'")
    @JsonProperty("issuer")
    private String issuer;

    /**
     * Return the offer itself ({@code credential_offer}, OpenID4VCI 1.0 section 4.1.1) instead of only a link to it.
     * The {@code openid-credential-offer://} deep link carries the offer URL-encoded either way. Absent, the offer is
     * returned by reference, as before.
     */
    @JsonProperty("offer_by_value")
    private Boolean offerByValue;
}