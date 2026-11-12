package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The answer to {@code POST /pre-authorized-data}. {@code credential_offer_uri} carries the
 * {@code openid-credential-offer://} deep link the QR code shows: it holds {@code credential_offer_uri=<url>} when the
 * offer is by reference (the default) and {@code credential_offer=<url-encoded JSON>} when the caller asked for the
 * offer by value, in which case {@code credential_offer} also carries the offer document itself.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PreAuthorizedResponse {
    @JsonProperty("credential_offer_uri")
    private String credentialOfferUri;

    /** The offer itself (OpenID4VCI 1.0 section 4.1.1), present only when the request asked for it by value. */
    @JsonProperty("credential_offer")
    private CredentialOfferResponse credentialOffer;
}
