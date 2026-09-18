package io.mosip.certify.oid4vci.d13;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

/** The 0.14.0 credential request (OpenID4VCI draft 13): a format, its selector, one proof. */
@Data
public class D13CredentialRequest {

    @NotBlank(message = ErrorConstants.INVALID_VC_FORMAT)
    private String format;

    @Valid
    @NotNull(message = VCIErrorConstants.INVALID_PROOF)
    private Proof proof;

    @Valid
    private Definition credential_definition;

    private String doctype;

    private Map<String, Object> claims;

    private String vct;

    @Data
    public static class Proof {
        @NotBlank(message = VCIErrorConstants.INVALID_PROOF)
        private String proof_type;
        private String jwt;
        private String cwt;
    }

    @Data
    public static class Definition {
        @JsonProperty("@context")
        private List<@NotBlank(message = VCIErrorConstants.INVALID_CREDENTIAL_REQUEST) String> context;
        private List<@NotBlank(message = VCIErrorConstants.INVALID_CREDENTIAL_REQUEST) String> type;
        private Map<String, Object> credentialSubject;
    }
}
