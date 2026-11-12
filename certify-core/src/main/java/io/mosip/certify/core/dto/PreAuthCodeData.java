package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PreAuthCodeData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String credentialConfigurationId;
    private Map<String, Object> claims;
    /** The access token subject the offer named, else null (the claims JSON is the subject then). */
    private String subject;
    private String txnCode;
    /** The surface the offer targeted ({@code oid4vci} or {@code legacy}): the access token is addressed to its endpoint. */
    private String issuer;
    private long createdAt;
    private long expiresAt;
}
