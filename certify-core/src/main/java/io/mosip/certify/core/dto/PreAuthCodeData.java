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
    /**
     * The tenant that created the offer. The code may only be exchanged through that tenant's token endpoint; {@code null}
     * (an entry written before this field existed) skips the check, as those entries predate any per-tenant audience.
     */
    private String tenantId;
    /**
     * The audience resolved when the offer was created (the targeted surface's credential endpoint for {@code oid4vci},
     * the configured {@code mosip.certify.oauth.access-token.audience} for {@code legacy}). {@code null} for an entry
     * written before this field existed, which keeps the legacy audience fallback.
     */
    private String audience;
    private long createdAt;
    private long expiresAt;
}
