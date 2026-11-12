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
     * The tenant that created an {@code oid4vci} offer. That code may only be exchanged through the same tenant's token
     * endpoint. {@code null} for a {@code legacy} offer, which is tenant-agnostic and redeemed anywhere, and for an
     * {@code oid4vci} entry written before offers were bound (that build was never released), which belongs to
     * {@code default}.
     */
    private String tenantId;
    /**
     * The audience resolved when an {@code oid4vci} offer was created (the tenant's credential endpoint). {@code null}
     * for a {@code legacy} offer and for an entry written before this field existed: both keep the configured
     * {@code mosip.certify.oauth.access-token.audience}, exactly as they did before the surface existed.
     */
    private String audience;
    private long createdAt;
    private long expiresAt;
}
