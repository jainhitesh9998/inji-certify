package io.mosip.certify.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** One issuance on the new surface (1.1.0 migration): what was issued to whom, and whether the wallet reported back. */
@Data
@Entity
@NoArgsConstructor
@Table(name = "issuance_transaction")
public class IssuanceTransaction {

    public static final String STATE_PENDING = "PENDING";
    public static final String STATE_ISSUED = "ISSUED";
    public static final String STATE_DEFERRED = "DEFERRED";
    public static final String STATE_FAILED = "FAILED";
    public static final String STATE_NOTIFIED = "NOTIFIED";

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId = "default";

    @Column(name = "access_token_hash")
    private String accessTokenHash;

    @Column(name = "credential_config_id")
    private String credentialConfigId;

    @Column(name = "protocol_version")
    private String protocolVersion;

    @Column(name = "state", nullable = false)
    private String state;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "holder_bindings", columnDefinition = "jsonb")
    private List<Map<String, Object>> holderBindings;

    @Column(name = "notification_id")
    private String notificationId;

    @Column(name = "credential_ids", columnDefinition = "TEXT[]")
    private List<String> credentialIds;

    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
}
