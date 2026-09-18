package io.mosip.certify.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** A versioned credential template (1.1.0 migration): the decoded text the legacy {@code vc_template} column held as base64. */
@Data
@Entity
@NoArgsConstructor
@IdClass(CredentialTemplateId.class)
@Table(name = "credential_template")
public class CredentialTemplate {

    public static final String ENGINE_VELOCITY = "velocity";
    public static final String MODE_FULL_DOCUMENT = "FULL_DOCUMENT";

    @Id
    @Column(name = "id", nullable = false)
    private String id;

    @Id
    @Column(name = "version", nullable = false)
    private Integer version = 1;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId = "default";

    @Column(name = "engine", nullable = false)
    private String engine;

    @Column(name = "mode", nullable = false)
    private String mode;

    @Column(name = "content", nullable = false, columnDefinition = "TEXT")
    private String content;

    @Column(name = "checksum")
    private String checksum;

    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;
}
