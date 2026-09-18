package io.mosip.certify.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/** Composite key of {@link CredentialTemplate}: the template id and its version; the tenant is a column, not part of the identity. */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialTemplateId implements Serializable {
    private String id;
    private Integer version;
}
