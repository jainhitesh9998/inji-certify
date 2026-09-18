package io.mosip.certify.spi;

import java.util.Objects;

/**
 * Who the request belongs to. Single-tenant deployments always see {@link #DEFAULT}; a {@link TenantResolver}
 * produces others once multi-tenancy is switched on (docs/design/05-target-architecture.md).
 *
 * @param tenantId         discriminator stored beside every tenant-scoped row
 * @param issuerIdentifier the {@code credential_issuer} value for this tenant
 * @param issuerDid        the DID the tenant signs W3C credentials with, or {@code null}
 * @param keyNamespace     prefix or namespace the key provider uses to tell tenant keys apart, or {@code null}
 */
public record TenantContext(String tenantId, String issuerIdentifier, String issuerDid, String keyNamespace) {

    public static final String DEFAULT_TENANT_ID = "default";

    public static final TenantContext DEFAULT = new TenantContext(DEFAULT_TENANT_ID, null, null, null);

    public TenantContext {
        Objects.requireNonNull(tenantId, "tenantId");
    }

    public static TenantContext defaultTenant(String issuerIdentifier, String issuerDid) {
        return new TenantContext(DEFAULT_TENANT_ID, issuerIdentifier, issuerDid, null);
    }
}
