package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import org.springframework.stereotype.Component;

/**
 * The {@link TenantContext} an adapter hands to the core for the tenant a request was resolved to: the tenant's own
 * issuer identifier, DID and key namespace when configured, otherwise the adapter's defaults. Every adapter builds its
 * command through this, so a single-tenant deployment sees exactly the defaults it always had.
 */
@Component
public class TenantContexts {

    private final TenancyProperties properties;

    public TenantContexts(TenancyProperties properties) {
        this.properties = properties;
    }

    public TenantContext forRequest(String tenantId, String defaultIssuerIdentifier, String defaultIssuerDid) {
        String id = tenantId == null || tenantId.isBlank() ? TenantContext.DEFAULT_TENANT_ID : tenantId;
        TenancyProperties.Tenant tenant = properties.tenant(id);
        if (tenant == null) {
            return new TenantContext(id, defaultIssuerIdentifier, defaultIssuerDid, null);
        }
        return new TenantContext(id,
                blank(tenant.issuerIdentifier()) ? defaultIssuerIdentifier : tenant.issuerIdentifier().replaceAll("/+$", ""),
                blank(tenant.issuerDid()) ? defaultIssuerDid : tenant.issuerDid(),
                blank(tenant.keyNamespace()) ? null : tenant.keyNamespace());
    }

    /** The tenant's issuer identifier if it overrides the deployment's, else the given default. */
    public String issuerIdentifier(String tenantId, String defaultIssuerIdentifier) {
        return forRequest(tenantId, defaultIssuerIdentifier, null).issuerIdentifier();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
