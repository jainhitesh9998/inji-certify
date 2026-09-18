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
                blank(tenant.issuerIdentifier()) ? pathIdentifier(id, defaultIssuerIdentifier) : tenant.issuerIdentifier().replaceAll("/+$", ""),
                blank(tenant.issuerDid()) ? defaultIssuerDid : tenant.issuerDid(),
                blank(tenant.keyNamespace()) ? null : tenant.keyNamespace());
    }

    /** The tenant's issuer identifier if it overrides the deployment's, else the given default. */
    public String issuerIdentifier(String tenantId, String defaultIssuerIdentifier) {
        return forRequest(tenantId, defaultIssuerIdentifier, null).issuerIdentifier();
    }

    /**
     * A path-resolved tenant without its own issuer identifier lives under {@code {deployment}/t/{tenant}}: the
     * deployment's identifier with the new surface's suffix taken off, so the adapter appends it again.
     */
    private String pathIdentifier(String tenantId, String defaultIssuerIdentifier) {
        if (defaultIssuerIdentifier == null || !TenancyProperties.RESOLVER_PATH.equalsIgnoreCase(properties.resolver())
                || TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            return defaultIssuerIdentifier;
        }
        String base = defaultIssuerIdentifier.replaceAll("/+$", "");
        String suffix = io.mosip.certify.oid4vci.Oid4vciIssuer.SUFFIX;
        if (base.endsWith(suffix)) {
            base = base.substring(0, base.length() - suffix.length());
        }
        return base + PathTenantResolver.PREFIX + tenantId;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
