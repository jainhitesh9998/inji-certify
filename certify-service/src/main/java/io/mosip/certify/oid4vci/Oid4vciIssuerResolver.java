package io.mosip.certify.oid4vci;

import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.tenancy.TenantContexts;
import org.springframework.stereotype.Component;

/**
 * The OpenID4VCI 1.0 surface's Credential Issuer Identifier for the tenant a request belongs to: the deployment's
 * {@code /oid4vci} identifier for {@code default}, a tenant's own identifier with this surface's suffix for a tenant that
 * configures one. Every adapter that has to name the surface (the discovery document, an offer's
 * {@code credential_issuer}) answers with this, so a wallet following an offer lands on the document it read.
 */
@Component
public class Oid4vciIssuerResolver {

    private final Oid4vciIssuer issuer;
    private final TenantContexts tenants;

    public Oid4vciIssuerResolver(Oid4vciIssuer issuer, TenantContexts tenants) {
        this.issuer = issuer;
        this.tenants = tenants;
    }

    public Oid4vciIssuer forTenant(String tenantId) {
        if (tenantId == null || TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            return issuer;
        }
        TenantContext tenant = tenants.forRequest(tenantId, issuer.identifier(), null);
        return issuer.identifier().equals(tenant.issuerIdentifier())
                ? issuer
                : Oid4vciIssuer.derive(tenant.issuerIdentifier(), null);
    }
}
