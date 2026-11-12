package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.core.spi.NonceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Discovery of the new surface: the issuer metadata under its own identifier (same configurations as the
 * compatibility surface, this surface's endpoints) and the nonce endpoint (the shared c_nonce store, so a nonce from
 * either endpoint is valid on either surface).
 */
@RestController
@RequestMapping({"/oid4vci", "/t/{tenant}/oid4vci"}) // the second form serves path-resolved tenants (certify.tenancy.resolver=path)
public class Oid4vciDiscoveryController {

    private final CredentialRegistry registry;
    private final NonceService nonceService;
    private final Oid4vciIssuer issuer;
    private final io.mosip.certify.core.dto.AuthorizationContext authorizationContext;
    private final io.mosip.certify.tenancy.TenantContexts tenants;
    private final TenantIssuerMetadata tenantMetadata;
    private final Oid4vciProperties properties;
    private final Oid4vciIssuerResolver issuers;

    public Oid4vciDiscoveryController(CredentialRegistry registry, NonceService nonceService, Oid4vciIssuer issuer,
                                      io.mosip.certify.core.dto.AuthorizationContext authorizationContext,
                                      io.mosip.certify.tenancy.TenantContexts tenants, TenantIssuerMetadata tenantMetadata, Oid4vciProperties properties,
                                      Oid4vciIssuerResolver issuers) {
        this.registry = registry;
        this.nonceService = nonceService;
        this.issuer = issuer;
        this.authorizationContext = authorizationContext;
        this.tenants = tenants;
        this.tenantMetadata = tenantMetadata;
        this.properties = properties;
        this.issuers = issuers;
    }

    /** The default tenant's document is develop's (goldens) plus this surface's identity; another tenant's is built from the core under its own identifier. */
    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public Object issuerMetadata() {
        CredentialIssuerMetadataDTO legacy = registry.issuerMetadata();
        String tenantId = authorizationContext.getTenantId();
        if (tenantId != null && !io.mosip.certify.spi.TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            io.mosip.certify.spi.TenantContext tenant = tenants.forRequest(tenantId, issuer.identifier(), null);
            return tenantMetadata.document(tenant, issuers.forTenant(tenantId), legacy);
        }
        CredentialIssuerMetadataDTO metadata = new CredentialIssuerMetadataDTO();
        metadata.setCredentialIssuer(issuer.identifier());
        metadata.setAuthorizationServers(legacy.getAuthorizationServers());
        metadata.setCredentialEndpoint(issuer.credentialEndpoint());
        metadata.setNonceEndpoint(issuer.nonceEndpoint());
        metadata.setNotificationEndpoint(issuer.notificationEndpoint());
        if (properties.batch().size() > 1) {
            metadata.setBatchCredentialIssuance(java.util.Map.of("batch_size", properties.batch().size()));
        }
        // OpenID4VCI 1.0 section 12.2.4: the issuer's display is the deployment's (the compatibility document's), inherited
        // as-is; only a document that already carries one keeps its own.
        if (metadata.getDisplay() == null) {
            metadata.setDisplay(legacy.getDisplay());
        }
        metadata.setCredentialConfigurationSupportedDTO(legacy.getCredentialConfigurationSupportedDTO());
        return metadata;
    }

    @PostMapping(value = "/nonce", produces = "application/json")
    public ResponseEntity<NonceResponse> nonce() {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(nonceService.generateNonce());
    }
}
