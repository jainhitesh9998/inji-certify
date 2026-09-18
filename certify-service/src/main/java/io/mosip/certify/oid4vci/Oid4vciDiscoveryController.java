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
@RequestMapping("/oid4vci")
public class Oid4vciDiscoveryController {

    private final CredentialRegistry registry;
    private final NonceService nonceService;
    private final Oid4vciIssuer issuer;
    private final io.mosip.certify.core.dto.AuthorizationContext authorizationContext;
    private final io.mosip.certify.tenancy.TenantContexts tenants;
    private final TenantIssuerMetadata tenantMetadata;

    public Oid4vciDiscoveryController(CredentialRegistry registry, NonceService nonceService, Oid4vciIssuer issuer,
                                      io.mosip.certify.core.dto.AuthorizationContext authorizationContext,
                                      io.mosip.certify.tenancy.TenantContexts tenants, TenantIssuerMetadata tenantMetadata) {
        this.registry = registry;
        this.nonceService = nonceService;
        this.issuer = issuer;
        this.authorizationContext = authorizationContext;
        this.tenants = tenants;
        this.tenantMetadata = tenantMetadata;
    }

    /** The default tenant's document is develop's (goldens); another tenant's is built from the core under its own identifier. */
    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public Object issuerMetadata() {
        CredentialIssuerMetadataDTO legacy = registry.issuerMetadata();
        String tenantId = authorizationContext.getTenantId();
        if (tenantId != null && !io.mosip.certify.spi.TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            io.mosip.certify.spi.TenantContext tenant = tenants.forRequest(tenantId, issuer.identifier(), null);
            Oid4vciIssuer tenantIssuer = issuer.identifier().equals(tenant.issuerIdentifier()) ? issuer : Oid4vciIssuer.derive(tenant.issuerIdentifier(), null);
            return tenantMetadata.document(tenant, tenantIssuer, legacy);
        }
        CredentialIssuerMetadataDTO metadata = new CredentialIssuerMetadataDTO();
        metadata.setCredentialIssuer(issuer.identifier());
        metadata.setAuthorizationServers(legacy.getAuthorizationServers());
        metadata.setCredentialEndpoint(issuer.credentialEndpoint());
        metadata.setNonceEndpoint(issuer.nonceEndpoint());
        metadata.setCredentialConfigurationSupportedDTO(legacy.getCredentialConfigurationSupportedDTO());
        return metadata;
    }

    @PostMapping(value = "/nonce", produces = "application/json")
    public ResponseEntity<NonceResponse> nonce() {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(nonceService.generateNonce());
    }
}
