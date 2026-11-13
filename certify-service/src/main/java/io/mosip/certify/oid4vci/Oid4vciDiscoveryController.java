package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.core.spi.NonceService;
import org.springframework.http.MediaType;
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
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;

    public Oid4vciDiscoveryController(CredentialRegistry registry, NonceService nonceService, Oid4vciIssuer issuer,
                                      io.mosip.certify.core.dto.AuthorizationContext authorizationContext,
                                      io.mosip.certify.tenancy.TenantContexts tenants, TenantIssuerMetadata tenantMetadata, Oid4vciProperties properties,
                                      Oid4vciIssuerResolver issuers, com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.registry = registry;
        this.nonceService = nonceService;
        this.issuer = issuer;
        this.authorizationContext = authorizationContext;
        this.tenants = tenants;
        this.tenantMetadata = tenantMetadata;
        this.properties = properties;
        this.issuers = issuers;
    }

    /**
     * The default tenant's document is develop's configurations plus this surface's identity; another tenant's is built
     * from the core under its own identifier. Both are finished by {@link Oid4vciMetadataDocument}: no null members,
     * claims in display order (OpenID4VCI 1.0 section 12.2.4); the compatibility documents keep their bytes.
     *
     * <p>The document is always the unsigned {@code application/json} form, whatever the request's {@code Accept}
     * header says. OpenID4VCI 1.0 section 12.2.2 permits that form and a signed {@code application/jwt}, and requires the
     * response's {@code Content-Type} to name what is returned; it does not let a wallet that prefers the signed form
     * (Talao asks for it) turn the metadata into a refusal. The {@code Content-Type} is therefore set explicitly rather
     * than declared with {@code produces = application/json}, which answered 406 to any other {@code Accept}.
     */
    @GetMapping("/.well-known/openid-credential-issuer")
    public ResponseEntity<Object> issuerMetadata() {
        CredentialIssuerMetadataDTO legacy = registry.issuerMetadata();
        String tenantId = authorizationContext.getTenantId();
        if (tenantId != null && !io.mosip.certify.spi.TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            io.mosip.certify.spi.TenantContext tenant = tenants.forRequest(tenantId, issuer.identifier(), null);
            java.util.List<io.mosip.certify.spi.CredentialConfiguration> configurations = tenantMetadata.configurations(tenantId);
            return asJson(Oid4vciMetadataDocument.finish(objectMapper.valueToTree(tenantMetadata.document(tenant, issuers.forTenant(tenantId), legacy, configurations)),
                    TenantIssuerMetadata.claimOrders(configurations)));
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
        // OpenID4VCI 1.0 section 12.2.4: the issuer display is the deployment's (the compatibility document's), inherited
        // as-is. This surface has no display of its own, so there is nothing to prefer over it.
        metadata.setDisplay(legacy.getDisplay());
        metadata.setCredentialConfigurationSupportedDTO(legacy.getCredentialConfigurationSupportedDTO());
        return asJson(Oid4vciMetadataDocument.finish(objectMapper.valueToTree(metadata), tenantMetadata.defaultClaimOrders()));
    }

    /** The one media type this surface publishes (section 12.2.2): set on the response, so no {@code Accept} negotiates it away. */
    private static ResponseEntity<Object> asJson(Object document) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(document);
    }

    @PostMapping(value = "/nonce", produces = "application/json")
    public ResponseEntity<NonceResponse> nonce() {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(nonceService.generateNonce());
    }
}
