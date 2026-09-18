package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class WellKnownController {

    @Autowired
    private CredentialRegistry credentialRegistry;

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private JwksService jwksService;

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata() {
        return credentialRegistry.issuerMetadata();
    }

    @Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.tenancy.TenantContexts> tenants;

    @Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.core.dto.AuthorizationContext> authorizationContext;

    @Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.utils.DIDDocumentUtil> didDocuments;

    /**
     * The deployment's DID document, or the tenant's when the request resolved to a tenant with its own issuer DID
     * (`certify.tenancy.tenants.<id>.issuer-did`): the same keys, published under the DID the tenant's credentials name.
     */
    @GetMapping(value = "/.well-known/did.json", produces = "application/json")
    public Map<String, Object> getDIDDocument() {
        String tenantDid = tenantDid();
        if (tenantDid != null) {
            io.mosip.certify.utils.DIDDocumentUtil util = didDocuments.getIfAvailable();
            if (util != null) {
                return util.generateDIDDocument(tenantDid);
            }
        }
        return vcIssuanceService.getDIDDocument();
    }

    private String tenantDid() {
        io.mosip.certify.core.dto.AuthorizationContext context = authorizationContext.getIfAvailable();
        io.mosip.certify.tenancy.TenantContexts contexts = tenants.getIfAvailable();
        if (context == null || contexts == null) {
            return null;
        }
        String tenantId = context.getTenantId();
        if (tenantId == null || io.mosip.certify.spi.TenantContext.DEFAULT_TENANT_ID.equals(tenantId)) {
            return null;
        }
        return contexts.forRequest(tenantId, null, null).issuerDid();
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        try {
            Map<String, Object> response = jwksService.getJwks();

            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }

        } catch (Exception e) {
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }
}