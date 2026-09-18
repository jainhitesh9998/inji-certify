package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HostTenantResolverTest {

    static final TenancyProperties PROPERTIES = new TenancyProperties(true, "host", Map.of(
            "acme", new TenancyProperties.Tenant(List.of("acme.example.org", "ACME.localhost"), "https://acme.example.org/v1/certify/", "did:web:acme.example.org", "acme"),
            "bare", new TenancyProperties.Tenant(List.of("bare.example.org"), null, null, null)));

    @Test
    void hostNamesTheTenantOrTheDefault() {
        HostTenantResolver resolver = new HostTenantResolver(PROPERTIES);
        assertEquals("acme", resolver.resolve(Map.of("host", "acme.example.org")).tenantId());
        assertEquals("acme", resolver.resolve(Map.of("host", "Acme.Localhost:8090")).tenantId(), "case and port do not matter");
        assertEquals(TenantContext.DEFAULT, resolver.resolve(Map.of("host", "issuer.example.org")));
        assertEquals(TenantContext.DEFAULT, resolver.resolve(Map.of()));
        assertEquals(TenantContext.DEFAULT, resolver.resolve(null));
    }

    @Test
    void tenantContextsApplyTheTenantOverridesOverTheDefaults() {
        TenantContexts contexts = new TenantContexts(PROPERTIES);
        TenantContext acme = contexts.forRequest("acme", "http://localhost:8090/v1/certify", "did:web:localhost");
        assertEquals("acme", acme.tenantId());
        assertEquals("https://acme.example.org/v1/certify", acme.issuerIdentifier(), "trailing slash dropped");
        assertEquals("did:web:acme.example.org", acme.issuerDid());
        assertEquals("acme", acme.keyNamespace());
        TenantContext bare = contexts.forRequest("bare", "http://localhost:8090/v1/certify", "did:web:localhost");
        assertEquals("http://localhost:8090/v1/certify", bare.issuerIdentifier(), "no override, the deployment's identifier");
        assertEquals("did:web:localhost", bare.issuerDid());
        assertNull(bare.keyNamespace());
        TenantContext dflt = contexts.forRequest(null, "http://localhost:8090/v1/certify", null);
        assertEquals(TenantContext.DEFAULT_TENANT_ID, dflt.tenantId());
        assertEquals("http://localhost:8090/v1/certify", contexts.issuerIdentifier("unknown", "http://localhost:8090/v1/certify"));
    }
}
