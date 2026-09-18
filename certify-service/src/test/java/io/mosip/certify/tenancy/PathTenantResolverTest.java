package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PathTenantResolverTest {

    static final TenancyProperties PROPERTIES = new TenancyProperties(true, "path",
            Map.of("acme", new TenancyProperties.Tenant(List.of(), null, "did:web:acme.example", null, List.of(), List.of())));

    @Test
    void theSegmentAfterTIsTheTenant() {
        assertEquals("acme", PathTenantResolver.tenantOf("/v1/certify/t/acme/oid4vci/credential"));
        assertEquals("acme", PathTenantResolver.tenantOf("/t/acme"));
        assertNull(PathTenantResolver.tenantOf("/v1/certify/oid4vci/credential"));
        assertNull(PathTenantResolver.tenantOf("/v1/certify/t/"));
    }

    @Test
    void onlyConfiguredTenantsResolveEverythingElseIsTheDefault() {
        PathTenantResolver resolver = new PathTenantResolver(PROPERTIES);
        assertEquals("acme", resolver.resolve(Map.of(PathTenantResolver.ATTRIBUTE_PATH, "/v1/certify/t/acme/oid4vci/nonce")).tenantId());
        assertEquals(TenantContext.DEFAULT, resolver.resolve(Map.of(PathTenantResolver.ATTRIBUTE_PATH, "/v1/certify/t/nobody/oid4vci/nonce")));
        assertEquals(TenantContext.DEFAULT, resolver.resolve(Map.of(PathTenantResolver.ATTRIBUTE_PATH, "/v1/certify/oid4vci/nonce")));
        assertEquals(TenantContext.DEFAULT, resolver.resolve(Map.of()));
    }
}
