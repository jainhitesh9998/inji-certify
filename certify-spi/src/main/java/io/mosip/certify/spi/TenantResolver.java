package io.mosip.certify.spi;

import java.util.Map;

/** Decides the tenant of a request from whatever the adapter hands over (host, path, issuer identifier, token). */
@FunctionalInterface
public interface TenantResolver {

    TenantContext resolve(Map<String, Object> requestAttributes);

    /** The single-tenant default. */
    static TenantResolver fixed(TenantContext tenant) {
        return attributes -> tenant;
    }
}
