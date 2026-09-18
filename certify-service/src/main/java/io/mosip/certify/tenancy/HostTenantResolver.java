package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.TenantResolver;

import java.util.Locale;
import java.util.Map;

/** The request host (the {@code Host} header, port dropped) names the tenant; an unknown host is the default tenant. */
public final class HostTenantResolver implements TenantResolver {

    public static final String ATTRIBUTE_HOST = "host";

    private final Map<String, String> tenantByHost;

    public HostTenantResolver(TenancyProperties properties) {
        this.tenantByHost = new java.util.HashMap<>();
        if (properties.tenants() != null) {
            properties.tenants().forEach((tenantId, tenant) -> {
                if (tenant != null && tenant.hosts() != null) {
                    tenant.hosts().forEach(host -> tenantByHost.put(normalize(host), tenantId));
                }
            });
        }
    }

    @Override
    public TenantContext resolve(Map<String, Object> requestAttributes) {
        Object host = requestAttributes == null ? null : requestAttributes.get(ATTRIBUTE_HOST);
        String tenantId = host == null ? null : tenantByHost.get(normalize(host.toString()));
        return tenantId == null ? TenantContext.DEFAULT : new TenantContext(tenantId, null, null, null);
    }

    static String normalize(String host) {
        String value = host.trim().toLowerCase(Locale.ROOT);
        int colon = value.indexOf(':');
        return colon > 0 && !value.startsWith("[") ? value.substring(0, colon) : value;
    }
}
