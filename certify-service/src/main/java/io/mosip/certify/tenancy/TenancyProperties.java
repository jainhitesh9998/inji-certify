package io.mosip.certify.tenancy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;
import java.util.Map;

/**
 * Tenancy settings (docs/design/14-configuration.md, `certify.tenancy`): off by default, in which case every request
 * is the {@code default} tenant. {@code resolver=host} maps the request host to a tenant through
 * {@code tenants.<id>.hosts}; a tenant may override the issuer identifier, the issuer DID and the key namespace.
 */
@ConfigurationProperties(prefix = TenancyProperties.PREFIX)
public record TenancyProperties(@DefaultValue("false") boolean enabled, @DefaultValue("fixed") String resolver,
                                @DefaultValue Map<String, Tenant> tenants) {

    public static final String PREFIX = "certify.tenancy";
    public static final String RESOLVER_FIXED = "fixed";
    public static final String RESOLVER_HOST = "host";

    public record Tenant(@DefaultValue List<String> hosts, String issuerIdentifier, String issuerDid, String keyNamespace) {}

    public Tenant tenant(String tenantId) {
        return tenants == null || tenantId == null ? null : tenants.get(tenantId);
    }
}
