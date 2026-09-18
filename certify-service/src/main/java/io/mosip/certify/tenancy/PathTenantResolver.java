package io.mosip.certify.tenancy;

import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.TenantResolver;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code certify.tenancy.resolver=path}: the tenant is the segment after {@code /t/} in the request path
 * ({@code {servletPath}/t/{tenant}/oid4vci/...}, docs/design/09-api-compatibility.md). Only tenants configured under
 * {@code certify.tenancy.tenants.<id>} are recognised; any other path, including one without the prefix, is the
 * default tenant, as the host resolver treats an unknown host.
 */
public final class PathTenantResolver implements TenantResolver {

    public static final String ATTRIBUTE_PATH = TenantResolutionFilter.ATTRIBUTE_PATH;
    static final String PREFIX = "/t/";
    private static final Pattern SEGMENT = Pattern.compile("/t/([A-Za-z0-9_.-]{1,64})(?:/|$)");

    private final TenancyProperties properties;

    public PathTenantResolver(TenancyProperties properties) {
        this.properties = properties;
    }

    @Override
    public TenantContext resolve(Map<String, Object> requestAttributes) {
        Object path = requestAttributes == null ? null : requestAttributes.get(ATTRIBUTE_PATH);
        String tenantId = path == null ? null : tenantOf(path.toString());
        return tenantId == null || properties.tenant(tenantId) == null ? TenantContext.DEFAULT : new TenantContext(tenantId, null, null, null);
    }

    static String tenantOf(String path) {
        Matcher matcher = SEGMENT.matcher(path);
        return matcher.find() ? matcher.group(1) : null;
    }
}
