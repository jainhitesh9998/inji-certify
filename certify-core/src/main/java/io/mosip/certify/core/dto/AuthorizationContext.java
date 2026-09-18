package io.mosip.certify.core.dto;

import java.util.HashMap;
import java.util.Map;

/**
 * What the authorization layer established for the current request: the validated access-token claims,
 * the token hash, the scheme the caller used, and the tenant the request belongs to ({@code default}
 * until a tenant resolver says otherwise). One instance exists per request; it is registered as a
 * request-scoped bean by the service and reached through {@link ParsedAccessToken} for existing callers.
 * Plain data, no framework types (docs/design/05-target-architecture.md).
 */
public class AuthorizationContext {

    public static final String DEFAULT_TENANT = "default";

    private Map<String, Object> claims = new HashMap<>();
    private String accessTokenHash;
    private boolean active;
    private String scheme;
    private String tenantId = DEFAULT_TENANT;

    public Map<String, Object> getClaims() { return claims; }
    public void setClaims(Map<String, Object> claims) { this.claims = claims; }
    public String getAccessTokenHash() { return accessTokenHash; }
    public void setAccessTokenHash(String accessTokenHash) { this.accessTokenHash = accessTokenHash; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getScheme() { return scheme; }
    public void setScheme(String scheme) { this.scheme = scheme; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId == null ? DEFAULT_TENANT : tenantId; }

    /** Clears everything, as a request boundary does. */
    public void reset() {
        claims = new HashMap<>();
        accessTokenHash = null;
        active = false;
        scheme = null;
        tenantId = DEFAULT_TENANT;
    }
}
