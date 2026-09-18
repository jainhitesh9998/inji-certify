package io.mosip.certify.authz;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.ParsedAccessToken;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * The {@link ParsedAccessToken} bean the application wires: a stateless delegate to the request-scoped
 * {@link AuthorizationContext}. Existing filters, services and plugins that inject {@code ParsedAccessToken}
 * keep working and become thread-safe without changes. Outside a request (batch jobs, tests without a
 * web context) the delegate falls back to its own fields so old unit tests and non-web callers still work.
 */
@Primary
@Component("parsedAccessToken")
@SuppressWarnings("deprecation")
public class RequestScopedParsedAccessToken extends ParsedAccessToken {

    private final AuthorizationContext context;

    public RequestScopedParsedAccessToken(AuthorizationContext context) {
        this.context = context;
    }

    private AuthorizationContext current() {
        try {
            context.isActive(); // touches the scoped proxy; throws outside a request
            return context;
        } catch (BeanCreationException | IllegalStateException e) {
            return null;
        }
    }

    @Override
    public Map<String, Object> getClaims() {
        AuthorizationContext c = current();
        return c != null ? c.getClaims() : super.getClaims();
    }

    @Override
    public void setClaims(Map<String, Object> claims) {
        AuthorizationContext c = current();
        if (c != null) {
            c.setClaims(claims);
        } else {
            super.setClaims(claims);
        }
    }

    @Override
    public String getAccessTokenHash() {
        AuthorizationContext c = current();
        return c != null ? c.getAccessTokenHash() : super.getAccessTokenHash();
    }

    @Override
    public void setAccessTokenHash(String accessTokenHash) {
        AuthorizationContext c = current();
        if (c != null) {
            c.setAccessTokenHash(accessTokenHash);
        } else {
            super.setAccessTokenHash(accessTokenHash);
        }
    }

    @Override
    public boolean isActive() {
        AuthorizationContext c = current();
        return c != null ? c.isActive() : super.isActive();
    }

    @Override
    public void setActive(boolean active) {
        AuthorizationContext c = current();
        if (c != null) {
            c.setActive(active);
        } else {
            super.setActive(active);
        }
    }
}
