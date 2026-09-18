package io.mosip.certify.authz;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.ParsedAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("deprecation")
class RequestScopedParsedAccessTokenTest {

    private AnnotationConfigWebApplicationContext context;
    private ParsedAccessToken token;

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigWebApplicationContext();
        context.register(AuthorizationContextConfig.class, RequestScopedParsedAccessToken.class);
        context.refresh(); // registers the request scope itself
        token = context.getBean(ParsedAccessToken.class);
        assertSame(RequestScopedParsedAccessToken.class, token.getClass());
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        context.close();
    }

    private static void bindRequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @Test
    void twoConcurrentRequestsNeverSeeEachOthersClaims() throws Exception {
        CyclicBarrier bothWritten = new CyclicBarrier(2);
        CountDownLatch done = new CountDownLatch(2);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        for (String subject : new String[]{"alice", "bob"}) {
            new Thread(() -> {
                try {
                    bindRequest();
                    token.setClaims(Map.of("sub", subject));
                    token.setAccessTokenHash("hash-" + subject);
                    token.setActive(true);
                    bothWritten.await();
                    assertEquals(subject, token.getClaims().get("sub"));
                    assertEquals("hash-" + subject, token.getAccessTokenHash());
                    assertTrue(token.isActive());
                    assertEquals(subject, context.getBean(AuthorizationContext.class).getClaims().get("sub"));
                } catch (Throwable t) {
                    failure.set(t);
                } finally {
                    RequestContextHolder.resetRequestAttributes();
                    done.countDown();
                }
            }, "request-" + subject).start();
        }
        done.await();
        assertNull(failure.get(), () -> "isolation failed: " + failure.get());
    }

    @Test
    void aNewRequestStartsEmptyAndDefaultTenant() {
        bindRequest();
        assertFalse(token.isActive());
        assertTrue(token.getClaims().isEmpty());
        assertEquals(AuthorizationContext.DEFAULT_TENANT, context.getBean(AuthorizationContext.class).getTenantId());
        token.setActive(true);
        RequestContextHolder.resetRequestAttributes();
        bindRequest();
        assertFalse(token.isActive(), "state does not leak into the next request");
    }

    @Test
    void outsideARequestTheDelegateFallsBackToItsOwnFields() {
        RequestContextHolder.resetRequestAttributes();
        token.setClaims(Map.of("scope", "batch"));
        token.setActive(true);
        assertEquals("batch", token.getClaims().get("scope"));
        assertTrue(token.isActive());
    }

    @Test
    void plainParsedAccessTokenStillWorksForUnitTests() {
        ParsedAccessToken plain = new ParsedAccessToken();
        plain.setClaims(Map.of("client_id", "x"));
        plain.setActive(true);
        assertEquals("x", plain.getClaims().get("client_id"));
        assertTrue(plain.isActive());
    }
}
