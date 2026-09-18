package io.mosip.certify.deprecation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.method.HandlerMethod;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeprecationInterceptorTest {

    static class SampleController {
        @DeprecatedEndpoint(name = "issuance-vd11", since = "2026-09-18", sunset = "2027-03-31",
                replacement = "/v1/certify/oid4vci/credential", docs = "https://example.org/deprecations#vd11")
        @PostMapping("/issuance/vd11/credential")
        public void deprecated() {}

        @GetMapping("/current")
        public void current() {}
    }

    @DeprecatedEndpoint(name = "legacy-controller", since = "2026-01-01")
    static class LegacyController {
        @GetMapping("/legacy")
        public void anything() {}
    }

    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    private final MockEnvironment environment = new MockEnvironment();
    private final Instant now = Instant.parse("2026-09-18T10:00:00Z");
    private DeprecationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new DeprecationInterceptor(meterRegistry, environment, new ObjectMapper(), Clock.fixed(now, ZoneOffset.UTC));
        ReflectionTestUtils.setField(interceptor, "defaultDocsUrl", "https://docs.example.org/certify");
        ReflectionTestUtils.setField(interceptor, "logInterval", Duration.ofHours(1));
    }

    private static HandlerMethod handler(Class<?> type, String method) throws Exception {
        return new HandlerMethod(type.getDeclaredConstructor().newInstance(), type.getDeclaredMethod(method));
    }

    @Test
    void deprecatedHandlerGetsHeadersAndIsCounted() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean proceed = interceptor.preHandle(new MockHttpServletRequest("POST", "/issuance/vd11/credential"), response,
                handler(SampleController.class, "deprecated"));

        assertTrue(proceed);
        assertEquals("@1789689600", response.getHeader("Deprecation")); // 2026-09-18T00:00:00Z
        assertEquals("Wed, 31 Mar 2027 23:59:59 GMT", response.getHeader("Sunset"));
        assertEquals("<https://example.org/deprecations#vd11>; rel=\"deprecation\", </v1/certify/oid4vci/credential>; rel=\"successor-version\"",
                response.getHeader("Link"));
        assertEquals(1.0, meterRegistry.get(DeprecationInterceptor.COUNTER_NAME)
                .tag("endpoint", "issuance-vd11").tag("enabled", "true").counter().count());
    }

    @Test
    void killSwitchAnswersGoneWithJsonAndStopsTheChain() throws Exception {
        environment.setProperty("mosip.certify.deprecated.issuance-vd11.enabled", "false");
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean proceed = interceptor.preHandle(new MockHttpServletRequest("POST", "/issuance/vd11/credential"), response,
                handler(SampleController.class, "deprecated"));

        assertFalse(proceed);
        assertEquals(410, response.getStatus());
        assertEquals("application/json", response.getContentType());
        String body = response.getContentAsString();
        assertTrue(body.contains("\"error\":\"endpoint_removed\""), body);
        assertTrue(body.contains("\"replacement\":\"/v1/certify/oid4vci/credential\""), body);
        assertEquals("@1789689600", response.getHeader("Deprecation"));
        assertEquals(1.0, meterRegistry.get(DeprecationInterceptor.COUNTER_NAME)
                .tag("endpoint", "issuance-vd11").tag("enabled", "false").counter().count());
    }

    @Test
    void handlerWithoutAnnotationIsUntouched() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertTrue(interceptor.preHandle(new MockHttpServletRequest("GET", "/current"), response,
                handler(SampleController.class, "current")));
        assertNull(response.getHeader("Deprecation"));
        assertTrue(meterRegistry.getMeters().isEmpty());
    }

    @Test
    void classLevelAnnotationAppliesToEveryHandlerAndOmitsSunsetWhenUnscheduled() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertTrue(interceptor.preHandle(new MockHttpServletRequest("GET", "/legacy"), response,
                handler(LegacyController.class, "anything")));
        assertEquals("@1767225600", response.getHeader("Deprecation")); // 2026-01-01T00:00:00Z
        assertNull(response.getHeader("Sunset"));
        assertEquals("<https://docs.example.org/certify>; rel=\"deprecation\"", response.getHeader("Link"));
    }

    @Test
    void warningIsLoggedAtMostOncePerInterval() {
        assertTrue(interceptor.shouldLog("x", now));
        assertFalse(interceptor.shouldLog("x", now.plus(Duration.ofMinutes(59))));
        assertTrue(interceptor.shouldLog("x", now.plus(Duration.ofMinutes(61))));
        assertTrue(interceptor.shouldLog("y", now));
    }

    @Test
    void nonHandlerMethodObjectsAreIgnored() throws Exception {
        assertTrue(interceptor.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object()));
    }
}
