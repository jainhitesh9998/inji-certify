package io.mosip.certify.deprecation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Applies the deprecation contract of docs/design/09-api-compatibility.md to every handler carrying
 * {@link DeprecatedEndpoint}: headers, a usage counter, a throttled warning, and a per-endpoint kill switch.
 */
@Slf4j
@Component
public class DeprecationInterceptor implements HandlerInterceptor {

    public static final String COUNTER_NAME = "certify.deprecated.calls";
    public static final String HEADER_DEPRECATION = "Deprecation";
    public static final String HEADER_SUNSET = "Sunset";
    public static final String HEADER_LINK = "Link";
    static final String PROPERTY_PREFIX = "mosip.certify.deprecated.";
    static final String ERROR_CODE = "endpoint_removed";

    private final MeterRegistry meterRegistry;
    private final Environment environment;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final Map<String, Instant> lastLogged = new ConcurrentHashMap<>();

    @Value("${mosip.certify.deprecation.docs-url:https://docs.inji.io/inji-certify}")
    private String defaultDocsUrl;

    @Value("${mosip.certify.deprecation.log-interval:PT1H}")
    private Duration logInterval = Duration.ofHours(1);

    @Autowired
    public DeprecationInterceptor(MeterRegistry meterRegistry, Environment environment, ObjectMapper objectMapper) {
        this(meterRegistry, environment, objectMapper, Clock.systemUTC());
    }

    DeprecationInterceptor(MeterRegistry meterRegistry, Environment environment, ObjectMapper objectMapper, Clock clock) {
        this.meterRegistry = meterRegistry;
        this.environment = environment;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        DeprecatedEndpoint deprecation = resolve(handler);
        if (deprecation == null) {
            return true;
        }
        boolean enabled = environment.getProperty(PROPERTY_PREFIX + deprecation.name() + ".enabled", Boolean.class, Boolean.TRUE);
        meterRegistry.counter(COUNTER_NAME, "endpoint", deprecation.name(), "enabled", String.valueOf(enabled)).increment();

        if (!enabled) {
            writeGone(response, deprecation);
            return false;
        }
        addHeaders(response, deprecation);
        if (shouldLog(deprecation.name(), clock.instant())) {
            log.warn("Deprecated endpoint '{}' called ({} {}); replacement: {}; sunset: {}. This message repeats at most every {}.",
                    deprecation.name(), request.getMethod(), request.getRequestURI(),
                    deprecation.replacement().isEmpty() ? "none announced" : deprecation.replacement(),
                    deprecation.sunset().isEmpty() ? "not scheduled" : deprecation.sunset(), logInterval);
        }
        return true;
    }

    static DeprecatedEndpoint resolve(Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return null;
        }
        DeprecatedEndpoint onMethod = AnnotatedElementUtils.findMergedAnnotation(handlerMethod.getMethod(), DeprecatedEndpoint.class);
        if (onMethod != null) {
            return onMethod;
        }
        return AnnotatedElementUtils.findMergedAnnotation(handlerMethod.getBeanType(), DeprecatedEndpoint.class);
    }

    void addHeaders(HttpServletResponse response, DeprecatedEndpoint deprecation) {
        // RFC 9745: Deprecation: @<seconds since epoch>
        long since = LocalDate.parse(deprecation.since()).atStartOfDay(ZoneOffset.UTC).toEpochSecond();
        response.setHeader(HEADER_DEPRECATION, "@" + since);
        if (!deprecation.sunset().isEmpty()) {
            // RFC 8594: Sunset: <HTTP-date>
            String sunset = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    LocalDate.parse(deprecation.sunset()).plusDays(1).atStartOfDay(ZoneOffset.UTC).minusSeconds(1));
            response.setHeader(HEADER_SUNSET, sunset);
        }
        StringBuilder link = new StringBuilder("<").append(docsUrl(deprecation)).append(">; rel=\"deprecation\"");
        if (isUrl(deprecation.replacement())) {
            link.append(", <").append(deprecation.replacement()).append(">; rel=\"successor-version\"");
        }
        response.addHeader(HEADER_LINK, link.toString());
    }

    private void writeGone(HttpServletResponse response, DeprecatedEndpoint deprecation) throws IOException {
        response.setStatus(HttpStatus.GONE.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        addHeaders(response, deprecation);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", ERROR_CODE);
        body.put("error_description", "The endpoint '" + deprecation.name() + "' has been disabled by configuration ("
                + PROPERTY_PREFIX + deprecation.name() + ".enabled=false)."
                + (deprecation.replacement().isEmpty() ? "" : " Use " + deprecation.replacement() + " instead."));
        if (!deprecation.replacement().isEmpty()) {
            body.put("replacement", deprecation.replacement());
        }
        body.put("docs", docsUrl(deprecation));
        response.getWriter().write(objectMapper.writeValueAsString(body));
        response.getWriter().flush();
    }

    boolean shouldLog(String name, Instant now) {
        Instant previous = lastLogged.putIfAbsent(name, now);
        if (previous == null) {
            return true;
        }
        if (Duration.between(previous, now).compareTo(logInterval) >= 0) {
            lastLogged.put(name, now);
            return true;
        }
        return false;
    }

    private String docsUrl(DeprecatedEndpoint deprecation) {
        return deprecation.docs().isEmpty() ? defaultDocsUrl : deprecation.docs();
    }

    private static boolean isUrl(String value) {
        return value.startsWith("http://") || value.startsWith("https://") || value.startsWith("/");
    }
}
