package io.mosip.certify.oid4vci.d13;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Buffers the body of {@code POST .../issuance/credential} so that {@link D13BodyCondition} can tell a draft-13
 * request ({@code format}, no {@code credential_configuration_id}) from an OpenID4VCI 1.0 one before the handler is
 * chosen. Every other request passes through untouched; the path, headers and security decisions are never changed.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13BodyBufferFilter extends OncePerRequestFilter {

    static final String ATTRIBUTE_DRAFT13_BODY = D13BodyBufferFilter.class.getName() + ".draft13";
    static final String CREDENTIAL_PATH = "/issuance/credential";

    private final ObjectMapper objectMapper;

    public D13BodyBufferFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !"POST".equalsIgnoreCase(request.getMethod()) || uri == null || !uri.endsWith(CREDENTIAL_PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = request.getInputStream().readAllBytes();
        request.setAttribute(ATTRIBUTE_DRAFT13_BODY, isDraft13(body));
        chain.doFilter(new BufferedRequest(request, body), response);
    }

    /** A draft-13 body names a format and no configuration id; anything unparseable is left to the 1.0 handler. */
    boolean isDraft13(byte[] body) {
        try {
            JsonNode node = objectMapper.readTree(body);
            return node != null && node.isObject() && node.hasNonNull("format") && !node.hasNonNull("credential_configuration_id");
        } catch (IOException e) {
            return false;
        }
    }

    /** Re-serves the buffered body to every later reader (argument resolution included). */
    static final class BufferedRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        BufferedRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public int read() { return in.read(); }
                @Override public boolean isFinished() { return in.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) {}
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }

        @Override
        public int getContentLength() {
            return body.length;
        }

        @Override
        public long getContentLengthLong() {
            return body.length;
        }
    }
}
