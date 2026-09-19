package io.mosip.certify.vcapi;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HTTP Basic authentication of VC-API clients against {@code certify.protocol.vc-api.clients}: the client id is the
 * user name, {@code secret} the password, compared in constant time. The authenticated client id is left in the
 * request attribute {@link #CLIENT_ATTRIBUTE} for the controller. (VCALM lists OAuth 2.0, zCap, DID auth and network
 * rules as its security schemes; Basic client credentials are the first one Certify offers.)
 */
@Slf4j
public class VcApiClientAuthFilter extends OncePerRequestFilter {

    public static final String CLIENT_ATTRIBUTE = VcApiClientAuthFilter.class.getName() + ".client";
    static final String PATH = "/vc-api/";

    private final VcApiProperties properties;

    public VcApiClientAuthFilter(VcApiProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().contains(PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String clientId = authenticate(request.getHeader("Authorization"));
        if (clientId == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "Basic realm=\"vc-api\"");
            response.setContentType("application/problem+json");
            response.getWriter().write(VcApiController.problemJson("UNAUTHORIZED", "A registered VC-API client must authenticate with HTTP Basic"));
            return;
        }
        request.setAttribute(CLIENT_ATTRIBUTE, clientId);
        chain.doFilter(request, response);
    }

    /** The client id when the header carries the id and secret of a configured client, else {@code null}. */
    String authenticate(String header) {
        if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6) || properties.clients() == null) {
            return null;
        }
        String credentials;
        try {
            credentials = new String(Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        int colon = credentials.indexOf(':');
        if (colon <= 0) {
            return null;
        }
        String clientId = credentials.substring(0, colon);
        String secret = credentials.substring(colon + 1);
        VcApiProperties.Client client = properties.clients().get(clientId);
        if (client == null || client.secret() == null || client.secret().isBlank()) {
            log.warn("VC-API client {} is not registered", clientId);
            return null;
        }
        boolean matches = MessageDigest.isEqual(client.secret().getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8));
        return matches ? clientId : null;
    }
}
