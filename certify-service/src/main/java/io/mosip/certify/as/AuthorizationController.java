package io.mosip.certify.as;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * {@code POST /oauth/par} (RFC 9126) and {@code GET /oauth/authorize} of Certify's own authorization server. Both sit
 * under the {@code **}{@code /oauth/**} patterns the deployment already exempts from the token filter and CSRF.
 */
@RestController
public class AuthorizationController {

    private final AuthorizationCodeService service;
    private final ClientAttestationValidator clientAttestation;

    public AuthorizationController(AuthorizationCodeService service, ClientAttestationValidator clientAttestation) {
        this.service = service;
        this.clientAttestation = clientAttestation;
    }

    @PostMapping(value = "/oauth/par", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> par(@RequestParam Map<String, String> params, jakarta.servlet.http.HttpServletRequest http) {
        clientAttestation.validate(http, params.get("client_id"));
        PushedAuthorizationRequest request = service.push(params);
        long expiresIn = Math.max(1, request.expiresAtEpochSeconds() - Instant.now().getEpochSecond());
        return ResponseEntity.status(HttpStatus.CREATED)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of("request_uri", request.requestUri(), "expires_in", expiresIn));
    }

    @GetMapping(value = "/oauth/authorize")
    public ResponseEntity<Void> authorize(@RequestParam(name = "client_id", required = false) String clientId,
                                          @RequestParam(name = "request_uri", required = false) String requestUri) {
        String location = service.authorize(clientId, requestUri);
        return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, location).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
    }

    @ExceptionHandler(AsException.class)
    public ResponseEntity<Map<String, String>> oauthError(AsException e) {
        return ResponseEntity.status(e.status()).header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of("error", e.error(), "error_description", String.valueOf(e.getMessage())));
    }
}
