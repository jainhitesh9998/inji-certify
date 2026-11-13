package io.mosip.certify.configv2;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * {@code /v2/credential-configurations} (docs/design/09-api-compatibility.md): the domain model in and out, HTTP status
 * codes and {@code {error, error_description}} bodies, and {@code POST /{id}/preview} as the dry run of a saved row.
 * The path sits under the same {@code credential-configurations} security patterns as the v1 API.
 */
@Slf4j
@RestController
@RequestMapping("/v2/credential-configurations")
public class CredentialConfigurationV2Controller {

    private final CredentialConfigurationV2Service service;

    public CredentialConfigurationV2Controller(CredentialConfigurationV2Service service) {
        this.service = service;
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<CredentialConfigurationV2> create(@RequestBody CredentialConfigurationV2 body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(body));
    }

    @GetMapping(produces = "application/json")
    public List<CredentialConfigurationV2> list() {
        return service.list();
    }

    @GetMapping(value = "/{id}", produces = "application/json")
    public CredentialConfigurationV2 get(@PathVariable String id) {
        return service.get(id);
    }

    @PutMapping(value = "/{id}", consumes = "application/json", produces = "application/json")
    public CredentialConfigurationV2 update(@PathVariable String id, @RequestBody CredentialConfigurationV2 body) {
        return service.update(id, body);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(value = "/{id}/preview", consumes = "application/json", produces = "application/json")
    public CredentialConfigurationV2.PreviewResponse preview(@PathVariable String id, @RequestBody(required = false) CredentialConfigurationV2.PreviewRequest request) {
        return service.preview(id, request);
    }

    @ExceptionHandler(ConfigV2Exception.class)
    public ResponseEntity<Map<String, String>> refused(ConfigV2Exception e) {
        return error(e.status(), e.code(), String.valueOf(e.getMessage()));
    }

    /**
     * A database constraint the validation did not anticipate: 409 for a unique key (SQL state 23505, e.g. two
     * concurrent creates of one id), 400 otherwise. The SQL and the driver's message go to the log, never to the caller.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, String>> constraint(DataIntegrityViolationException e) {
        String state = sqlState(e);
        log.warn("v2 configuration refused by a database constraint (SQL state {})", state, e);
        if (UNIQUE_VIOLATION.equals(state) || e instanceof DuplicateKeyException) {
            return error(409, ConfigV2Exception.CONFIGURATION_EXISTS, "A configuration with the same identity exists");
        }
        return error(400, ConfigV2Exception.INVALID_CONFIGURATION, "The configuration is missing a required value or carries a value"
                + " the store refuses (too long or of the wrong type); check scope, display, display.order and the field lengths");
    }

    /** Bean validation of the row (at flush or commit): 400 naming the v2 fields. */
    @ExceptionHandler({ConstraintViolationException.class, TransactionSystemException.class})
    public ResponseEntity<Map<String, String>> invalidRow(RuntimeException e) {
        ConstraintViolationException violation = cause(e, ConstraintViolationException.class);
        if (violation == null) {
            log.error("v2 configuration call failed", e);
            return error(500, "server_error", "The configuration could not be processed; see the service log");
        }
        String fields = violation.getConstraintViolations().stream()
                .map(v -> FIELDS.getOrDefault(String.valueOf(v.getPropertyPath()), String.valueOf(v.getPropertyPath())))
                .sorted().distinct().collect(java.util.stream.Collectors.joining(", "));
        return error(400, ConfigV2Exception.INVALID_CONFIGURATION, "Required value(s) missing: " + fields);
    }

    /** A body that is not JSON, or not this model's shapes: 400 without the parser's internals. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> unreadable(HttpMessageNotReadableException e) {
        log.debug("Unreadable v2 configuration body", e);
        return error(400, ConfigV2Exception.INVALID_CONFIGURATION, "The body is not a JSON v2 configuration");
    }

    /**
     * Anything else is answered with its own HTTP status (Spring MVC's errors) or 500, never with the MOSIP envelope
     * and 200 that the global advice gives the v1 API. Security exceptions go back to the security filters.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> unexpected(Exception e) throws Exception {
        if (e instanceof org.springframework.security.access.AccessDeniedException
                || e instanceof org.springframework.security.core.AuthenticationException) {
            throw e;
        }
        if (e instanceof ErrorResponse response) {
            return error(response.getStatusCode().value(), "invalid_request", response.getBody().getDetail() == null
                    ? HttpStatus.valueOf(response.getStatusCode().value()).getReasonPhrase() : response.getBody().getDetail());
        }
        log.error("v2 configuration call failed", e);
        return error(500, "server_error", "The configuration could not be processed; see the service log");
    }

    private static ResponseEntity<Map<String, String>> error(int status, String code, String description) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("error", code, "error_description", description));
    }

    static final String UNIQUE_VIOLATION = "23505";

    /** Entity properties as the v2 model names them. */
    private static final Map<String, String> FIELDS = Map.of(
            "scope", "scope",
            "display", "display.display",
            "order", "display.order",
            "credentialConfigKeyId", "id",
            "cryptographicBindingMethodsSupported", "protocol.cryptographicBindingMethodsSupported",
            "credentialSigningAlgValuesSupported", "protocol.credentialSigningAlgValuesSupported",
            "proofTypesSupported", "protocol.proofTypesSupported");

    static String sqlState(Throwable e) {
        java.sql.SQLException sql = cause(e, java.sql.SQLException.class);
        return sql == null ? null : sql.getSQLState();
    }

    private static <T extends Throwable> T cause(Throwable e, Class<T> type) {
        for (Throwable t = e; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (type.isInstance(t)) {
                return type.cast(t);
            }
        }
        return null;
    }
}
