package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.issuance.IssuanceException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 0.14.0 error answers for the draft-13 controllers: a nonce problem is {@code invalid_proof} carrying the fresh
 * {@code c_nonce} the wallet must use next; other core errors keep their code and message; bean validation errors
 * are left to the service's advice, which already answers {@code /issuance/*} the 0.14.0 way. The handler is
 * resolved lazily so that {@code @WebMvcTest} slices of other controllers, which include every advice, still load.
 */
@RestControllerAdvice(assignableTypes = {D13CredentialController.class, D13VersionedPathsController.class})
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13ErrorAdvice {

    private final ObjectProvider<D13IssuanceHandler> handler;

    public D13ErrorAdvice(ObjectProvider<D13IssuanceHandler> handler) {
        this.handler = handler;
    }

    @ExceptionHandler(IssuanceException.class)
    public ResponseEntity<Map<String, Object>> issuanceError(IssuanceException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        switch (e.getErrorCode()) {
            case IssuanceException.INVALID_NONCE -> {
                body.put("error", IssuanceException.INVALID_PROOF);
                body.put("error_description", IssuanceException.INVALID_PROOF);
                VCIssuanceTransaction fresh = handler.getObject().freshNonce();
                body.put("c_nonce", fresh.getCNonce());
                body.put("c_nonce_expires_in", fresh.getCNonceExpireSeconds());
                return ResponseEntity.badRequest().body(body);
            }
            case IssuanceException.NOT_AUTHENTICATED -> {
                body.put("error", e.getErrorCode());
                body.put("error_description", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            }
            case IssuanceException.ISSUANCE_FAILED -> {
                body.put("error", "server_error");
                body.put("error_description", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
            }
            default -> {
                body.put("error", e.getErrorCode());
                body.put("error_description", e.getMessage());
                return ResponseEntity.badRequest().body(body);
            }
        }
    }
}
