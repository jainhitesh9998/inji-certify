package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.entity.IssuanceTransaction;
import io.mosip.certify.repository.IssuanceTransactionRepository;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * OpenID4VCI 1.0 Notification Endpoint: the wallet reports {@code credential_accepted}, {@code credential_failure} or
 * {@code credential_deleted} for the {@code notification_id} the credential response carried, under the same access
 * token; the transaction moves to NOTIFIED and the answer is 204. Errors are {@code invalid_notification_id} and
 * {@code invalid_notification_request}, HTTP 400, as the specification lists them.
 */
@Slf4j
@RestController
@RequestMapping("/oid4vci")
public class Oid4vciNotificationController {

    public static final Set<String> EVENTS = Set.of("credential_accepted", "credential_failure", "credential_deleted");
    static final String ERROR_INVALID_NOTIFICATION_ID = "invalid_notification_id";
    static final String ERROR_INVALID_NOTIFICATION_REQUEST = "invalid_notification_request";

    private final IssuanceTransactionRepository transactions;
    private final AuthorizationContext authorizationContext;

    public Oid4vciNotificationController(IssuanceTransactionRepository transactions, AuthorizationContext authorizationContext) {
        this.transactions = transactions;
        this.authorizationContext = authorizationContext;
    }

    @PostMapping(value = "/notification", consumes = "application/json")
    public ResponseEntity<?> notification(@RequestBody NotificationRequest request) {
        if (!authorizationContext.isActive()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_token", "error_description", "The notification endpoint needs an access token"));
        }
        if (request == null || request.getNotificationId() == null || request.getNotificationId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", ERROR_INVALID_NOTIFICATION_REQUEST, "error_description", "notification_id is required"));
        }
        if (request.getEvent() == null || !EVENTS.contains(request.getEvent())) {
            return ResponseEntity.badRequest().body(Map.of("error", ERROR_INVALID_NOTIFICATION_REQUEST, "error_description", "event must be one of " + EVENTS));
        }
        Optional<IssuanceTransaction> transaction = transactions.findByNotificationIdAndAccessTokenHash(request.getNotificationId(), authorizationContext.getAccessTokenHash());
        if (transaction.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", ERROR_INVALID_NOTIFICATION_ID, "error_description", "Unknown notification_id for this access token"));
        }
        IssuanceTransaction row = transaction.get();
        row.setState(IssuanceTransaction.STATE_NOTIFIED);
        transactions.save(row);
        log.info("Wallet reported {} for transaction {}{}", request.getEvent(), row.getId(),
                request.getEventDescription() == null ? "" : ": " + request.getEventDescription());
        return ResponseEntity.noContent().build();
    }

    @Data
    public static class NotificationRequest {
        @JsonProperty("notification_id")
        private String notificationId;
        private String event;
        @JsonProperty("event_description")
        private String eventDescription;
    }
}
