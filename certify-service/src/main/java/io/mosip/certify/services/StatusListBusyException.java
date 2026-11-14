package io.mosip.certify.services;

import io.mosip.certify.core.exception.CertifyException;

import java.time.Duration;

/**
 * A status list's row lock was not available within {@code certify.status.update.lock-wait}: the batch job (or another
 * writer) holds it, typically while it signs the list. Nothing was written — the caller's transaction is rolled back —
 * and asking again later can succeed (M-11d review round 5, finding 1).
 *
 * <p>A status change answers it as a retryable refusal: VC-API {@code 503} with {@code Retry-After}
 * ({@link #retryAfterSeconds()}), {@code /credentials/status} the MOSIP error wrapper with {@value #ERROR_CODE}. The
 * batch job moves on to the next list and tries this one again on its next run.
 */
public class StatusListBusyException extends CertifyException {

    /** The error code: the request was not applied and may be sent again as it is. */
    public static final String ERROR_CODE = "status_list_busy_retry_later";

    private final String listId;
    private final transient Duration waited;

    public StatusListBusyException(String listId, Duration waited, Throwable cause) {
        super(ERROR_CODE, "Status list " + listId + " is being updated and its lock was not available within " + waited
                + " (certify.status.update.lock-wait); nothing was queued or written, retry the request later", cause);
        this.listId = listId;
        this.waited = waited;
    }

    /** The list whose lock was not available. */
    public String listId() {
        return listId;
    }

    /** How long the lock was waited for: {@code certify.status.update.lock-wait}. */
    public Duration waited() {
        return waited;
    }

    /** When to ask again: the lock wait itself, at least one second. */
    public Duration retryAfter() {
        return waited == null || waited.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : waited;
    }

    /** {@link #retryAfter()} in whole seconds, rounded up, as the {@code Retry-After} header carries it (RFC 9110 10.2.3). */
    public long retryAfterSeconds() {
        Duration wait = retryAfter();
        return wait.getSeconds() + (wait.getNano() > 0 ? 1 : 0);
    }
}
