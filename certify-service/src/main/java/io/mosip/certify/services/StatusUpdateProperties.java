package io.mosip.certify.services;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * {@code certify.status.update}: how status changes wait for a status list's row lock (M-11d review round 5, finding 1).
 *
 * <p>A status change ({@code POST /credentials/status}, the VC-API status endpoint) and the batch job's application of a
 * list both lock the list's row ({@link StatusListLockWait}); the job holds that lock while it signs the list, which can
 * be a network HSM or KMS call. Without a bound, a hanging signer would hold every status request for that list — a
 * Tomcat thread and a Hikari connection each — until the pool is drained and issuance fails too.
 *
 * @param lockWait how long a status change or the batch job waits for a list's row lock before it gives up: a status
 *                 change is refused as retryable ({@value StatusListBusyException#ERROR_CODE}; VC-API {@code 503} with
 *                 {@code Retry-After}) and queues nothing, the batch job moves on to the next list and tries this one
 *                 again on its next run. At least one millisecond and at most {@link Integer#MAX_VALUE} milliseconds
 *                 (PostgreSQL's {@code lock_timeout} range; zero would mean "wait for ever" there, so it is refused).
 *                 Applied with {@code SET LOCAL lock_timeout} on PostgreSQL; another database keeps its own lock timeout
 *                 and failure ({@link StatusListLockWait}).
 */
@ConfigurationProperties(prefix = "certify.status.update")
public record StatusUpdateProperties(@DefaultValue("PT5S") Duration lockWait) {

    /** The default {@link #lockWait()}: long enough for a list's normal signing, short enough to keep a pool alive. */
    public static final Duration DEFAULT_LOCK_WAIT = Duration.ofSeconds(5);

    public StatusUpdateProperties {
        lockWait = lockWait == null ? DEFAULT_LOCK_WAIT : lockWait;
        if (lockWait.isNegative() || lockWait.compareTo(Duration.ofMillis(1)) < 0) {
            throw new IllegalArgumentException("certify.status.update.lock-wait must be at least one millisecond (PT0.001S),"
                    + " got " + lockWait + "; zero would let a status change wait for ever on PostgreSQL");
        }
        if (lockWait.compareTo(Duration.ofMillis(Integer.MAX_VALUE)) > 0) {
            throw new IllegalArgumentException("certify.status.update.lock-wait must be at most " + Integer.MAX_VALUE
                    + " milliseconds (PostgreSQL's lock_timeout range), got " + lockWait);
        }
    }

    /** The defaults: {@code lock-wait} {@code PT5S}. */
    public static StatusUpdateProperties defaults() {
        return new StatusUpdateProperties(null);
    }
}
