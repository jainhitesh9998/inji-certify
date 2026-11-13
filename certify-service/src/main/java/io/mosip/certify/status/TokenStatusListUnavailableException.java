package io.mosip.certify.status;

import java.time.Duration;

/**
 * A Token Status List exists but cannot be served now: it is expired or names another URI in {@code sub}, and it could
 * not be signed again (the signer failed, is still busy past {@code renew-wait}, or failed within {@code renew-backoff}).
 * The endpoint answers 503 with {@code Retry-After} {@link #retryAfter()}.
 */
public class TokenStatusListUnavailableException extends IllegalStateException {

    private final transient Duration retryAfter;

    public TokenStatusListUnavailableException(String message, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.retryAfter = retryAfter;
    }

    /** When to ask again: at least one second. */
    public Duration retryAfter() {
        return retryAfter == null || retryAfter.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : retryAfter;
    }

    /** {@link #retryAfter()} in whole seconds, rounded up, as the {@code Retry-After} header carries it (RFC 9110 10.2.3). */
    public long retryAfterSeconds() {
        Duration wait = retryAfter();
        return wait.getSeconds() + (wait.getNano() > 0 ? 1 : 0);
    }
}
