package io.mosip.certify.services;

import io.mosip.certify.status.TokenStatusListProperties;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The lists the status-list batch job holds back after a failed update (M-11d review round 2, majors 1-3): a transient
 * failure is retried on the next run and then with a back-off that doubles up to {@code retry-backoff-max}; a permanent
 * refusal is quarantined for {@code quarantine}, or until the trust material it was refused under changes. A held list's
 * transactions stay pending and the job's selection excludes it, so none of them is applied before an older one and none
 * of them fills another list's window. A success forgets the list.
 *
 * <p>In memory, per instance: the job runs on one instance at a time (ShedLock), so another instance taking the next run
 * starts without this state and simply tries the list again — more attempts, never a lost or reordered transaction.
 * Persisting holds would need a table, which this package does not add (D-M11-4).
 */
final class StatusListUpdateHolds {

    enum Kind { BACKOFF, QUARANTINE }

    /**
     * Why and until when a list is held. {@code failures} counts consecutive failures of the same kind, so a back-off
     * grows and a repeated quarantine is logged without the first one's ERROR; {@code trust} is the trust-material version
     * a quarantine was decided under.
     */
    record Hold(Kind kind, Instant until, int failures, String rule, String reason, int trust) {}

    private final Map<String, Hold> holds = new ConcurrentHashMap<>();

    /**
     * The lists held at {@code now}: a back-off or quarantine still running, a quarantine only while the trust material
     * is the one it was decided under. A hold that ended stays recorded (its failure count drives the next back-off) but
     * no longer excludes the list.
     */
    Set<String> held(Instant now, int trust) {
        Set<String> held = new LinkedHashSet<>();
        holds.forEach((listId, hold) -> {
            if (isHeld(hold, now, trust)) {
                held.add(listId);
            }
        });
        return held;
    }

    /** The quarantined lists still held at {@code now}, with their holds. */
    Map<String, Hold> quarantined(Instant now, int trust) {
        Map<String, Hold> quarantined = new LinkedHashMap<>();
        holds.forEach((listId, hold) -> {
            if (hold.kind() == Kind.QUARANTINE && isHeld(hold, now, trust)) {
                quarantined.put(listId, hold);
            }
        });
        return quarantined;
    }

    /** The lists backing off after transient failures, still held at {@code now}. */
    Map<String, Hold> backingOff(Instant now) {
        Map<String, Hold> backingOff = new LinkedHashMap<>();
        holds.forEach((listId, hold) -> {
            if (hold.kind() == Kind.BACKOFF && now.isBefore(hold.until())) {
                backingOff.put(listId, hold);
            }
        });
        return backingOff;
    }

    private static boolean isHeld(Hold hold, Instant now, int trust) {
        if (!now.isBefore(hold.until())) {
            return false;
        }
        // a CRL refreshed, an anchor added or replaced: the refusal may not hold any more, so the next run tries again
        return hold.kind() != Kind.QUARANTINE || hold.trust() == trust;
    }

    /**
     * A transient failure: the first of a streak is retried on the next run (the list is excluded for the rest of this
     * one only), each further one waits {@code retry-backoff}, doubled per failure, at most {@code retry-backoff-max}.
     */
    Hold backOff(String listId, Instant now, String rule, String reason, TokenStatusListProperties.Batch settings) {
        Hold prior = holds.get(listId);
        int failures = prior != null && prior.kind() == Kind.BACKOFF ? prior.failures() + 1 : 1;
        Duration delay = failures == 1 ? Duration.ZERO : delay(failures - 1, settings);
        Hold hold = new Hold(Kind.BACKOFF, now.plus(delay), failures, rule, reason, 0);
        holds.put(listId, hold);
        return hold;
    }

    private static Duration delay(int attempt, TokenStatusListProperties.Batch settings) {
        Duration delay = settings.retryBackoff();
        for (int doubling = 1; doubling < attempt && delay.compareTo(settings.retryBackoffMax()) < 0; doubling++) {
            delay = delay.multipliedBy(2);
        }
        return delay.compareTo(settings.retryBackoffMax()) > 0 ? settings.retryBackoffMax() : delay;
    }

    /** A permanent refusal: held for {@code quarantine}, or until the trust material moves from {@code trust}. */
    Hold quarantine(String listId, Instant now, String rule, String reason, int trust,
                    TokenStatusListProperties.Batch settings) {
        Hold prior = holds.get(listId);
        int failures = prior != null && prior.kind() == Kind.QUARANTINE ? prior.failures() + 1 : 1;
        Hold hold = new Hold(Kind.QUARANTINE, now.plus(settings.quarantine()), failures, rule, reason, trust);
        holds.put(listId, hold);
        return hold;
    }

    /** The list was updated (or retired): it is no longer held, and its next failure starts a new streak. */
    Hold succeeded(String listId) {
        return holds.remove(Objects.requireNonNull(listId, "listId"));
    }
}
