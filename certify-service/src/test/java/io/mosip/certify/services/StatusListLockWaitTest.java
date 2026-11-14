package io.mosip.certify.services;

import org.junit.jupiter.api.Test;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.PessimisticLockingFailureException;

import java.sql.SQLException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11d review round 5, finding 1: what counts as "the list's lock was not available in time", and the bound's
 * settings. The bound itself ({@code SET LOCAL lock_timeout}) is proved on PostgreSQL by
 * {@code StatusListPostgresTest.aStatusChangeOnALockedListIsRefusedRetryablyWithinTheBoundAndQueuesNothing} and
 * {@code aBatchRunSkipsALockedListWithinTheBoundAndAppliesTheOthers}.
 */
class StatusListLockWaitTest {

    @Test
    void postgresLockNotAvailableIsRecognisedWhereverSpringOrHibernateWrapsIt() {
        SQLException postgres = new SQLException("canceling statement due to lock timeout", "55P03");
        assertTrue(StatusListLockWait.lockNotAvailable(postgres));
        assertTrue(StatusListLockWait.lockNotAvailable(new PessimisticLockingFailureException("lock", postgres)));
        assertTrue(StatusListLockWait.lockNotAvailable(new CannotAcquireLockException("lock",
                new jakarta.persistence.PessimisticLockException("lock", postgres))));
        SQLException chained = new SQLException("batch failed", "XX000");
        chained.setNextException(postgres);
        assertTrue(StatusListLockWait.lockNotAvailable(new RuntimeException(chained)), "a chained SQLException");
    }

    @Test
    void otherFailuresAreNotRetryable() {
        assertFalse(StatusListLockWait.lockNotAvailable(new DataAccessResourceFailureException("connection refused",
                new SQLException("connection refused", "08001"))));
        assertFalse(StatusListLockWait.lockNotAvailable(new SQLException("deadlock detected", "40P01")));
        assertFalse(StatusListLockWait.lockNotAvailable(new SQLException("canceling statement due to statement timeout",
                "57014")), "a statement timeout is not a lock that was not available");
        assertFalse(StatusListLockWait.lockNotAvailable(new IllegalStateException("no SQL at all")));
        assertFalse(StatusListLockWait.lockNotAvailable(null));
    }

    @Test
    void aLockNotAvailableBecomesTheRetryableRefusalAndAnythingElsePassesThrough() {
        StatusListLockWait wait = StatusListLockWait.withoutDatabase();
        PessimisticLockingFailureException lock = new PessimisticLockingFailureException("lock",
                new SQLException("canceling statement due to lock timeout", "55P03"));
        StatusListBusyException busy = assertThrows(StatusListBusyException.class, () -> wait.bounded("list-1", () -> {
            throw lock;
        }));
        assertEquals("status_list_busy_retry_later", busy.getErrorCode());
        assertEquals("list-1", busy.listId());
        assertSame(lock, busy.getCause());
        assertEquals(Duration.ofSeconds(5), busy.waited());
        assertEquals(5, busy.retryAfterSeconds());

        IllegalStateException other = new IllegalStateException("not a lock");
        assertSame(other, assertThrows(IllegalStateException.class, () -> wait.bounded("list-1", () -> {
            throw other;
        })));
        AtomicInteger calls = new AtomicInteger();
        assertEquals(Optional.of("row"), wait.bounded("list-1", () -> {
            calls.incrementAndGet();
            return Optional.of("row");
        }));
        assertEquals(1, calls.get());
    }

    @Test
    void theLockWaitIsAPositiveBoundedDurationDefaultingToFiveSeconds() {
        assertEquals(Duration.ofSeconds(5), StatusUpdateProperties.defaults().lockWait());
        assertEquals(Duration.ofMillis(1), new StatusUpdateProperties(Duration.ofMillis(1)).lockWait());
        assertThrows(IllegalArgumentException.class, () -> new StatusUpdateProperties(Duration.ZERO),
                "zero is lock_timeout's 'wait for ever'");
        assertThrows(IllegalArgumentException.class, () -> new StatusUpdateProperties(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> new StatusUpdateProperties(Duration.ofNanos(999_999)));
        assertThrows(IllegalArgumentException.class, () -> new StatusUpdateProperties(
                Duration.ofMillis(Integer.MAX_VALUE).plusMillis(1)));
        // Retry-After is whole seconds, at least one
        assertEquals(1, new StatusListBusyException("l", Duration.ofMillis(200), null).retryAfterSeconds());
        assertEquals(3, new StatusListBusyException("l", Duration.ofMillis(2_001), null).retryAfterSeconds());
    }
}
