package io.mosip.certify.services;

import io.mosip.certify.core.exception.StatusListBusyException;
import jakarta.persistence.EntityManager;
import org.hibernate.Session;
import org.hibernate.jdbc.ReturningWork;
import org.hibernate.jdbc.Work;
import org.junit.jupiter.api.Test;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * M-11d review round 5, finding 1: what counts as "the list's lock was not available in time", the statements that bound
 * the wait on PostgreSQL, and the bound's settings. The bound itself is proved on PostgreSQL by
 * {@code StatusListPostgresTest.aStatusChangeOnALockedListIsRefusedRetryablyWithinTheBoundAndQueuesNothing},
 * {@code aStatusChangeQueuedBehindAnotherWaiterIsStillRefusedWithinTheBound} and
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

    // ---- M-11d CI fix: the lock statement is bounded as a whole (statement_timeout), not per lock acquisition ----------

    @Test
    void onPostgresTheLockStatementIsBoundedAsAWholeAndItsStatementTimeoutIsPutBackOnceTheLockIsHeld() throws Exception {
        List<String> sql = new ArrayList<>();
        StatusListLockWait wait = new StatusListLockWait(entityManager("PostgreSQL", "0", sql), StatusUpdateProperties.defaults());
        assertEquals("row", inTransaction(() -> wait.bounded("list-1", () -> {
            sql.add("LOCK");
            return "row";
        })));
        assertEquals(List.of("SELECT setting FROM pg_settings WHERE name = 'statement_timeout'",
                "SET LOCAL lock_timeout = '5000ms'", "SET LOCAL statement_timeout = '5000ms'", "LOCK",
                "SET LOCAL statement_timeout = '0ms'"), sql);
    }

    @Test
    void aShorterStatementTimeoutAlreadyInForceIsKeptAndPutBack() throws Exception {
        List<String> sql = new ArrayList<>();
        StatusListLockWait wait = new StatusListLockWait(entityManager("PostgreSQL", "2000", sql), StatusUpdateProperties.defaults());
        inTransaction(() -> wait.bounded("list-1", () -> sql.add("LOCK")));
        assertEquals(List.of("SELECT setting FROM pg_settings WHERE name = 'statement_timeout'",
                "SET LOCAL lock_timeout = '5000ms'", "SET LOCAL statement_timeout = '2000ms'", "LOCK",
                "SET LOCAL statement_timeout = '2000ms'"), sql);
    }

    @Test
    void theBoundedLockStatementTimingOutIsTheRetryableRefusalAndNothingIsPutBackInTheAbortedTransaction() throws Exception {
        List<String> sql = new ArrayList<>();
        StatusListLockWait wait = new StatusListLockWait(entityManager("PostgreSQL", "0", sql), StatusUpdateProperties.defaults());
        QueryTimeoutException timeout = new QueryTimeoutException("lock",
                new SQLException("canceling statement due to statement timeout", "57014"));
        StatusListBusyException busy = assertThrows(StatusListBusyException.class, () -> inTransaction(() ->
                wait.bounded("list-1", () -> {
                    throw timeout;
                })));
        assertSame(timeout, busy.getCause());
        assertEquals("status_list_busy_retry_later", busy.getErrorCode());
        assertEquals("SET LOCAL statement_timeout = '5000ms'", sql.get(sql.size() - 1), "no statement after the failure");
    }

    @Test
    void elsewhereNothingIsSetAndAStatementTimeoutIsNotALockThatWasNotAvailable() throws Exception {
        List<String> sql = new ArrayList<>();
        StatusListLockWait wait = new StatusListLockWait(entityManager("H2", "0", sql), StatusUpdateProperties.defaults());
        assertEquals("row", inTransaction(() -> wait.bounded("list-1", () -> "row")));
        assertTrue(sql.isEmpty(), String.valueOf(sql));
        QueryTimeoutException timeout = new QueryTimeoutException("query",
                new SQLException("canceling statement due to statement timeout", "57014"));
        assertSame(timeout, assertThrows(QueryTimeoutException.class, () -> inTransaction(() ->
                wait.bounded("list-1", () -> {
                    throw timeout;
                }))));
    }

    @Test
    void theWaitIsBoundedInsideATransactionOnly() throws Exception {
        StatusListLockWait wait = new StatusListLockWait(entityManager("PostgreSQL", "0", new ArrayList<>()),
                StatusUpdateProperties.defaults());
        assertThrows(IllegalStateException.class, () -> wait.bounded("list-1", () -> "row"));
    }

    private static <T> T inTransaction(Supplier<T> body) {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            return body.get();
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    /** A session on a database named {@code product} whose {@code statement_timeout} is {@code statementTimeout}. */
    private static EntityManager entityManager(String product, String statementTimeout, List<String> sql) throws Exception {
        DatabaseMetaData metaData = mock(DatabaseMetaData.class);
        when(metaData.getDatabaseProductName()).thenReturn(product);
        ResultSet setting = mock(ResultSet.class);
        when(setting.next()).thenReturn(true);
        when(setting.getString(1)).thenReturn(statementTimeout);
        Statement statement = mock(Statement.class);
        when(statement.executeQuery(anyString())).thenAnswer(inv -> {
            sql.add(inv.getArgument(0));
            return setting;
        });
        when(statement.execute(anyString())).thenAnswer(inv -> sql.add(inv.getArgument(0)) && false);
        Connection connection = mock(Connection.class);
        when(connection.getMetaData()).thenReturn(metaData);
        when(connection.createStatement()).thenReturn(statement);
        Session session = mock(Session.class);
        when(session.doReturningWork(any())).thenAnswer(inv -> ((ReturningWork<?>) inv.getArgument(0)).execute(connection));
        doAnswer(inv -> {
            ((Work) inv.getArgument(0)).execute(connection);
            return null;
        }).when(session).doWork(any());
        EntityManager entityManager = mock(EntityManager.class);
        when(entityManager.unwrap(Session.class)).thenReturn(session);
        return entityManager;
    }
}
