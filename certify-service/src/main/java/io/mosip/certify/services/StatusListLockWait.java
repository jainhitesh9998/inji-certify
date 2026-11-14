package io.mosip.certify.services;

import io.mosip.certify.core.exception.StatusListBusyException;
import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.function.Supplier;

/**
 * Takes a status list's row lock with a bounded wait (M-11d review round 5, finding 1).
 *
 * <p>The batch job applies a list under its row lock ({@code SELECT … FOR NO KEY UPDATE},
 * {@code StatusListCredentialRepository.findByIdForUpdate}) and holds it while it signs the list — a network HSM or KMS
 * call that can hang. A status change takes the same lock before it queues its transaction (the ordering of G42), so an
 * unbounded wait would pin a request thread and a pooled connection per waiting request; a bulk revocation against a
 * list whose signer hangs could drain the pool and stop issuance as well.
 *
 * <p>Hibernate cannot express a bounded wait on PostgreSQL: its lock-timeout hint renders only {@code NOWAIT} (0) or
 * {@code SKIP LOCKED} (-2), and any other value is ignored. So before the lock is taken, in the caller's transaction:
 * <ul>
 *   <li>{@code SET LOCAL statement_timeout} bounds the lock statement as a whole to {@code certify.status.update.lock-wait}
 *   (or to the {@code statement_timeout} already in force when that is shorter), and is put back to that value as soon
 *   as the lock is held. This is the bound. {@code lock_timeout} alone is not one: PostgreSQL applies it to each
 *   lock acquisition separately, and a row lock that another session is already waiting for takes two — the tuple lock
 *   that queues the waiters, then the holder's transaction — so the second waiter of a held list waited for up to twice
 *   the bound, longer still behind a multixact (M-11d CI fix: {@code 10.003 s} against a {@code 5 s} bound, the third of
 *   three status changes for one list);</li>
 *   <li>{@code SET LOCAL lock_timeout} bounds every single lock wait of the rest of the caller's transaction to the same
 *   value, as before.</li>
 * </ul>
 * Both settings end with that transaction and never leak into the pooled connection. PostgreSQL then fails the lock with
 * SQLState {@value #POSTGRES_QUERY_CANCELED} ({@code query_canceled}: the statement timeout) or
 * {@value #POSTGRES_LOCK_NOT_AVAILABLE} ({@code lock_not_available}: the lock timeout), which is raised here as a
 * {@link StatusListBusyException}; the caller's transaction rolls back, so nothing is queued or written.
 *
 * <p>Other databases: the statements are PostgreSQL's, so they run only when the connection's
 * {@code DatabaseMetaData.getDatabaseProductName()} is {@code PostgreSQL} — read from the connection, not from the
 * Hibernate dialect, because an H2 test context that activates the {@code local} profile keeps that profile's
 * {@code PostgreSQLDialect}. Another database keeps its own lock timeout and its own failure: H2 (a test database, not
 * on the runtime classpath) bounds every lock wait by its {@code LOCK_TIMEOUT}, two seconds by default in 2.2, but raises
 * its timeout as a {@code SQLTimeoutException}, which Hikari treats as a broken connection and evicts, so the caller sees
 * the failed rollback rather than a {@link StatusListBusyException}.
 */
@Slf4j
@Component
@EnableConfigurationProperties(StatusUpdateProperties.class)
public class StatusListLockWait {

    /** PostgreSQL {@code lock_not_available}: {@code lock_timeout} expired, or a {@code NOWAIT} lock was taken. */
    public static final String POSTGRES_LOCK_NOT_AVAILABLE = "55P03";

    /**
     * PostgreSQL {@code query_canceled}: {@code statement_timeout} expired (or the statement was cancelled). A refusal
     * only for the lock statement this class bounded; anywhere else it is not a lock that was not available.
     */
    public static final String POSTGRES_QUERY_CANCELED = "57014";

    /** The transaction's session, or {@code null} for a caller whose repository is not a database (unit tests). */
    private final EntityManager entityManager;
    private final Duration lockWait;
    /** Whether the database is PostgreSQL, read once from the first connection (one data source per application). */
    private volatile Boolean postgres;

    @Autowired
    public StatusListLockWait(EntityManager entityManager, StatusUpdateProperties properties) {
        this.entityManager = entityManager;
        this.lockWait = (properties == null ? StatusUpdateProperties.defaults() : properties).lockWait();
    }

    /**
     * No statement is run: for callers whose repository is not a database (unit tests). A lock failure the repository
     * raises is still recognised and raised as {@link StatusListBusyException}.
     */
    public static StatusListLockWait withoutDatabase() {
        return new StatusListLockWait(null, StatusUpdateProperties.defaults());
    }

    /** How long a lock is waited for: {@code certify.status.update.lock-wait}. */
    public Duration lockWait() {
        return lockWait;
    }

    /**
     * Runs {@code lock} — a {@code SELECT … FOR UPDATE} of the list's row — with the wait bounded by {@link #lockWait()}.
     * Must run inside the caller's transaction: the bound is that transaction's, and so is the lock.
     *
     * @throws StatusListBusyException the lock was not available in time; the transaction must roll back (it is aborted
     *                                 on PostgreSQL), which throwing this out of a {@code @Transactional} method does
     */
    /** The innermost cause's message: PostgreSQL's own text (a lock timeout, a statement timeout or a cancel). */
    private static String rootMessage(Throwable failure) {
        Throwable root = failure;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root.getMessage();
    }

    public <T> T bounded(String listId, Supplier<T> lock) {
        Long statementTimeoutBefore = boundTheWait();
        T locked;
        try {
            locked = lock.get();
        } catch (RuntimeException e) {
            if (lockNotAvailable(e) || (statementTimeoutBefore != null && hasSqlState(e, POSTGRES_QUERY_CANCELED))) {
                // 57014 is also what an explicit cancel (pg_cancel_backend) raises: the refusal is the same (rolled back,
                // retryable), and the WARN carries PostgreSQL's own message so a cancel is not read as contention
                log.warn("Status list {} is locked by another writer (the batch job signing it, or a status change) and"
                        + " its lock was not available within {} (certify.status.update.lock-wait); refused as retryable"
                        + " (database: {})", listId, lockWait, rootMessage(e));
                throw new StatusListBusyException(listId, lockWait, e);
            }
            throw e;
        }
        if (statementTimeoutBefore != null) {
            // the lock is held: the rest of the caller's transaction runs under the statement_timeout it had before.
            // After a failure there is nothing to put back: the transaction is aborted and its SET LOCALs end with it.
            setLocal("statement_timeout", statementTimeoutBefore);
        }
        return locked;
    }

    /**
     * On PostgreSQL, in the caller's transaction: {@code SET LOCAL lock_timeout} for the rest of it and
     * {@code SET LOCAL statement_timeout} for the lock statement; nothing elsewhere.
     *
     * @return the {@code statement_timeout} in force before, in milliseconds ({@code 0}: none), to put back once the
     * lock is held; {@code null} when nothing was set (no database, or not PostgreSQL)
     */
    private Long boundTheWait() {
        if (entityManager == null) {
            return null;
        }
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            // SET LOCAL outside a transaction block is a no-op on PostgreSQL: the wait would not be bounded at all
            throw new IllegalStateException("A status list's row lock is taken inside a transaction, so its wait can be"
                    + " bounded for that transaction only");
        }
        long millis = Math.max(1L, lockWait.toMillis());
        return entityManager.unwrap(Session.class).doReturningWork(connection -> {
            if (!postgres(connection)) {
                return null;
            }
            long before;
            try (Statement statement = connection.createStatement();
                 ResultSet setting = statement.executeQuery(
                         "SELECT setting FROM pg_settings WHERE name = 'statement_timeout'")) { // milliseconds
                setting.next();
                before = Long.parseLong(setting.getString(1));
            }
            // a shorter statement_timeout the deployment set is kept: the bound only ever tightens it
            long statement = before > 0 && before < millis ? before : millis;
            try (Statement set = connection.createStatement()) {
                // literals: SET takes no bind parameter, and the values are numbers this class formats
                set.execute("SET LOCAL lock_timeout = '" + millis + "ms'");
                set.execute("SET LOCAL statement_timeout = '" + statement + "ms'");
            }
            return before;
        });
    }

    private boolean postgres(Connection connection) throws SQLException {
        Boolean known = postgres;
        if (known == null) {
            String product = connection.getMetaData().getDatabaseProductName();
            known = "PostgreSQL".equalsIgnoreCase(product);
            postgres = known;
            if (!known) {
                log.info("Status list lock waits are bounded by the database's own lock timeout on {};"
                        + " certify.status.update.lock-wait ({}) applies on PostgreSQL", product, lockWait);
            }
        }
        return known;
    }

    private void setLocal(String parameter, long millis) {
        entityManager.unwrap(Session.class).doWork(connection -> {
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET LOCAL " + parameter + " = '" + millis + "ms'");
            }
        });
    }

    /**
     * Whether {@code failure} is a lock that was not available in time: PostgreSQL {@value #POSTGRES_LOCK_NOT_AVAILABLE},
     * wherever it sits in the cause chain (Spring and Hibernate wrap the driver's exception in their own, whose classes
     * differ by version and lock mode). A statement timeout ({@value #POSTGRES_QUERY_CANCELED}) is not one in general;
     * {@link #bounded} recognises it for the one statement it bounded.
     */
    public static boolean lockNotAvailable(Throwable failure) {
        return hasSqlState(failure, POSTGRES_LOCK_NOT_AVAILABLE);
    }

    /** Whether an {@link SQLException} with {@code sqlState} is anywhere in {@code failure}'s cause or next chain. */
    private static boolean hasSqlState(Throwable failure, String sqlState) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof SQLException sql) {
                for (SQLException next = sql; next != null; next = next.getNextException()) {
                    if (sqlState.equals(next.getSQLState())) {
                        return true;
                    }
                    if (next.getNextException() == next) {
                        break;
                    }
                }
            }
        }
        return false;
    }
}
