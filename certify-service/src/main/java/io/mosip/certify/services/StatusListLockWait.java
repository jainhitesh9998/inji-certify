package io.mosip.certify.services;

import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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
 * {@code SKIP LOCKED} (-2), and any other value is ignored. So before the lock is taken, {@code SET LOCAL lock_timeout}
 * bounds every lock wait of the rest of the caller's transaction to {@code certify.status.update.lock-wait}; the setting
 * ends with that transaction and never leaks into the pooled connection. PostgreSQL then fails the lock with SQLState
 * {@value #POSTGRES_LOCK_NOT_AVAILABLE} ({@code lock_not_available}), which is raised here as a
 * {@link StatusListBusyException}; the caller's transaction rolls back, so nothing is queued or written.
 *
 * <p>Other databases: the statement is PostgreSQL's, so it runs only when the connection's
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
    public <T> T bounded(String listId, Supplier<T> lock) {
        boundTheWait();
        try {
            return lock.get();
        } catch (RuntimeException e) {
            if (lockNotAvailable(e)) {
                log.warn("Status list {} is locked by another writer (the batch job signing it, or a status change) and"
                        + " its lock was not available within {} (certify.status.update.lock-wait); refused as retryable",
                        listId, lockWait);
                throw new StatusListBusyException(listId, lockWait, e);
            }
            throw e;
        }
    }

    /** {@code SET LOCAL lock_timeout} on PostgreSQL, in the caller's transaction; nothing elsewhere. */
    private void boundTheWait() {
        if (entityManager == null) {
            return;
        }
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            // SET LOCAL outside a transaction block is a no-op on PostgreSQL: the wait would not be bounded at all
            throw new IllegalStateException("A status list's row lock is taken inside a transaction, so its wait can be"
                    + " bounded for that transaction only");
        }
        long millis = Math.max(1L, lockWait.toMillis());
        entityManager.unwrap(Session.class).doWork(connection -> {
            Boolean known = postgres;
            if (known == null) {
                known = "PostgreSQL".equalsIgnoreCase(connection.getMetaData().getDatabaseProductName());
                postgres = known;
                if (!known) {
                    log.info("Status list lock waits are bounded by the database's own lock timeout on {};"
                                    + " certify.status.update.lock-wait ({}) applies on PostgreSQL",
                            connection.getMetaData().getDatabaseProductName(), lockWait);
                }
            }
            if (known) {
                try (Statement statement = connection.createStatement()) {
                    // a literal: SET takes no bind parameter, and the value is a number this class formats
                    statement.execute("SET LOCAL lock_timeout = '" + millis + "ms'");
                }
            }
        });
    }

    /**
     * Whether {@code failure} is a lock that was not available in time: PostgreSQL {@value #POSTGRES_LOCK_NOT_AVAILABLE},
     * wherever it sits in the cause chain (Spring and Hibernate wrap the driver's exception in their own, whose classes
     * differ by version and lock mode).
     */
    public static boolean lockNotAvailable(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof SQLException sql) {
                for (SQLException next = sql; next != null; next = next.getNextException()) {
                    if (POSTGRES_LOCK_NOT_AVAILABLE.equals(next.getSQLState())) {
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
