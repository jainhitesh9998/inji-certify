package io.mosip.certify.services;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.StatusListRetiredException;
import io.mosip.certify.status.StatusListSignerPolicy;
import io.mosip.certify.status.TokenStatusListService;
import io.mosip.certify.status.TokenStatusListUpdateException;
import net.javacrumbs.shedlock.core.LockAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The batch job never applies a list's transactions out of order, never lets a list it cannot update starve the others,
 * and never parks one silently (M-11d review rounds 1 and 2).
 *
 * <p>The transaction table is an in-memory one that behaves as the queries do: pending rows that name a list, oldest
 * first (creation time, then id), without the lists the job excludes, at most the page size. The token-list service is
 * a mock whose {@code update} is scripted per test.
 */
class StatusListUpdateBatchJobStuckListsTest {

    static final Instant T0 = Instant.parse("2026-11-14T10:00:00Z");

    final InMemoryStatusTransactions table = new InMemoryStatusTransactions();
    final StatusListCredentialRepository lists = mock(StatusListCredentialRepository.class);
    final TokenStatusListService tokenLists = mock(TokenStatusListService.class);
    final StatusListUpdateBatchJob job = new StatusListUpdateBatchJob();
    final MutableClock clock = new MutableClock(T0);
    final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    /** The status maps {@code update} applied, per list, in the order it applied them. */
    final List<String> applied = new CopyOnWriteArrayList<>();
    final AtomicInteger trust = new AtomicInteger();

    @BeforeEach
    void setUp() {
        LockAssert.TestHelper.makeAllAssertsPass(true);
        @SuppressWarnings("unchecked")
        ObjectProvider<TokenStatusListService> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(tokenLists);
        when(tokenLists.trustMaterialVersion()).thenAnswer(inv -> trust.get());
        ReflectionTestUtils.setField(job, "transactionRepository", table.repository);
        ReflectionTestUtils.setField(job, "statusListRepository", lists);
        ReflectionTestUtils.setField(job, "tokenStatusLists", provider);
        ReflectionTestUtils.setField(job, "statusListCredentialService", mock(StatusListCredentialService.class));
        ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        ReflectionTestUtils.setField(job, "batchSize", 1);
        job.setClock(clock);
        job.bindMetrics(meters);
        when(lists.findById(anyString())).thenAnswer(inv -> Optional.of(row(inv.getArgument(0))));
        Logger logger = (Logger) LoggerFactory.getLogger(StatusListUpdateBatchJob.class);
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        LockAssert.TestHelper.makeAllAssertsPass(false);
        ((Logger) LoggerFactory.getLogger(StatusListUpdateBatchJob.class)).detachAppender(logs);
    }

    @Test
    void aRetiredListsTransactionsAreMarkedProcessedWithAWarn() {
        CredentialStatusTransaction stuck = table.add("cwt-retired", 3, true, T0);
        doAnswer(inv -> {
            throw new StatusListRetiredException("the pinned signer expired");
        }).when(tokenLists).update(any(StatusListCredential.class), any());

        job.updateStatusLists();

        assertTrue(stuck.getIsProcessed(), "the transaction is closed instead of blocking the queue");
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                && event.getFormattedMessage().contains("retired")), messages());
    }

    /**
     * Review round 2, major 1, the reviewer's reproduction: batch size 1, an older {@code {5:false}} and a newer
     * {@code {5:true}} on one CWT list, and the first update fails transiently ("HSM session lost"). Before the fix the
     * job moved to the next page, applied the newer transaction alone, and applied the older one on top of it in the
     * next run: {@code [{5=true}, {5=false}]}, both processed, the revocation lost.
     */
    @Test
    void aListThatFailsIsNeverUpdatedWithANewerTransactionBeforeAnOlderOne() {
        table.add("cwt-hsm", 5, false, Instant.parse("2026-11-01T00:00:00Z"));
        table.add("cwt-hsm", 5, true, Instant.parse("2026-11-02T00:00:00Z"));
        script((row, statuses) -> {
            if (applied.isEmpty() && failOnce.compareAndSet(false, true)) {
                throw TokenStatusListUpdateException.signing(row.getId(), new IllegalStateException("HSM session lost"));
            }
            applied.add(row.getId() + statuses);
        });

        job.updateStatusLists();
        assertEquals(List.of(), applied, "nothing of the list is applied in the run its oldest transaction failed in");
        assertEquals(2, table.pending().size(), "both transactions stay pending");

        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists(); // batch size 1: one transaction per run, the older one first
        job.updateStatusLists();
        assertEquals(List.of("cwt-hsm{5=false}", "cwt-hsm{5=true}"), applied, "creation order, the revocation last");
        assertTrue(table.pending().isEmpty());
    }

    /** The same order for a JWT list, whose failure is retried on the next run as before (no back-off). */
    @Test
    void aJwtListThatFailsKeepsItsOrderAndIsRetriedOnTheNextRun() {
        table.add("jwt-a", 5, false, Instant.parse("2026-11-01T00:00:00Z"));
        table.add("jwt-a", 5, true, Instant.parse("2026-11-02T00:00:00Z"));
        script((row, statuses) -> {
            if (applied.isEmpty() && failOnce.compareAndSet(false, true)) {
                throw new IllegalStateException("keymanager unavailable");
            }
            applied.add(row.getId() + statuses);
        });

        job.updateStatusLists();
        assertEquals(List.of(), applied);
        job.updateStatusLists(); // same instant: a JWT list is not backed off
        job.updateStatusLists();
        assertEquals(List.of("jwt-a{5=false}", "jwt-a{5=true}"), applied);
    }

    /**
     * Review round 2, major 3: batch size 1 and sixty stuck rows of a list whose signer refuses permanently, ahead of a
     * healthy row. The old window paged with OFFSET up to {@code max-pages} (50) and never got there; the exclusion is in
     * the selection now, so the healthy row is processed in the first run, and the refused list is tried once.
     */
    @Test
    void stuckRowsOfAQuarantinedListDoNotStarveAHealthyRowBehindThem() {
        for (int index = 0; index < 60; index++) {
            table.add("cwt-revoked", index, true, T0.minusSeconds(3600 - index));
        }
        CredentialStatusTransaction healthy = table.add("jwt-healthy", 7, true, T0);
        AtomicInteger revokedAttempts = new AtomicInteger();
        script((row, statuses) -> {
            if ("cwt-revoked".equals(row.getId())) {
                revokedAttempts.incrementAndGet();
                throw TokenStatusListUpdateException.signing(row.getId(), new IllegalStateException(
                        StatusListSignerPolicy.REVOKED + ": the IACA revoked the Document Signer"));
            }
            applied.add(row.getId() + statuses);
        });

        job.updateStatusLists();

        assertTrue(healthy.getIsProcessed(), "the healthy row is processed in the first run");
        assertEquals(1, revokedAttempts.get(), "the refused list is tried once, not once per page");
        assertTrue(table.excludedSelections.stream().anyMatch(excluded -> excluded.contains("cwt-revoked")),
                "the exclusion is in the selection: " + table.excludedSelections);
        assertEquals(1, logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count(), messages());
        assertTrue(logs.list.stream().allMatch(event -> event.getLevel() != Level.ERROR || event.getThrowableProxy() == null),
                "a permanent refusal is no stack trace: " + messages());

        // observable every run: a WARN naming the list and its pending rows, and the gauges
        assertTrue(lastWarn().contains("cwt-revoked (60 pending, " + StatusListSignerPolicy.REVOKED), lastWarn());
        assertEquals(1.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value());
        assertEquals(60.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_TRANSACTIONS).gauge().value());

        // the next runs inside the quarantine exclude it from the start and do not try it, but still report it
        CredentialStatusTransaction later = table.add("jwt-healthy", 8, true, T0.plusSeconds(1));
        logs.list.clear();
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertTrue(later.getIsProcessed());
        assertEquals(1, revokedAttempts.get());
        assertEquals(0, logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count(), messages());
        assertTrue(lastWarn().contains("cwt-revoked (60 pending"), lastWarn());

        // after the quarantine it is tried again (an operator's fix is picked up without a restart)
        clock.advance(Duration.ofHours(1));
        job.updateStatusLists();
        assertEquals(2, revokedAttempts.get(), "tried again after the quarantine interval");
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                && event.getFormattedMessage().contains("still refused after its quarantine")), messages());
        assertEquals(60, table.pending().size(), "and its transactions are still pending, none dropped");
    }

    /** A change of the IACA trust material (a CRL refreshed, an anchor replaced) ends a quarantine at the next run. */
    @Test
    void aQuarantineEndsWhenTheTrustMaterialChanges() {
        table.add("cwt-revoked", 1, true, T0);
        AtomicReference<Boolean> revoked = new AtomicReference<>(true);
        script((row, statuses) -> {
            if (revoked.get()) {
                throw TokenStatusListUpdateException.signing(row.getId(), new IllegalStateException(
                        StatusListSignerPolicy.REVOKED + ": on hold"));
            }
            applied.add(row.getId() + statuses);
        });
        job.updateStatusLists();
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertEquals(List.of(), applied, "quarantined");

        revoked.set(false);
        trust.incrementAndGet(); // the IACA published a new CRL
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertEquals(List.of("cwt-revoked{1=true}"), applied, "released by the trust change, not the hour");
        assertEquals(0.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value());
        assertEquals(0.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_TRANSACTIONS).gauge().value());
    }

    /**
     * A transient failure is retried on the next run; a second consecutive one waits {@code retry-backoff} (1 minute by
     * default), a third twice that, and the list is reported as backing off meanwhile.
     */
    @Test
    void aTransientFailureIsRetriedOnTheNextRunThenBacksOff() {
        table.add("cwt-flaky", 2, true, T0);
        AtomicInteger attempts = new AtomicInteger();
        AtomicReference<Boolean> failing = new AtomicReference<>(true);
        script((row, statuses) -> {
            attempts.incrementAndGet();
            if (failing.get()) {
                throw TokenStatusListUpdateException.signing(row.getId(), new IllegalStateException(
                        "STATUS_SIGNER_GONE: the pinned signer cannot be resolved", new RuntimeException("HSM down")));
            }
            applied.add(row.getId() + statuses);
        });

        job.updateStatusLists();
        assertEquals(1, attempts.get());
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.ERROR && event.getThrowableProxy() != null),
                "the first transient failure is an ERROR with its stack trace: " + messages());
        job.updateStatusLists(); // the next run: retried at once
        assertEquals(2, attempts.get(), "a transient failure is retried on the next run");
        job.updateStatusLists(); // within retry-backoff of the second failure
        assertEquals(2, attempts.get(), "then it backs off");
        assertTrue(lastWarn().contains("cwt-flaky (1 pending, STATUS_SIGNER_GONE"), lastWarn());
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertEquals(3, attempts.get());
        clock.advance(Duration.ofMinutes(1)); // the third failure waits two minutes
        job.updateStatusLists();
        assertEquals(3, attempts.get());

        failing.set(false);
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertEquals(List.of("cwt-flaky{2=true}"), applied);
        assertTrue(table.pending().isEmpty());
        assertTrue(logs.list.stream().anyMatch(event -> event.getFormattedMessage().contains("updated again after 3 failed")),
                messages());
    }

    // ---------------------------------------------------------------------------------------------------------------

    final java.util.concurrent.atomic.AtomicBoolean failOnce = new java.util.concurrent.atomic.AtomicBoolean();

    private void script(BiConsumer<StatusListCredential, Map<Long, Boolean>> update) {
        doAnswer(inv -> {
            update.accept(inv.getArgument(0), new java.util.TreeMap<>(inv.<Map<Long, Boolean>>getArgument(1)));
            return null;
        }).when(tokenLists).update(any(StatusListCredential.class), any());
    }

    private String lastWarn() {
        return logs.list.stream().filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).reduce((first, second) -> second).orElse("");
    }

    private String messages() {
        return logs.list.stream().map(event -> event.getLevel() + " " + event.getFormattedMessage()).toList().toString();
    }

    private static StatusListCredential row(String id) {
        StatusListCredential row = new StatusListCredential();
        row.setId(id);
        row.setVcDocument("{}");
        row.setCredentialType(id.startsWith("jwt") ? TokenStatusListService.TYPE : TokenStatusListService.TYPE_CWT);
        row.setStatusPurpose("revocation");
        row.setCapacityInKB(1L);
        row.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        row.setCreatedDtimes(LocalDateTime.now());
        return row;
    }

    /** A clock the test moves. */
    static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            now = new AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(instant -> instant.plus(by));
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }
    }
}
