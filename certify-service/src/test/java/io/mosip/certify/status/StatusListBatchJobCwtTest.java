package io.mosip.certify.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.certify.services.InMemoryStatusTransactions;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.services.StatusListTransactionApplier;
import io.mosip.certify.services.StatusListUpdateBatchJob;
import net.javacrumbs.shedlock.core.LockAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.freshCrl;
import static io.mosip.certify.status.StatusListTestKeys.staleCrl;
import static io.mosip.certify.status.TokenStatusListCwtServiceTest.T0;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * M-11d review round 2, major 2, through the real service and the real batch job: a CWT list whose update fails is held
 * back by what the failure is, never parked until a restart, and its revocations are applied in creation order once it
 * can be signed again.
 * <ul>
 *   <li>a provider outage (the HSM session is lost) is transient: tried again on the next run, then applied in order;</li>
 *   <li>{@code CRL_STALE} is transient: once the IACA's CRL is refreshed the next run publishes the revocation, with the
 *   same service instance;</li>
 *   <li>{@code STATUS_SIGNER_REVOKED} is permanent: quarantined, reported every run (a WARN with the pending
 *   transactions and the gauges), tried again after the quarantine, and released at once when the CRL changes;</li>
 *   <li>a stored token its pinned signer did not sign is permanent and observable, with no stack trace on any run.</li>
 * </ul>
 */
class StatusListBatchJobCwtTest {

    final TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
    final TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(T0);
    final InMemoryStatusTransactions table = new InMemoryStatusTransactions();
    final StatusListUpdateBatchJob job = new StatusListUpdateBatchJob();
    final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    TokenStatusListService lists;
    String listId;
    long idx;

    @BeforeEach
    void setUp() {
        LockAssert.TestHelper.makeAllAssertsPass(true);
        lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        listId = fixture.listId(entry);
        idx = entry.idx();
        wire(job);
        job.bindMetrics(meters);
        logs.start();
        for (Class<?> source : List.of(StatusListUpdateBatchJob.class, StatusListTransactionApplier.class, TokenStatusListService.class)) {
            ((Logger) LoggerFactory.getLogger(source)).addAppender(logs);
        }
    }

    @AfterEach
    void tearDown() {
        LockAssert.TestHelper.makeAllAssertsPass(false);
        for (Class<?> source : List.of(StatusListUpdateBatchJob.class, StatusListTransactionApplier.class, TokenStatusListService.class)) {
            ((Logger) LoggerFactory.getLogger(source)).detachAppender(logs);
        }
    }

    @Test
    void aProviderOutageIsRetriedOnTheNextRunAndTheRevocationsLandInOrder() {
        table.add(listId, idx, false, T0.minusSeconds(120)); // the older transaction: reinstated
        table.add(listId, idx, true, T0.minusSeconds(60));   // the newer one: revoked
        fixture.switching.failSigning.set(true);             // "HSM session lost"

        job.updateStatusLists();
        assertEquals(2, table.pending().size(), "nothing applied, nothing dropped");
        assertFalse(bit(), "the stored list is unchanged");
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.ERROR
                && event.getFormattedMessage().contains("tried again on the next run")), messages());

        fixture.switching.failSigning.set(false);
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists(); // batch size 1: the older transaction
        assertFalse(bit());
        job.updateStatusLists(); // then the newer one
        assertTrue(bit(), "the revocation, created last, is what the list says");
        assertTrue(table.pending().isEmpty());
        assertEquals(DSC, TokenStatusListCwt.decode(token()).x5chain().get(0), "re-signed by the pinned signer");
    }

    @Test
    void aStaleCrlIsRecoveredAfterTheCrlIsRefreshedWithoutARestart() {
        fixture.registry.enforced.set(true);
        fixture.registry.crl.set(staleCrl());
        table.add(listId, idx, true, T0);

        job.updateStatusLists();
        assertEquals(1, table.pending().size());
        assertTrue(logs.list.stream().anyMatch(event -> event.getFormattedMessage().contains(StatusListSignerPolicy.CRL_STALE)),
                messages());

        fixture.registry.crl.set(freshCrl()); // the operator publishes a new CRL; same job, same service
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        assertTrue(table.pending().isEmpty(), "applied once the CRL is fresh");
        assertTrue(bit());
    }

    @Test
    void aRevokedSignerIsQuarantinedObservableAndRetriedAfterTheInterval() {
        fixture.registry.enforced.set(true);
        fixture.registry.crl.set(StatusListTestKeys.crl(T0.minus(Duration.ofHours(1)), T0.plus(Duration.ofDays(1)),
                DSC.getSerialNumber()));
        table.add(listId, idx, true, T0);
        table.add(listId, idx + 1, true, T0.plusSeconds(1));

        job.updateStatusLists();
        int signedAfterRefusal = fixture.signed.get();
        assertEquals(2, table.pending().size());
        assertEquals(1, errors(), messages());
        assertTrue(lastWarn().contains(listId + " (2 pending, " + StatusListSignerPolicy.REVOKED), lastWarn());
        assertEquals(1.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value());
        assertEquals(2.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_TRANSACTIONS).gauge().value());

        logs.list.clear();
        clock.advance(Duration.ofMinutes(30));
        job.updateStatusLists(); // inside the quarantine: not tried, still reported
        assertEquals(0, errors(), messages());
        assertTrue(lastWarn().contains(listId + " (2 pending"), lastWarn());
        assertTrue(logs.list.stream().noneMatch(event -> event.getFormattedMessage().contains("still refused")), messages());

        clock.advance(Duration.ofMinutes(31));
        job.updateStatusLists(); // after it: tried again, refused again, quarantined again without a new ERROR
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                && event.getFormattedMessage().contains("still refused after its quarantine")), messages());
        assertEquals(0, errors(), messages());
        assertEquals(signedAfterRefusal, fixture.signed.get(), "a refused signer signs nothing");

        // the IACA lifts the revocation (a new CRL): the quarantine ends at the next run, not after another hour
        fixture.registry.crl.set(StatusListTestKeys.crl(T0, T0.plus(Duration.ofDays(1))));
        clock.advance(Duration.ofMinutes(1));
        job.updateStatusLists();
        job.updateStatusLists();
        assertTrue(table.pending().isEmpty(), "both revocations published");
        assertTrue(bit());
        assertEquals(0.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value());
        assertTrue(logs.list.stream().allMatch(event -> event.getThrowableProxy() == null), "no stack trace: " + messages());
    }

    @Test
    void aTamperedRowIsQuarantinedAndObservableWithoutAStackTraceOnAnyRun() {
        fixture.storeToken(listId, TokenStatusListCwtServiceTest.TokenStatusListCwtBase.tamperLst(token(), 9, true));
        table.add(listId, idx, true, T0);

        for (int run = 0; run < 3; run++) {
            job.updateStatusLists();
            clock.advance(Duration.ofMinutes(1));
        }
        clock.advance(Duration.ofHours(1));
        job.updateStatusLists(); // after the quarantine: tried and refused again

        assertEquals(1, table.pending().size(), "the revocation is not applied to a token the pinned signer did not sign");
        assertTrue(logs.list.stream().allMatch(event -> event.getThrowableProxy() == null), "no stack trace: " + messages());
        assertEquals(2, errors(), "one ERROR from the service (once per document) and one from the job: " + messages());
        assertTrue(logs.list.stream().filter(event -> event.getLevel() == Level.WARN)
                        .filter(event -> event.getFormattedMessage().contains(TokenStatusListUpdateException.UNVERIFIABLE))
                        .count() >= 4, "reported on every run: " + messages());
    }

    /**
     * M-11d review round 4, finding 1, the reviewer's interleaving through the real CWT service: run A selects the
     * pending reinstatement and pauses (an instance stalled past ShedLock's {@code lockAtMostFor}); meanwhile run B
     * applies it, a revocation is queued and run B applies that too ({@code revoked=true, pending=0}). Run A then resumes
     * with its stale selection. Before the fix it applied the reinstatement again and published
     * {@code revoked=false, pending=0}; the applier now reads the list's pending rows again (under the list's lock in the
     * database) and finds nothing to apply.
     */
    @Test
    void aStaleSelectionResumedAfterANewerRunLeavesTheNewestState() {
        StatusListUpdateBatchJob other = new StatusListUpdateBatchJob(); // a second instance on the same database
        wire(other);
        table.add(listId, idx, false, T0); // the reinstatement run A selects
        table.afterNextSelection(() -> {
            other.updateStatusLists();      // run B applies the reinstatement
            table.add(listId, idx, true, T0.plusSeconds(1));
            clock.advance(Duration.ofMinutes(1));
            other.updateStatusLists();      // and then the revocation
            assertTrue(bit(), "revoked=true");
            assertTrue(table.pending().isEmpty(), "pending=0");
        });
        int signedBefore = fixture.signed.get();

        job.updateStatusLists();           // run A: selects, pauses while B runs, then resumes with the stale rows

        assertTrue(bit(), "the newest state stands: the stale reinstatement is not applied again");
        assertTrue(table.pending().isEmpty());
        assertEquals(signedBefore + 2, fixture.signed.get(), "run B signed twice; run A signed nothing");
        assertTrue(table.rows.stream().allMatch(row -> row.getIsProcessed()), "each transaction was applied once");
    }

    /**
     * Finding 2 (G43), through the real CWT service: the list holds {@code size-bits} statuses. A negative index, 2^35
     * (whose {@code (int) (idx / 8)} wrapped to byte 0 and revoked index 0, then was marked processed) and the index
     * equal to the size are each closed on their own with an ERROR and the rejected counter, and the valid revocation
     * queued behind them is applied in the same run; the list is never quarantined and index 0 is untouched.
     */
    @Test
    void outOfRangeIndicesAreClosedOnTheirOwnAndAValidRevocationBehindThemIsApplied() {
        ReflectionTestUtils.setField(job, "batchSize", 10);
        long size = fixture.properties.sizeBits();
        assertEquals(size, lists.capacity(fixture.rows.get(listId)).orElseThrow(), "the list's own size");
        long valid = size - 1; // the last index on the list, not index 0 (which the overflow used to hit)
        assertFalse(TokenStatusListService.get(TokenStatusListCwt.decode(token()).lst(), 0));
        table.add(listId, -1, true, T0);
        table.add(listId, 1L << 35, true, T0.plusSeconds(1));
        table.add(listId, size, true, T0.plusSeconds(2));
        table.add(listId, valid, true, T0.plusSeconds(3));

        job.updateStatusLists();

        byte[] bits = TokenStatusListCwt.decode(token()).lst();
        assertTrue(TokenStatusListService.get(bits, valid), "the valid revocation is applied in the same run");
        assertFalse(TokenStatusListService.get(bits, 0), "2^35 does not wrap onto index 0");
        assertTrue(table.pending().isEmpty(), "the invalid rows are closed, not left to block the list");
        assertEquals(3.0, meters.get(StatusListUpdateBatchJob.METRIC_REJECTED_TRANSACTIONS).functionCounter().count());
        assertEquals(0.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value(), "not quarantined");
        assertEquals(3, logs.list.stream().filter(event -> event.getLevel() == Level.ERROR)
                .filter(event -> event.getFormattedMessage().contains("closed without being applied")).count(), messages());
        for (String index : List.of("-1", String.valueOf(1L << 35), String.valueOf(size))) {
            assertTrue(logs.list.stream().anyMatch(event -> event.getFormattedMessage().contains("its index " + index + " is not in")),
                    index + ": " + messages());
        }
    }

    /**
     * Batch size 1: the invalid rows ahead of a valid one cost a run each and never hold the list back, and neither
     * touches a bit — not index 0, where 2^35 wrapped, nor any other.
     */
    @Test
    void outOfRangeIndicesAheadOfAValidOneNeverHoldTheListBack() {
        long valid = fixture.properties.sizeBits() - 1;
        byte[] before = TokenStatusListCwt.decode(token()).lst();
        table.add(listId, 1L << 35, true, T0);
        table.add(listId, -5, true, T0.plusSeconds(1));
        table.add(listId, valid, true, T0.plusSeconds(2));

        job.updateStatusLists();
        job.updateStatusLists(); // no clock change: a held list would not be tried again
        assertArrayEquals(before, TokenStatusListCwt.decode(token()).lst(), "the two invalid rows changed no bit");
        job.updateStatusLists();

        byte[] after = TokenStatusListCwt.decode(token()).lst();
        assertTrue(TokenStatusListService.get(after, valid), "applied on the third run");
        TokenStatusListService.set(after, valid, false);
        assertArrayEquals(before, after, "and nothing else changed");
        assertTrue(table.pending().isEmpty());
        assertEquals(0.0, meters.get(StatusListUpdateBatchJob.METRIC_QUARANTINED_LISTS).gauge().value());
    }

    private void wire(StatusListUpdateBatchJob target) {
        @SuppressWarnings("unchecked")
        ObjectProvider<TokenStatusListService> service = mock(ObjectProvider.class);
        when(service.getIfAvailable()).thenReturn(lists);
        @SuppressWarnings("unchecked")
        ObjectProvider<TokenStatusListProperties> properties = mock(ObjectProvider.class);
        when(properties.getIfAvailable()).thenReturn(fixture.properties);
        ReflectionTestUtils.setField(target, "transactionRepository", table.repository);
        ReflectionTestUtils.setField(target, "applier", new StatusListTransactionApplier(table.repository,
                fixture.repository, service, mock(StatusListCredentialService.class),
                io.mosip.certify.services.StatusListLockWait.withoutDatabase()));
        ReflectionTestUtils.setField(target, "tokenStatusLists", service);
        ReflectionTestUtils.setField(target, "tokenStatusListProperties", properties);
        ReflectionTestUtils.setField(target, "batchJobEnabled", true);
        ReflectionTestUtils.setField(target, "batchSize", 1);
        target.setClock(clock);
    }

    private boolean bit() {
        return TokenStatusListService.get(TokenStatusListCwt.decode(token()).lst(), idx);
    }

    private byte[] token() {
        return TokenStatusListCwtServiceTest.TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument());
    }

    private long errors() {
        return logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count();
    }

    private String lastWarn() {
        return logs.list.stream().filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage).reduce((first, second) -> second).orElse("");
    }

    private String messages() {
        return logs.list.stream().map(event -> event.getLevel() + " " + event.getFormattedMessage()).toList().toString();
    }

    static {
        // the fixture certificates sit around the real now; the test instants must be inside them
        if (!DSC.getNotAfter().toInstant().isAfter(Instant.parse("2026-11-13T12:00:00Z"))) {
            throw new IllegalStateException("the fixture Document Signer must outlive the test");
        }
    }
}
