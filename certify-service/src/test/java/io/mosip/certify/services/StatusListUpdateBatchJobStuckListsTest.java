package io.mosip.certify.services;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.StatusListRetiredException;
import io.mosip.certify.status.TokenStatusListService;
import net.javacrumbs.shedlock.core.LockAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Review round 1, major 4: the batch job must not be jammed by a list it can never update. A retired list's
 * transactions are closed with a WARN (every mDL on it has expired, D-M11-7), and a list whose signer refuses
 * permanently — a revoked Document Signer, a rotated-away key — is skipped for the rest of the run and until the next
 * restart, so its stuck rows cannot fill the oldest-{@code batch-size} window and stop every other list's update.
 */
class StatusListUpdateBatchJobStuckListsTest {

    CredentialStatusTransactionRepository transactions = mock(CredentialStatusTransactionRepository.class);
    StatusListCredentialRepository lists = mock(StatusListCredentialRepository.class);
    TokenStatusListService tokenLists = mock(TokenStatusListService.class);
    StatusListUpdateBatchJob job = new StatusListUpdateBatchJob();
    ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void setUp() {
        LockAssert.TestHelper.makeAllAssertsPass(true);
        @SuppressWarnings("unchecked")
        ObjectProvider<TokenStatusListService> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(tokenLists);
        ReflectionTestUtils.setField(job, "transactionRepository", transactions);
        ReflectionTestUtils.setField(job, "statusListRepository", lists);
        ReflectionTestUtils.setField(job, "tokenStatusLists", provider);
        ReflectionTestUtils.setField(job, "statusListCredentialService", mock(StatusListCredentialService.class));
        ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        ReflectionTestUtils.setField(job, "batchSize", 1);
        ReflectionTestUtils.setField(job, "maxPages", 20);
        when(lists.findById(anyString())).thenAnswer(inv -> Optional.of(row(inv.getArgument(0))));
        when(transactions.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
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
        CredentialStatusTransaction stuck = txn("retired", 3);
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(any())).thenReturn(List.of());
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 1))).thenReturn(List.of(stuck));
        doThrow(new StatusListRetiredException("the pinned signer expired"))
                .when(tokenLists).update(any(StatusListCredential.class), any());

        job.updateStatusLists();

        assertTrue(stuck.getIsProcessed(), "the transaction is closed instead of blocking the queue");
        ArgumentCaptor<List<CredentialStatusTransaction>> saved = ArgumentCaptor.forClass(List.class);
        verify(transactions).saveAll(saved.capture());
        assertEquals(1, saved.getValue().size());
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                        && event.getFormattedMessage().contains("retired")),
                messages());
    }

    /**
     * {@code batch-size} is 1 and the window is three stuck rows of a revoked-DSC list: the second run must still reach
     * a JWT list's pending row in the same run, and the revoked list must be logged once, not retried on every page.
     */
    @Test
    void aRevokedDscListDoesNotBlockAJwtListWithMoreStuckRowsThanTheBatchSize() {
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(any())).thenReturn(List.of());
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 1)))
                .thenReturn(List.of(txn("revoked", 0)));
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(1, 1)))
                .thenReturn(List.of(txn("revoked", 1)));
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(2, 1)))
                .thenReturn(List.of(txn("jwt", 0)));
        // only the revoked list's signer refuses; the JWT list signs with its own key and succeeds
        org.mockito.Mockito.doAnswer(inv -> {
            if ("revoked".equals(((StatusListCredential) inv.getArgument(0)).getId())) {
                throw new IllegalStateException(
                        "STATUS_SIGNER_REVOKED: the IACA revoked the Document Signer since 2026-11-13");
            }
            return null;
        }).when(tokenLists).update(any(StatusListCredential.class), any());

        job.updateStatusLists();

        ArgumentCaptor<List<CredentialStatusTransaction>> saved = ArgumentCaptor.forClass(List.class);
        verify(transactions).saveAll(saved.capture());
        assertTrue(saved.getValue().stream().allMatch(CredentialStatusTransaction::getIsProcessed),
                "the JWT list's row is processed in the same run");
        verify(tokenLists, org.mockito.Mockito.times(1)).update(argThat(row -> "revoked".equals(row.getId())), any());
        long errors = logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count();
        assertEquals(1, errors, "the revoked list is recorded once per run: " + messages());

        // the next run skips it without another attempt or ERROR, and still reaches the JWT list
        job.updateStatusLists();
        verify(tokenLists, org.mockito.Mockito.times(1)).update(argThat(row -> "revoked".equals(row.getId())), any());
        assertEquals(1, logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count(), messages());
    }

    /** A transient failure (the signer is unavailable for a moment) is still retried on the next run. */
    @Test
    void aTransientFailureIsNotLockedOut() {
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(any())).thenReturn(List.of());
        when(transactions.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 1)))
                .thenReturn(List.of(txn("transient", 0)));
        doThrow(new IllegalStateException("HSM session lost"))
                .when(tokenLists).update(any(StatusListCredential.class), any());

        job.updateStatusLists();

        verify(transactions, never()).saveAll(anyList());
        assertFalse(logs.list.stream().anyMatch(event -> event.getLevel() == Level.ERROR
                        && event.getFormattedMessage().contains("skipped for the rest")),
                messages());
        assertTrue(logs.list.stream().anyMatch(event -> event.getLevel() == Level.ERROR), messages());
    }

    private static CredentialStatusTransaction txn(String listId, long index) {
        CredentialStatusTransaction txn = new CredentialStatusTransaction();
        txn.setStatusListCredentialId(listId);
        txn.setStatusListIndex(index);
        txn.setStatusValue(true);
        txn.setCreatedDtimes(LocalDateTime.now());
        return txn;
    }

    private static StatusListCredential row(String id) {
        StatusListCredential row = new StatusListCredential();
        row.setId(id);
        row.setVcDocument("{\"envelope\":true}");
        // the JWT list is the one that must still be reachable; the revoked list is a CWT row
        row.setCredentialType(id.equals("jwt") ? TokenStatusListService.TYPE : TokenStatusListService.TYPE_CWT);
        row.setStatusPurpose("revocation");
        row.setCapacityInKB(1L);
        row.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        row.setCreatedDtimes(LocalDateTime.now());
        return row;
    }

    private String messages() {
        return logs.list.stream().map(event -> event.getLevel() + " " + event.getFormattedMessage()).toList().toString();
    }

    static {
        // the JWT row's document must be parseable only by the JWT path, which this test mocks away
        if (!"TokenStatusList".equals(TokenStatusListService.TYPE)) {
            throw new IllegalStateException("the JWT list type changed");
        }
    }
}
