package io.mosip.certify.services;

import io.mosip.certify.core.exception.StatusListBusyException;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.StatusListRetiredException;
import io.mosip.certify.status.TokenStatusListService;
import io.mosip.certify.status.TokenStatusListUpdateException;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

/**
 * Applies one status list's pending transactions in one database transaction, under the list's row lock (M-11d review
 * round 4, findings 1 to 3).
 *
 * <p>{@link StatusListUpdateBatchJob} selects outside any transaction which lists to visit; it never applies the rows it
 * selected. Each list is applied here: the row is locked ({@code SELECT … FOR NO KEY UPDATE} on PostgreSQL,
 * {@link StatusListCredentialRepository#findByIdForUpdate}), the list's pending transactions are read again under the
 * lock, oldest first by the database sequence ({@link CredentialStatusTransactionRepository#findPendingForList}), applied
 * to the stored list and marked processed, and the transaction commits. So:
 * <ul>
 *   <li>a run that resumes from a selection another run has since applied (an instance paused past ShedLock's
 *   {@code lockAtMostFor}) finds those rows processed and applies nothing, instead of writing an older status over a
 *   newer one (finding 1);</li>
 *   <li>within a list the sequence order is the commit order, because {@code CredentialStatusServiceImpl} inserts a
 *   transaction only while holding the same row lock: no transaction of the list commits with a lower id after a higher
 *   one was applied, whatever the nodes' clocks say (finding 3, G42);</li>
 *   <li>a transaction whose index lies outside the list is closed on its own, with an ERROR and the job's
 *   {@value StatusListUpdateBatchJob#METRIC_REJECTED_TRANSACTIONS} counter, and the list's valid transactions are
 *   applied (finding 2, G43).</li>
 * </ul>
 * The wait for the row lock is bounded by {@code certify.status.update.lock-wait} ({@link StatusListLockWait}): a list
 * whose lock another writer holds past it — an instance paused while it signs the list, a signer that hangs — fails
 * with {@link StatusListBusyException}, nothing is written, and the job moves on to the next list instead of stalling
 * the run behind it (review round 5, finding 1).
 * A separate bean because the job calling its own {@code @Transactional} method would bypass Spring's proxy.
 */
@Slf4j
@Service
public class StatusListTransactionApplier {

    /**
     * What one application did: the transactions applied to the list, and those closed without being applied because
     * their index is not on it.
     */
    public record Outcome(int applied, int rejected) {
        /** Transactions this call marked processed. */
        public int closed() {
            return applied + rejected;
        }
    }

    private final CredentialStatusTransactionRepository transactionRepository;
    private final StatusListCredentialRepository statusListRepository;
    private final ObjectProvider<TokenStatusListService> tokenStatusLists;
    private final StatusListCredentialService statusListCredentialService;
    /** Bounds the wait for a list's row lock. */
    private final StatusListLockWait lockWait;

    /**
     * The clock a Bitstring list's {@code validFrom} is written from: {@code Clock.systemUTC()} in production, another
     * only through {@link #setClock(Clock)} from a test (not an injection point, so a deployment's {@code Clock} bean
     * cannot change the writer clock).
     */
    private volatile Clock clock = Clock.systemUTC();

    @Autowired
    public StatusListTransactionApplier(CredentialStatusTransactionRepository transactionRepository,
                                        StatusListCredentialRepository statusListRepository,
                                        ObjectProvider<TokenStatusListService> tokenStatusLists,
                                        StatusListCredentialService statusListCredentialService,
                                        StatusListLockWait lockWait) {
        this.transactionRepository = transactionRepository;
        this.statusListRepository = statusListRepository;
        this.tokenStatusLists = tokenStatusLists;
        this.statusListCredentialService = statusListCredentialService;
        this.lockWait = java.util.Objects.requireNonNull(lockWait, "lockWait");
    }

    /** For tests: the writer clock (production keeps {@code Clock.systemUTC()}). */
    public void setClock(Clock clock) {
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Applies the list's oldest pending transactions, at most {@code limit}, read again under its row lock, and marks
     * them processed, all in one database transaction. A transaction whose index is outside the list is closed without
     * being applied; a list none of whose transactions is pending any more (another run applied them) is left alone.
     *
     * @throws StatusListRetiredException     a CWT list whose pinned signer is past its {@code notAfter}: nothing is
     *                                        written; the job closes the list's transactions with {@link #closeRetired}
     * @throws TokenStatusListUpdateException a CWT list that cannot be updated now; nothing is written
     * @throws StatusListBusyException        the list's row lock was not available within
     *                                        {@code certify.status.update.lock-wait}; nothing is written
     * @throws CertifyException               any other failure ({@code status_list_update_failed}); nothing is written
     */
    @Transactional
    public Outcome apply(String listId, int limit) {
        try {
            StatusListCredential list = lockWait.bounded(listId, () -> statusListRepository.findByIdForUpdate(listId))
                    .orElseThrow(() -> {
                        log.error("Status list credential not found: {}", listId);
                        return new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND);
                    });
            List<CredentialStatusTransaction> pending = transactionRepository.findPendingForList(listId,
                    PageRequest.of(0, Math.max(1, limit)));
            if (pending.isEmpty()) {
                log.info("Status list {} has no pending transaction left: another run applied what this run selected,"
                        + " and nothing is applied again", listId);
                return new Outcome(0, 0);
            }
            OptionalLong capacity = StatusListEntries.capacity(list, tokenLists());
            Map<Long, Boolean> statuses = new LinkedHashMap<>();
            List<CredentialStatusTransaction> rejected = new ArrayList<>();
            for (CredentialStatusTransaction transaction : pending) {
                if (StatusListEntries.inRange(transaction.getStatusListIndex(), capacity)) {
                    // oldest first: a later transaction on the same index wins
                    statuses.remove(transaction.getStatusListIndex());
                    statuses.put(transaction.getStatusListIndex(), transaction.getStatusValue());
                } else {
                    rejected.add(transaction);
                }
            }
            for (CredentialStatusTransaction transaction : rejected) {
                log.error("Status transaction {} on list {} is closed without being applied: its index {} is not in {},"
                                + " so it names no credential on the list; the list's other transactions are applied",
                        transaction.getTransactionLogId(), listId, transaction.getStatusListIndex(),
                        StatusListEntries.describe(capacity));
            }
            if (!statuses.isEmpty()) {
                write(list, statuses);
            }
            markProcessed(pending);
            log.info("Status list {}: {} transaction(s) applied, {} closed as out of range", listId,
                    pending.size() - rejected.size(), rejected.size());
            return new Outcome(pending.size() - rejected.size(), rejected.size());
        } catch (StatusListRetiredException | TokenStatusListUpdateException | StatusListBusyException e) {
            // the job closes a retired list's transactions, holds back a CWT list by what its failure says, and moves on
            // past a list whose lock another writer holds
            throw e;
        } catch (RuntimeException e) {
            log.error("Error occurred while updating status list with ID: {}", listId, e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED,
                    "Error occurred while updating status list with ID: " + listId);
        }
    }

    /**
     * Closes the oldest pending transactions of a retired list, at most {@code limit}, under its row lock: no re-sign is
     * possible and none is wanted — every mDL on the list has expired (D-M11-7) — so they must not block the queue. A
     * transaction of its own, so a refusal of {@link #apply} (which writes nothing) never takes this write with it.
     *
     * @return how many transactions were closed
     * @throws StatusListBusyException the list's row lock was not available within {@code certify.status.update.lock-wait}
     */
    @Transactional
    public int closeRetired(String listId, int limit) {
        lockWait.bounded(listId, () -> statusListRepository.findByIdForUpdate(listId));
        List<CredentialStatusTransaction> pending = transactionRepository.findPendingForList(listId,
                PageRequest.of(0, Math.max(1, limit)));
        markProcessed(pending);
        return pending.size();
    }

    private TokenStatusListService tokenLists() {
        return tokenStatusLists == null ? null : tokenStatusLists.getIfAvailable();
    }

    private void write(StatusListCredential list, Map<Long, Boolean> statuses) {
        String credentialType = list.getCredentialType();
        if (TokenStatusListService.TYPE.equals(credentialType) || TokenStatusListService.TYPE_CWT.equals(credentialType)) {
            // a Token Status List is a signed JWT or a CWT Status List Token, not a VC document; the service routes by
            // the row's type, and a CWT list is re-signed by its own pinned signer (M-11d). It joins this transaction,
            // so its own row lock is the one already held.
            TokenStatusListService tokenLists = tokenLists();
            if (tokenLists == null) {
                throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED, "Token status lists are not available");
            }
            tokenLists.update(list, statuses);
            return;
        }
        JSONObject vcDocument = new JSONObject(list.getVcDocument());
        String newEncodedList = BitStringStatusListUtils.updateEncodedList(
                vcDocument.getJSONObject("credentialSubject").getString("encodedList"), statuses, list.getCapacityInKB());
        updateStatusListCredential(list, newEncodedList);
        log.info("Successfully updated status list credential: {}", list.getId());
    }

    /**
     * Writes a Bitstring Status List credential with a new {@code encodedList}, re-signed (unchanged from the batch job
     * it moved out of).
     */
    public void updateStatusListCredential(StatusListCredential statusListCredential, String newEncodedList) {
        try {
            log.info("Starting update of StatusListCredential with ID: {}", statusListCredential.getId());

            // Parse the current VC document
            JSONObject vcDocument = new JSONObject(statusListCredential.getVcDocument());
            log.info("Parsed VC document for StatusListCredential ID: {}", statusListCredential.getId());

            // Update the encodedList in the credential subject
            JSONObject credentialSubject = vcDocument.getJSONObject("credentialSubject");
            credentialSubject.put("encodedList", newEncodedList);
            log.info("Updated encodedList for StatusListCredential ID: {}", statusListCredential.getId());

            // Update timestamps
            // Was new Date().toInstant().toString(): the millisecond instant, so Instant.toString() writes three
            // fraction digits, or none at all when they are zero (:23Z as well as :23.123Z). clock.instant() would keep
            // this JVM's microsecond clock and write six digits, which is a different wire form; clock.millis() keeps
            // the instant and the form exactly as they were. The reader of this field accepts both forms - see
            // LegacyW3cDateTimes.
            String newValidFrom = Instant.ofEpochMilli(clock.millis()).toString();
            vcDocument.put("validFrom", newValidFrom);
            log.info("Set new validFrom timestamp: {} for StatusListCredential ID: {}", newValidFrom, statusListCredential.getId());

            // Re-sign the status list credential
            String updatedVcDocument = statusListCredentialService.resignStatusListCredential(vcDocument.toString());
            log.info("Re-signed VC document for StatusListCredential ID: {}", statusListCredential.getId());

            // Update the database record
            statusListCredential.setVcDocument(updatedVcDocument);
            statusListCredential.setUpdatedDtimes(LocalDateTime.now());
            statusListRepository.save(statusListCredential);

            log.info("Successfully updated and saved StatusListCredential ID: {}", statusListCredential.getId());

        } catch (Exception e) {
            log.error("Error occurred while updating StatusListCredential with ID: {}", statusListCredential.getId(), e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_CREDENTIAL_UPDATE_FAILED, "Error occurred while updating StatusListCredential with ID: " + statusListCredential.getId());
        }
    }

    private void markProcessed(List<CredentialStatusTransaction> transactions) {
        if (transactions.isEmpty()) {
            return;
        }
        LocalDateTime processedTime = LocalDateTime.now();
        for (CredentialStatusTransaction transaction : transactions) {
            transaction.setProcessedTime(processedTime);
            transaction.setIsProcessed(true);
        }
        transactionRepository.saveAll(transactions);
    }
}
