package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.StatusListRetiredException;
import io.mosip.certify.status.StatusListSignerPolicy;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Batch job service for updating Status List Credentials
 * Runs every minute(can be configured) to process new credential status transactions and update status lists
 */
@Slf4j
@Service
public class StatusListUpdateBatchJob {

    @Autowired
    private CredentialStatusTransactionRepository transactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListRepository;

    @Autowired
    private org.springframework.beans.factory.ObjectProvider<io.mosip.certify.status.TokenStatusListService> tokenStatusLists;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Value("${mosip.certify.batch.status-list-update.enabled:true}")
    private boolean batchJobEnabled;

    @Value("${mosip.certify.batch.status-list-update.batch-size:1000}")
    private int batchSize;

    /** How many pages of pending transactions one run scans to assemble its batch around unprocessable lists. */
    @Value("${mosip.certify.batch.status-list-update.max-pages:50}")
    private int maxPages = 50;

    /**
     * Lists whose re-sign refuses permanently — a revoked Document Signer, a rotated-away version, a stale CRL — so
     * their pending transactions are skipped instead of filling every run's window, which used to stop every other
     * list's update once the stuck rows reached {@code batch-size} (review round 1, major 4). In memory: a restart
     * retries, which is what an operator who has fixed the signer wants.
     */
    private final Set<String> unprocessableLists = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * The clock {@code validFrom} is written from: {@code Clock.systemUTC()} always in production;
     * only a test sets another through {@link #setClock(Clock)} (not a Spring injection point, so a {@code Clock} bean a
     * deployment or plugin defines can neither replace the writer clock nor make startup ambiguous).
     */
    private Clock clock = Clock.systemUTC();

    /** For tests: the writer clock (production keeps {@code Clock.systemUTC()}). */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * Scheduled method that runs periodically (schedule controlled by cron expression property)
     * to update status lists by processing new credential status transactions.
     */
    @Scheduled(cron = "${mosip.certify.batch.status-list-update.cron-expression:0 0/1 * * * *}")
    @SchedulerLock(
            name = "updateStatusLists",
            lockAtMostFor = "${mosip.certify.batch.status-list-update.lock-at-most-for:50m}",
            lockAtLeastFor = "${mosip.certify.batch.status-list-update.lock-at-least-for:50s}"
    )
    public void updateStatusLists() {
        LockAssert.assertLocked();
        if (!batchJobEnabled) {
            log.info("Status list update batch job is disabled");
            return;
        }

        log.info("Starting status list update batch job");

        try {
            int processed = 0;
            int updatedLists = 0;
            Set<String> failedThisRun = new LinkedHashSet<>();
            for (int page = 0; page < maxPages && processed < batchSize; page++) {
                List<CredentialStatusTransaction> newTransactions = transactionRepository
                        .findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(page, batchSize));
                if (newTransactions.isEmpty()) {
                    if (page == 0) {
                        log.info("No unprocessed transactions found");
                    }
                    break;
                }
                if (page == 0) {
                    log.info("Found {} unprocessed transactions to process", newTransactions.size());
                }
                int before = processed;
                Map<String, List<CredentialStatusTransaction>> transactionsByStatusList = groupTransactionsByStatusList(newTransactions);
                for (Map.Entry<String, List<CredentialStatusTransaction>> entry : transactionsByStatusList.entrySet()) {
                    String statusListId = entry.getKey();
                    List<CredentialStatusTransaction> transactions = entry.getValue();
                    if (unprocessableLists.contains(statusListId) || failedThisRun.contains(statusListId)) {
                        continue; // its transactions stay pending; the window pages past them
                    }
                    try {
                        updateStatusList(statusListId, transactions);
                        processed += transactions.size();
                        updatedLists++;
                        log.info("Successfully updated status list: {} and marked {} transactions as processed", statusListId, transactions.size());
                    } catch (StatusListRetiredException e) {
                        // D-M11-7: no re-sign is possible and none is wanted — every mDL that indexed the list has
                        // expired — so the transactions are closed rather than blocking the queue (major 4)
                        markProcessed(transactions);
                        processed += transactions.size();
                        log.warn("Status list {} is retired ({}); its {} transaction(s) are marked processed without a"
                                        + " re-sign: every mDL on the list has expired (D-M11-7)",
                                statusListId, e.getMessage(), transactions.size());
                    } catch (RuntimeException e) {
                        if (permanent(e)) {
                            unprocessableLists.add(statusListId);
                            failedThisRun.add(statusListId);
                            log.error("Status list {} cannot be updated by its signer ({}); it is skipped for the rest of"
                                            + " this run and until the next restart, so it cannot block other lists",
                                    statusListId, e.getMessage());
                        } else {
                            log.error("Failed to update status list: {}", statusListId, e);
                            // Continue processing other status lists even if one fails
                        }
                    }
                }
                if (processed >= batchSize || newTransactions.size() < batchSize) {
                    break;
                }
                if (processed == before) {
                    // nothing in this window can be processed: move the window past the stuck rows
                    continue;
                }
                page--; // rows were committed as processed, so the next batch starts at this offset again
            }

            log.info("Status list update batch job completed successfully. Updated {} status lists, {} transactions processed",
                    updatedLists, processed);

        } catch (Exception e) {
            log.error("Error in status list update batch job", e);
            throw new CertifyException(ErrorConstants.BATCH_JOB_EXECUTION_FAILED);
        }
    }

    /**
     * Closes transactions that can never be published (a retired list) in their own transaction: the caller's run is
     * not transactional, so the write must not wait for (or be lost with) another list.
     */
    private void markProcessed(List<CredentialStatusTransaction> transactions) {
        LocalDateTime processedTime = LocalDateTime.now();
        for (CredentialStatusTransaction txn : transactions) {
            txn.setProcessedTime(processedTime);
            txn.setIsProcessed(true);
        }
        transactionRepository.saveAll(transactions);
    }

    /**
     * Whether a failure will not go away by retrying: the signer policy refuses this certificate (revoked, rotated
     * away, stale CRL, wrong purpose) rather than the signer being unavailable for a moment.
     */
    static boolean permanent(Throwable failure) {
        String message = String.valueOf(failure == null ? null : failure.getMessage());
        return message.startsWith(StatusListSignerPolicy.PREFIX)
                || message.startsWith(StatusListSignerPolicy.CHAIN_LINK_INVALID)
                || message.startsWith(StatusListSignerPolicy.CRL_STALE);
    }

    /**
     * Group transactions by their status list credential ID
     */
    private Map<String, List<CredentialStatusTransaction>> groupTransactionsByStatusList(List<CredentialStatusTransaction> transactions) {

        return transactions.stream()
                .filter(t -> t.getStatusListCredentialId() != null)
                .collect(Collectors.groupingBy(CredentialStatusTransaction::getStatusListCredentialId));
    }

    /**
     * Update a specific status list with the given transactions
     */
    @Transactional
    public void updateStatusList(String statusListId, List<CredentialStatusTransaction> transactions) {
        log.info("Updating status list {} with {} transactions", statusListId, transactions.size());

        try {
            // Fetch the current status list credential
            Optional<StatusListCredential> optionalStatusList = statusListRepository.findById(statusListId);

            if (optionalStatusList.isEmpty()) {
                log.error("Status list credential not found: {}", statusListId);
                throw new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND);
            }

            StatusListCredential statusListCredential = optionalStatusList.get();

            // Apply transaction updates to the status data
            Map<Long, Boolean> updatedStatuses = getUpdatedStatus(transactions);
            String credentialType = statusListCredential.getCredentialType();
            if (io.mosip.certify.status.TokenStatusListService.TYPE.equals(credentialType)
                    || io.mosip.certify.status.TokenStatusListService.TYPE_CWT.equals(credentialType)) {
                // a Token Status List is a signed JWT or a CWT Status List Token, not a VC document; the service routes
                // by the row's type, and a CWT list is re-signed by its own pinned signer (M-11d)
                io.mosip.certify.status.TokenStatusListService tokenLists = tokenStatusLists == null ? null : tokenStatusLists.getIfAvailable();
                if (tokenLists == null) {
                    throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED, "Token status lists are not available");
                }
                tokenLists.update(statusListCredential, updatedStatuses);
                LocalDateTime processedTime = LocalDateTime.now();
                for (CredentialStatusTransaction txn : transactions) {
                    txn.setProcessedTime(processedTime);
                    txn.setIsProcessed(true);
                }
                transactionRepository.saveAll(transactions);
                return;
            }

            JSONObject vcDocument = new JSONObject(statusListCredential.getVcDocument());

            // Generate new encoded list
            String newEncodedList = BitStringStatusListUtils.updateEncodedList(vcDocument.getJSONObject("credentialSubject").getString("encodedList"),updatedStatuses, statusListCredential.getCapacityInKB());

            // Update the status list credential with new encoded list
            updateStatusListCredential(statusListCredential, newEncodedList);

            // Mark transactions as processed
            LocalDateTime processedTime = LocalDateTime.now();
            for (CredentialStatusTransaction txn : transactions) {
                txn.setProcessedTime(processedTime);
                txn.setIsProcessed(true);
            }
            transactionRepository.saveAll(transactions);

            log.info("Successfully updated status list credential: {}", statusListId);

        } catch (StatusListRetiredException e) {
            // the caller closes the transactions and warns; a certified reason, not a generic failure (major 4)
            throw e;
        } catch (RuntimeException e) {
            if (permanent(e)) {
                throw e; // the caller records it once and skips the list instead of retrying it forever
            }
            log.error("Error occurred while updating status list with ID: {}", statusListId, e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED, "Error occurred while updating status list with ID: " + statusListId);
        } catch (Exception e) {
            log.error("Error occurred while updating status list with ID: {}", statusListId, e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED, "Error occurred while updating status list with ID: " + statusListId);
        }
    }

    /** Returns a map of status list index to the latest status value, based on transaction creation time.
     * If multiple transactions exist for the same index, the latest one (by createdDtimes) is used.
     */
    private Map<Long, Boolean> getUpdatedStatus(List<CredentialStatusTransaction> transactions) {
        return transactions.stream()
                .filter(t -> t.getStatusListIndex() != null)
                .sorted(Comparator.comparing(CredentialStatusTransaction::getCreatedDtimes))
                .collect(Collectors.toMap(
                        CredentialStatusTransaction::getStatusListIndex,
                        CredentialStatusTransaction::getStatusValue,
                        (first, second) -> second,
                        HashMap::new
                ));
    }


    /**
     * Update the status list credential with the new encoded list
     */
    @Transactional
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
}