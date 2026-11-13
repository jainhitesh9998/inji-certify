package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
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

    /**
     * The clock {@code validFrom} is written from: {@code Clock.systemUTC()} unless a deployment, or a test, injects
     * another through {@link #setClock(Clock)}.
     */
    private Clock clock = Clock.systemUTC();

    /** Optional injection point for the writer clock; the default is the system clock. */
    @Autowired(required = false)
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
            // Fetch a batch of unprocessed transactions
            List<CredentialStatusTransaction> newTransactions = transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, batchSize));

            if (newTransactions.isEmpty()) {
                log.info("No unprocessed transactions found");
                return;
            }

            log.info("Found {} unprocessed transactions to process", newTransactions.size());

            // Group transactions by status list credential ID
            Map<String, List<CredentialStatusTransaction>> transactionsByStatusList = groupTransactionsByStatusList(newTransactions);

            // Update each affected status list
            int updatedLists = 0;
            for (Map.Entry<String, List<CredentialStatusTransaction>> entry : transactionsByStatusList.entrySet()) {
                String statusListId = entry.getKey();
                List<CredentialStatusTransaction> transactions = entry.getValue();

                try {
                    updateStatusList(statusListId, transactions);
                    updatedLists++;
                    log.info("Successfully updated status list: {} and marked {} transactions as processed", statusListId, transactions.size());
                } catch (Exception e) {
                    log.error("Failed to update status list: {}", statusListId, e);
                    // Continue processing other status lists even if one fails
                }
            }

            log.info("Status list update batch job completed successfully. Updated {} status lists", updatedLists);

        } catch (Exception e) {
            log.error("Error in status list update batch job", e);
            throw new CertifyException(ErrorConstants.BATCH_JOB_EXECUTION_FAILED);
        }
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
            if (io.mosip.certify.status.TokenStatusListService.TYPE.equals(statusListCredential.getCredentialType())) {
                // a Token Status List is a signed JWT, not a VC document
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