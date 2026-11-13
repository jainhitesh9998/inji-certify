package io.mosip.certify.services;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.StatusListRetiredException;
import io.mosip.certify.status.TokenStatusListProperties;
import io.mosip.certify.status.TokenStatusListService;
import io.mosip.certify.status.TokenStatusListUpdateException;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.json.JSONObject;
import org.springframework.beans.factory.ObjectProvider;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Batch job service for updating Status List Credentials
 * Runs every minute(can be configured) to process new credential status transactions and update status lists
 *
 * <p>Each run takes the oldest pending transactions, at most {@code batch-size}, and applies them list by list, oldest
 * first. A list whose update fails is excluded from the rest of the run in the selection itself, so none of its newer
 * transactions is applied before an older one that failed, and its pending rows never fill the window another list's
 * rows need (M-11d review round 2, majors 1 and 3). A Token Status List or Bitstring list that failed is tried again on
 * the next run, as before. A CWT list's failure says whether a retry can help ({@link TokenStatusListUpdateException}):
 * a transient one is retried on the next run and then with a bounded back-off, a permanent one is quarantined for
 * {@code certify.status.token-status-list.batch.quarantine} or until the IACA trust material changes; a quarantined
 * list is reported every run (a WARN with its pending transactions, and the gauges {@value #METRIC_QUARANTINED_LISTS}
 * and {@value #METRIC_QUARANTINED_TRANSACTIONS}).
 */
@Slf4j
@Service
public class StatusListUpdateBatchJob {

    /** Gauge: the CWT lists quarantined after a permanent refusal, whose transactions wait for an operator. */
    public static final String METRIC_QUARANTINED_LISTS = "certify.status.batch.quarantined-lists";
    /** Gauge: the pending transactions on those lists, as counted by the last run. */
    public static final String METRIC_QUARANTINED_TRANSACTIONS = "certify.status.batch.quarantined-transactions";

    @Autowired
    private CredentialStatusTransactionRepository transactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListRepository;

    @Autowired
    private ObjectProvider<TokenStatusListService> tokenStatusLists;

    /** {@code certify.status.token-status-list.batch.*}: the back-off and quarantine of a CWT list (rule 9, typed). */
    @Autowired
    private ObjectProvider<TokenStatusListProperties> tokenStatusListProperties;

    @Autowired
    private ObjectProvider<MeterRegistry> meterRegistry;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Value("${mosip.certify.batch.status-list-update.enabled:true}")
    private boolean batchJobEnabled;

    @Value("${mosip.certify.batch.status-list-update.batch-size:1000}")
    private int batchSize;

    /** The CWT lists held back after a failure; see {@link StatusListUpdateHolds}. */
    private final StatusListUpdateHolds holds = new StatusListUpdateHolds();

    /** What the gauges read: held strongly here, since Micrometer may hold its state weakly. */
    private final AtomicInteger quarantinedLists = new AtomicInteger();
    private final AtomicLong quarantinedTransactions = new AtomicLong();
    private volatile MeterRegistry boundMeters;
    /** Whether the first run has looked for the application's registry: once, so a failing lookup cannot fail every run. */
    private volatile boolean meterLookupDone;

    /**
     * The clock {@code validFrom} is written from: {@code Clock.systemUTC()} always in production;
     * only a test sets another through {@link #setClock(Clock)} (not a Spring injection point, so a {@code Clock} bean a
     * deployment or plugin defines can neither replace the writer clock nor make startup ambiguous). The back-off and the
     * quarantine run on it too.
     */
    private Clock clock = Clock.systemUTC();

    /** For tests: the writer clock (production keeps {@code Clock.systemUTC()}). */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * Registers the gauges {@value #METRIC_QUARANTINED_LISTS} and {@value #METRIC_QUARANTINED_TRANSACTIONS} with
     * {@code registry}. A run binds the application's registry itself; a test binds its own.
     */
    public synchronized void bindMetrics(MeterRegistry registry) {
        if (registry == null || registry == boundMeters) {
            return;
        }
        Gauge.builder(METRIC_QUARANTINED_LISTS, quarantinedLists, AtomicInteger::get)
                .description("CWT status lists the batch job has quarantined after a permanent signer refusal")
                .register(registry);
        Gauge.builder(METRIC_QUARANTINED_TRANSACTIONS, quarantinedTransactions, AtomicLong::get)
                .description("Pending credential status transactions on quarantined CWT status lists")
                .register(registry);
        boundMeters = registry;
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
            if (!meterLookupDone) {
                meterLookupDone = true;
                try {
                    if (boundMeters == null && meterRegistry != null) {
                        bindMetrics(meterRegistry.getIfAvailable());
                    }
                } catch (RuntimeException e) {
                    log.warn("The status-list batch gauges are not registered: {}", e.getMessage());
                }
            }
            Instant now = clock.instant();
            int trust = trustMaterialVersion();
            TokenStatusListProperties.Batch settings = batchSettings();
            // lists held back by an earlier run, and every list that fails in this one: excluded in the selection, so
            // no newer transaction of theirs is applied before an older one and their rows never fill the window
            Set<String> excluded = new LinkedHashSet<>(holds.held(now, trust));
            int processed = 0;
            int updatedLists = 0;
            boolean first = true;
            while (processed < batchSize) {
                int limit = batchSize - processed;
                List<CredentialStatusTransaction> newTransactions = pending(excluded, limit);
                if (newTransactions.isEmpty()) {
                    if (first) {
                        log.info("No unprocessed transactions found");
                    }
                    break;
                }
                if (first) {
                    log.info("Found {} unprocessed transactions to process", newTransactions.size());
                }
                first = false;
                int processedBefore = processed;
                int excludedBefore = excluded.size();
                Map<String, List<CredentialStatusTransaction>> transactionsByStatusList = groupTransactionsByStatusList(newTransactions);
                for (Map.Entry<String, List<CredentialStatusTransaction>> entry : transactionsByStatusList.entrySet()) {
                    String statusListId = entry.getKey();
                    List<CredentialStatusTransaction> transactions = entry.getValue();
                    if (excluded.contains(statusListId)) {
                        continue; // failed earlier in this run: its transactions stay pending, in order
                    }
                    try {
                        updateStatusList(statusListId, transactions);
                        processed += transactions.size();
                        updatedLists++;
                        recovered(statusListId);
                        log.info("Successfully updated status list: {} and marked {} transactions as processed", statusListId, transactions.size());
                    } catch (StatusListRetiredException e) {
                        // D-M11-7: no re-sign is possible and none is wanted — every mDL that indexed the list has
                        // expired — so the transactions are closed rather than blocking the queue
                        markProcessed(transactions);
                        processed += transactions.size();
                        recovered(statusListId);
                        log.warn("Status list {} is retired ({}); its {} transaction(s) are marked processed without a"
                                        + " re-sign: every mDL on the list has expired (D-M11-7)",
                                statusListId, e.getMessage(), transactions.size());
                    } catch (TokenStatusListUpdateException e) {
                        excluded.add(statusListId);
                        hold(statusListId, e, now, trust, settings);
                    } catch (RuntimeException e) {
                        // a JWT or Bitstring list: tried again on the next run, as before; excluded for the rest of
                        // this one so none of its newer transactions overtakes the ones that failed
                        excluded.add(statusListId);
                        log.error("Failed to update status list: {}", statusListId, e);
                    }
                }
                if (newTransactions.size() < limit) {
                    break; // every pending row outside the excluded lists was in this window
                }
                if (processed == processedBefore && excluded.size() == excludedBefore) {
                    break; // nothing changed: a selection that ignores the exclusion must not spin
                }
            }
            report(now, trust);

            log.info("Status list update batch job completed successfully. Updated {} status lists, {} transactions processed",
                    updatedLists, processed);

        } catch (Exception e) {
            log.error("Error in status list update batch job", e);
            throw new CertifyException(ErrorConstants.BATCH_JOB_EXECUTION_FAILED);
        }
    }

    /** The oldest pending transactions outside {@code excluded}, at most {@code limit}; the exclusion is in the query. */
    private List<CredentialStatusTransaction> pending(Set<String> excluded, int limit) {
        PageRequest window = PageRequest.of(0, limit);
        return excluded.isEmpty() ? transactionRepository.findPending(window)
                : transactionRepository.findPendingExcluding(excluded, window);
    }

    /**
     * Holds back a CWT list that could not be updated: a transient failure is retried on the next run and then with a
     * bounded back-off, a permanent refusal is quarantined. The first failure of a streak is logged at ERROR (a transient
     * one with its stack trace, a permanent one without: the refusal is the whole story), later ones at WARN; the list's
     * transactions stay pending either way.
     */
    private void hold(String listId, TokenStatusListUpdateException failure, Instant now, int trust,
                      TokenStatusListProperties.Batch settings) {
        if (failure.permanent()) {
            StatusListUpdateHolds.Hold hold = holds.quarantine(listId, now, failure.rule(), failure.getMessage(), trust, settings);
            if (hold.failures() == 1) {
                log.error("Status list {} is quarantined: its update is refused ({}: {}). Its transactions stay pending and"
                                + " are applied in order once it can be signed; it is tried again after {}"
                                + " (certify.status.token-status-list.batch.quarantine) or as soon as the IACA trust material"
                                + " changes", listId, failure.rule(), failure.getMessage(), hold.until());
            } else {
                log.warn("Status list {} is still refused after its quarantine ({}: {}, attempt {}); quarantined again"
                        + " until {}", listId, failure.rule(), failure.getMessage(), hold.failures(), hold.until());
            }
            return;
        }
        StatusListUpdateHolds.Hold hold = holds.backOff(listId, now, failure.rule(), failure.getMessage(), settings);
        if (hold.failures() == 1) {
            log.error("Status list {} could not be updated ({}); its transactions stay pending and it is tried again on the"
                    + " next run", listId, failure.rule(), failure);
        } else {
            log.warn("Status list {} still cannot be updated ({}: {}, attempt {}); its transactions stay pending, next"
                    + " attempt after {}", listId, failure.rule(), failure.getMessage(), hold.failures(), hold.until());
        }
    }

    /** A list that was held back is updated again (or retired): forget the hold and say so. */
    private void recovered(String listId) {
        StatusListUpdateHolds.Hold hold = holds.succeeded(listId);
        if (hold != null) {
            log.info("Status list {} is updated again after {} failed attempt(s) ({})", listId, hold.failures(), hold.rule());
        }
    }

    /**
     * Every run: a WARN listing the quarantined lists with their pending transactions (and one for lists backing off),
     * and the gauges, so a list whose revocations wait for an operator is never silent.
     */
    private void report(Instant now, int trust) {
        Map<String, StatusListUpdateHolds.Hold> quarantined = holds.quarantined(now, trust);
        Map<String, StatusListUpdateHolds.Hold> backingOff = holds.backingOff(now);
        Map<String, Long> pending = new HashMap<>();
        if (!quarantined.isEmpty() || !backingOff.isEmpty()) {
            Set<String> ids = new LinkedHashSet<>(quarantined.keySet());
            ids.addAll(backingOff.keySet());
            try {
                for (CredentialStatusTransactionRepository.PendingCount count : transactionRepository.countPendingByList(ids)) {
                    pending.put(count.getListId(), count.getPending());
                }
            } catch (RuntimeException e) {
                // the run's work is done; a report without counts is better than a failed run
                log.warn("The pending transactions of the held status lists {} could not be counted: {}", ids, e.getMessage());
            }
        }
        long waiting = 0;
        for (String listId : quarantined.keySet()) {
            waiting += pending.getOrDefault(listId, 0L);
        }
        quarantinedLists.set(quarantined.size());
        quarantinedTransactions.set(waiting);
        if (!quarantined.isEmpty()) {
            log.warn("Status lists quarantined, their revocations not yet published: {}", describe(quarantined, pending));
        }
        if (!backingOff.isEmpty()) {
            log.warn("Status lists backing off after transient failures: {}", describe(backingOff, pending));
        }
    }

    private static List<String> describe(Map<String, StatusListUpdateHolds.Hold> held, Map<String, Long> pending) {
        return held.entrySet().stream().map(entry -> entry.getKey() + " (" + pending.getOrDefault(entry.getKey(), 0L)
                + " pending, " + entry.getValue().rule() + ", next attempt after " + entry.getValue().until() + ")").toList();
    }

    private int trustMaterialVersion() {
        TokenStatusListService lists = tokenStatusLists == null ? null : tokenStatusLists.getIfAvailable();
        return lists == null ? 0 : lists.trustMaterialVersion();
    }

    private TokenStatusListProperties.Batch batchSettings() {
        TokenStatusListProperties properties = tokenStatusListProperties == null ? null
                : tokenStatusListProperties.getIfAvailable();
        return properties == null ? new TokenStatusListProperties.Batch(null, null, null) : properties.batch();
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
     * Group transactions by their status list credential ID, keeping the selection's order: the lists in the order of
     * their oldest pending transaction, each list's transactions oldest first.
     */
    private Map<String, List<CredentialStatusTransaction>> groupTransactionsByStatusList(List<CredentialStatusTransaction> transactions) {

        return transactions.stream()
                .filter(t -> t.getStatusListCredentialId() != null)
                .collect(Collectors.groupingBy(CredentialStatusTransaction::getStatusListCredentialId,
                        LinkedHashMap::new, Collectors.toList()));
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
            if (TokenStatusListService.TYPE.equals(credentialType) || TokenStatusListService.TYPE_CWT.equals(credentialType)) {
                // a Token Status List is a signed JWT or a CWT Status List Token, not a VC document; the service routes
                // by the row's type, and a CWT list is re-signed by its own pinned signer (M-11d)
                TokenStatusListService tokenLists = tokenStatusLists == null ? null : tokenStatusLists.getIfAvailable();
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

        } catch (StatusListRetiredException | TokenStatusListUpdateException e) {
            // the caller closes a retired list's transactions, and holds back a CWT list by what its failure says
            throw e;
        } catch (RuntimeException e) {
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