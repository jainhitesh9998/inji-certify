package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    /**
     * Find a batch of unprocessed transactions, ordered by creation time, with custom batch size.
     */
    List<CredentialStatusTransaction> findByIsProcessedFalseOrderByCreatedDtimesAsc(Pageable pageable);

    /**
     * The oldest pending transactions that name a list, oldest first (creation time, then the identity column, so two
     * transactions created in the same instant keep the order they were written in). What the status-list batch job
     * reads when it holds no list back; a row without a list can never be applied and is not read at all, so it cannot
     * occupy the job's window.
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.isProcessed = false AND t.statusListCredentialId IS NOT NULL"
            + " ORDER BY t.createdDtimes ASC, t.transactionLogId ASC")
    List<CredentialStatusTransaction> findPending(Pageable pageable);

    /**
     * {@link #findPending} without the lists the batch job is holding back (a failure earlier in the run, a back-off or a
     * quarantine; M-11d review round 2, major 3). The exclusion is in the query, so however many rows a held list has
     * pending, the window is filled from the other lists: there is no offset to page past them. {@code excluded} holds
     * one id per held list, not per row — a list carries up to {@code size-bits} entries (131,072 by default), so the set
     * stays orders of magnitude below PostgreSQL's 65,535 bind parameters — and must not be empty (use
     * {@link #findPending} then).
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.isProcessed = false AND t.statusListCredentialId IS NOT NULL"
            + " AND t.statusListCredentialId NOT IN :excluded ORDER BY t.createdDtimes ASC, t.transactionLogId ASC")
    List<CredentialStatusTransaction> findPendingExcluding(@Param("excluded") Collection<String> excluded, Pageable pageable);

    /** How many transactions are pending on a list. */
    interface PendingCount {
        String getListId();

        long getPending();
    }

    /** The pending transactions of each of {@code listIds} (non-empty): what the job reports for a list it holds back. */
    @Query("SELECT t.statusListCredentialId AS listId, COUNT(t) AS pending FROM CredentialStatusTransaction t"
            + " WHERE t.isProcessed = false AND t.statusListCredentialId IN :listIds GROUP BY t.statusListCredentialId")
    List<PendingCount> countPendingByList(@Param("listIds") Collection<String> listIds);
}