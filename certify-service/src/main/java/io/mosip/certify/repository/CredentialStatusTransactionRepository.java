package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    /**
     * Find a batch of unprocessed transactions, ordered by creation time, with custom batch size.
     */
    List<CredentialStatusTransaction> findByIsProcessedFalseOrderByCreatedDtimesAsc(Pageable pageable);

    /**
     * The oldest pending transactions that name a list, oldest first by {@code transaction_log_id}: the value the
     * database's own sequence ({@code SERIAL}) assigns at insert, never a node's clock (G42; {@code cr_dtimes} is written
     * by {@code @PrePersist} from the inserting node's {@code LocalDateTime.now()}, so a node whose clock runs ahead
     * would order its older reinstatement after another node's later revocation). Inside one list the sequence is also
     * the commit order, because {@code CredentialStatusServiceImpl} inserts a list's transaction only while it holds
     * that list's row lock, the lock the job applies under ({@link #findPendingForList}). What the status-list batch job
     * reads when it holds no list back; a row without a list can never be applied and is not read at all, so it cannot
     * occupy the job's window. The selection only decides which lists a run visits: the rows applied are read again
     * under the list's lock.
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.isProcessed = false AND t.statusListCredentialId IS NOT NULL"
            + " ORDER BY t.transactionLogId ASC")
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
            + " AND t.statusListCredentialId NOT IN :excluded ORDER BY t.transactionLogId ASC")
    List<CredentialStatusTransaction> findPendingExcluding(@Param("excluded") Collection<String> excluded, Pageable pageable);

    /**
     * One list's pending transactions, oldest first by {@code transaction_log_id}, at most the page size: what
     * {@code StatusListTransactionApplier} applies, read while it holds the list's row lock. Every writer of a list's
     * transactions ({@code CredentialStatusServiceImpl}) takes that lock before its insert draws the sequence value, so
     * within a list the sequence order is the commit order, and no transaction of the list can commit with a lower id
     * after a higher one was applied (M-11d review round 4, finding 3). Read under the lock, the rows are exactly those
     * no other run has applied: a run that resumes from a selection made before another run committed finds them
     * processed and applies nothing (finding 1).
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.isProcessed = false AND t.statusListCredentialId = :listId"
            + " ORDER BY t.transactionLogId ASC")
    List<CredentialStatusTransaction> findPendingForList(@Param("listId") String listId, Pageable pageable);

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