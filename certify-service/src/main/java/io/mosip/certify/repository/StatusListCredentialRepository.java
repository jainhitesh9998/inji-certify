package io.mosip.certify.repository;

import io.mosip.certify.entity.StatusListCredential;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface StatusListCredentialRepository extends JpaRepository<StatusListCredential, String> {

    /**
     * Find a suitable status list credential that is available (not full) and matches the given purpose
     *
     * @param statusPurpose The purpose of the status list (e.g., "revocation", "suspension")
     * @return An optional containing the first available status list credential, or empty if none found
     */
    Optional<StatusListCredential> findFirstByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
            String credentialType, String statusPurpose, StatusListCredential.CredentialStatus credentialStatus);

    Optional<StatusListCredential> findFirstByStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
            String statusPurpose,
            StatusListCredential.CredentialStatus credentialStatus
    );

    /**
     * Every available list of a type and purpose, newest first: a CWT status list belongs to one signer, so
     * {@code TokenStatusListService.allocateCwt} has to look past rows another Document Signer's mDLs are indexed in
     * (docs/design/wp/M-11-status-list-under-iaca.md section 4.3).
     */
    List<StatusListCredential> findByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
            String credentialType, String statusPurpose, StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Allocation's view of a CWT list: only the id and the envelope, so choosing a candidate never loads the entities'
     * other columns (a retired Document Signer's old lists stay {@code AVAILABLE} and are scanned on every allocation).
     */
    interface CwtCandidate {
        String getId();

        String getVcDocument();
    }

    /** As the derived query above, projected to what allocation reads (review round 1, minor 6). */
    @Query("SELECT s.id AS id, s.vcDocument AS vcDocument FROM StatusListCredential s"
            + " WHERE s.credentialType = :credentialType AND s.statusPurpose = :statusPurpose"
            + " AND s.credentialStatus = :credentialStatus ORDER BY s.createdDtimes DESC")
    List<CwtCandidate> findCwtCandidates(@Param("credentialType") String credentialType,
                                         @Param("statusPurpose") String statusPurpose,
                                         @Param("credentialStatus") StatusListCredential.CredentialStatus credentialStatus);

    /**
     * The document as stored, read straight from the table: a scalar projection does not go through the persistence
     * context's first-level cache, which a request (Spring's open-in-view keeps the session open) would otherwise hit
     * with the copy it read before waiting for another writer's commit.
     */
    @Query("SELECT s.vcDocument FROM StatusListCredential s WHERE s.id = :id")
    Optional<String> findDocumentById(@Param("id") String id);

    /**
     * The row locked for the rest of the transaction: the single writer of a list's document (a status update now, a
     * re-sign later) reads it through here, so two updates cannot each sign a snapshot and lose one of the bits, and a
     * re-sign cannot overwrite a status update committed between its read and its compare-and-set. A status change takes
     * the same lock before it queues its transaction ({@code CredentialStatusServiceImpl}), so a list's transactions
     * draw their {@code transaction_log_id} in commit order and the batch job, which applies a list under this lock,
     * never sees a lower id commit after it applied a higher one (M-11d review round 4, G42). A status change for a list
     * therefore waits while the job signs that list; that wait is the ordering.
     *
     * <p>{@code PESSIMISTIC_WRITE} is rendered by the dialect: {@code for no key update} with {@code PostgreSQLDialect}
     * (Hibernate 6, PostgreSQL 9.3 and later) and {@code for update} with {@code H2Dialect}. On PostgreSQL the two
     * {@code for no key update} locks conflict with each other, which is the serialisation wanted, but not with the
     * {@code key share} lock that inserting a transaction row takes on its list through the foreign key a deployment
     * upgraded from 0.12 has, so a writer that does not take this lock first (a row written by hand) is not blocked by
     * it either. The consequence for tests: an H2 database under
     * {@code PostgreSQLDialect} — the {@code local} profile's {@code application-local.properties} sets it, and an H2
     * {@code @SpringBootTest} that activates {@code local} keeps it unless it overrides
     * {@code spring.jpa.database-platform} with {@code H2Dialect} as {@code OfferPageTest} does — receives
     * {@code for no key update}, which H2 rejects; such a context must set {@code H2Dialect} to run a status update
     * (M-11d review round 2, nit 9).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM StatusListCredential s WHERE s.id = :id")
    Optional<StatusListCredential> findByIdForUpdate(@Param("id") String id);

    /**
     * Marks a list full by writing {@code credential_status} only. Saving the whole entity instead would write the
     * {@code vc_document} the caller read, silently reverting a revocation a concurrent writer committed in between
     * (review round 1, major 2: reproduced on PostgreSQL 15). No wire bytes change: every column but the status keeps
     * the value it has in the table.
     *
     * @return 1 when the row was updated, 0 when no row has that id
     */
    @Modifying(flushAutomatically = true)
    @Transactional
    @Query("UPDATE StatusListCredential s SET s.credentialStatus = :status WHERE s.id = :id")
    int updateCredentialStatus(@Param("id") String id,
                               @Param("status") StatusListCredential.CredentialStatus status);

    /**
     * Find capacity of status list by ID
     */
    @Query("SELECT s.capacityInKB FROM StatusListCredential s WHERE s.id = :id")
    Optional<Long> findCapacityInKBById(@Param("id") String id);

    /**
     * Find the maximum updated timestamp from all status list credentials
     */
    @Query("SELECT MAX(s.updatedDtimes) FROM StatusListCredential s WHERE s.updatedDtimes IS NOT NULL")
    Optional<LocalDateTime> findMaxUpdatedTime();

    /**
     * Replaces a list's document only while it is still the document the caller read (compare-and-set): a Token Status
     * List re-signed for freshness never overwrites a list the batch job (or another instance) changed in the meantime.
     *
     * @return 1 when the document was replaced, 0 when it had changed
     */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Transactional
    @Query("UPDATE StatusListCredential s SET s.vcDocument = :next WHERE s.id = :id AND s.vcDocument = :previous")
    int replaceDocument(@Param("id") String id, @Param("previous") String previous, @Param("next") String next);
}
