package io.mosip.certify.repository;

import io.mosip.certify.entity.StatusListCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
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
