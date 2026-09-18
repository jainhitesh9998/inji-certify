package io.mosip.certify.repository;

import io.mosip.certify.entity.IssuanceTransaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IssuanceTransactionRepository extends JpaRepository<IssuanceTransaction, UUID> {
    Optional<IssuanceTransaction> findByNotificationIdAndAccessTokenHash(String notificationId, String accessTokenHash);

    long deleteByExpiresAtBefore(LocalDateTime cutoff);
}
