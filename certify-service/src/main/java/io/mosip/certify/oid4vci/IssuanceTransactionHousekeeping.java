package io.mosip.certify.oid4vci;

import io.mosip.certify.repository.IssuanceTransactionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

/** Deletes issuance transactions past their retention (`certify.protocol.oid4vci-v1.notification.purge-interval`). */
@Slf4j
@Component
public class IssuanceTransactionHousekeeping {

    private final IssuanceTransactionRepository repository;

    public IssuanceTransactionHousekeeping(IssuanceTransactionRepository repository) {
        this.repository = repository;
    }

    @Transactional
    @Scheduled(fixedDelayString = "${certify.protocol.oid4vci-v1.notification.purge-interval:PT1H}",
            initialDelayString = "${certify.protocol.oid4vci-v1.notification.purge-interval:PT1H}")
    public void purgeExpired() {
        long purged = purgeExpired(LocalDateTime.now(ZoneOffset.UTC));
        if (purged > 0) {
            log.info("Purged {} expired issuance transactions", purged);
        }
    }

    @Transactional
    public long purgeExpired(LocalDateTime now) {
        return repository.deleteByExpiresAtBefore(now);
    }
}
