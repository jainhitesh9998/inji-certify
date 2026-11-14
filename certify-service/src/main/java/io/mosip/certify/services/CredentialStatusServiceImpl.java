package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.TokenStatusListService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.OptionalLong;

/**
 * Queues a credential's status change for the status-list batch job.
 *
 * <p>The list's row is locked ({@code SELECT … FOR NO KEY UPDATE} on PostgreSQL) before the transaction row is inserted
 * and until it commits: the lock the batch job applies the list under ({@link StatusListTransactionApplier}). Writers of
 * one list are therefore serialised, so the {@code transaction_log_id} each draws from the database sequence follows the
 * order their changes commit in, and the job never sees a lower id commit after it applied a higher one (M-11d review
 * round 4, finding 3, G42). The cost is that a status change for a list waits while the job signs that list.
 *
 * <p>An index outside the list — negative, or at or past its size — is refused before anything is queued
 * ({@code requested_index_is_out_of_bounds_for_status_list_capacity}, through each surface's own error mapping): it names
 * no credential on the list (finding 2, G43).
 */
@Slf4j
@Service
public class CredentialStatusServiceImpl implements CredentialStatusService {
    @Autowired
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    /** The size of a Token Status List is read from its own document; absent when the application has no token lists. */
    @Autowired
    private ObjectProvider<TokenStatusListService> tokenStatusLists;

    @Override
    @Transactional
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {
        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();
        String id = request.getCredentialStatus().getId();

        if(id != null && !id.equals(statusListCredentialId)) {
            throw new CertifyException(ErrorConstants.STATUS_ID_MISMATCH, "Mismatch between credential status ID and Status List Credential.");
        }
        // the list's row lock, held until this transaction commits: the batch job's lock, so the sequence value the
        // insert below draws is in commit order for this list
        StatusListCredential statusListCredential = (statusListCredentialId == null ? java.util.Optional.<StatusListCredential>empty()
                : statusListCredentialRepository.findByIdForUpdate(statusListCredentialId))
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + statusListCredentialId));
        OptionalLong capacity = StatusListEntries.capacity(statusListCredential,
                tokenStatusLists == null ? null : tokenStatusLists.getIfAvailable());
        if (!StatusListEntries.inRange(statusListIndex, capacity)) {
            log.warn("Status update refused: index {} is not on status list {}, whose indices are {}", statusListIndex,
                    statusListCredentialId, StatusListEntries.describe(capacity));
            throw new CertifyException(ErrorConstants.INDEX_OUT_OF_BOUNDS, "Status list index " + statusListIndex
                    + " is outside status list " + statusListCredentialId + ", whose indices are "
                    + StatusListEntries.describe(capacity));
        }

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        if(StringUtils.isEmpty(request.getCredentialStatus().getStatusPurpose())) {
            transaction.setStatusPurpose(statusListCredential.getStatusPurpose());
        } else {
            transaction.setStatusPurpose(request.getCredentialStatus().getStatusPurpose());
        }
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(statusListIndex);
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setStatusListCredentialUrl(transaction.getStatusListCredentialId());
        dto.setStatusListIndex(transaction.getStatusListIndex());
        dto.setStatusPurpose(transaction.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        if(request.getCredentialStatus().getType() != null) {
            dto.setCredentialType(request.getCredentialStatus().getType());
        }
        return dto;
    }
}
