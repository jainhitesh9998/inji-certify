package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;

public interface CredentialStatusService {
    /**
     * Queues a status change for its list. On PostgreSQL it waits for the list's row lock at most
     * {@code certify.status.update.lock-wait} and otherwise throws
     * {@link io.mosip.certify.core.exception.StatusListBusyException} (retryable; nothing queued). Called inside a
     * caller's transaction it joins it: the bounded {@code lock_timeout} then applies to the rest of that transaction,
     * and a busy refusal marks it rollback-only, so a caller that catches the refusal cannot go on and commit.
     */
    CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest updateCredentialStatusRequest);
}
