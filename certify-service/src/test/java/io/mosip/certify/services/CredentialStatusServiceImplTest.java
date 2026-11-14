package io.mosip.certify.services;

import io.mosip.certify.core.exception.StatusListBusyException;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusServiceImplTest {
    @Mock
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        // the mocked repository is no database: the lock's wait is not bounded by a statement, a lock failure is mapped
        org.springframework.test.util.ReflectionTestUtils.setField(credentialStatusService, "statusListLockWait",
                StatusListLockWait.withoutDatabase());
    }

    @Test
    public void updateCredentialStatusV2_StatusIdMismatch_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setId("https://example.com/status-list/abc#12345"); // Mismatched ID

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_id_mismatch", exception.getErrorCode());
        assertEquals("Mismatch between credential status ID and Status List Credential.", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_StatusListNotFound_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        when(statusListCredentialRepository.findByIdForUpdate(statusListCredential)).thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: " + statusListCredential, exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusPurpose_UsesStatusListCredentialPurpose() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(null); // Null status purpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findByIdForUpdate(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void updateCredentialStatusV2_ValidRequest_ReturnsResponse() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findByIdForUpdate(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals(statusListCredential, response.getStatusListCredentialUrl());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(87823L, response.getStatusListIndex());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusListCredential_ThrowsException() {
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(null); // Null StatusListCredential

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: null", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusListIndex_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(null); // Null StatusListIndex

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: https://example.com/status-list/xyz#87823", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_EmptyStatusPurpose_UsesStatusListCredentialPurpose() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(""); // Empty StatusPurpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findByIdForUpdate(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void updateCredentialStatusV2_InvalidStatusListCredentialFormat_ThrowsException() {
        String statusListCredential = "invalid-format";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: invalid-format", exception.getMessage());
    }

    /**
     * M-11d review round 4, finding 2 (G43): an index that is not on the list is refused before anything is queued — a
     * negative one, 2^35 (which a narrowing conversion wrapped onto index 0), and the index equal to the list's size —
     * for a Bitstring list (its {@code capacity_in_kb}) and for a Token Status List (its own {@code lst}).
     */
    @Test
    public void updateCredentialStatus_IndexNotOnTheList_IsRefusedBeforeAnythingIsQueued() {
        String listId = "bitstring-list";
        StatusListCredential bitstring = new StatusListCredential();
        bitstring.setId(listId);
        bitstring.setCapacityInKB(16L); // 131,072 statuses
        when(statusListCredentialRepository.findByIdForUpdate(listId)).thenReturn(Optional.of(bitstring));
        for (long index : new long[]{-1L, 131_072L, 1L << 35, Long.MIN_VALUE}) {
            UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(listId);
            request.getCredentialStatus().setStatusListIndex(index);
            CertifyException refused = assertThrows(CertifyException.class, () -> credentialStatusService.updateCredentialStatus(request));
            assertEquals("requested_index_is_out_of_bounds_for_status_list_capacity", refused.getErrorCode());
        }
        org.mockito.Mockito.verify(credentialStatusTransactionRepository, org.mockito.Mockito.never()).save(any());

        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class))).thenAnswer(invocation -> invocation.getArgument(0));
        UpdateCredentialStatusRequest last = createValidUpdateCredentialRequest(listId);
        last.getCredentialStatus().setStatusListIndex(131_071L);
        assertEquals(131_071L, credentialStatusService.updateCredentialStatus(last).getStatusListIndex(), "the last index is on the list");
    }

    @Test
    public void updateCredentialStatus_TokenStatusListIndex_IsHeldToTheListsOwnSize() {
        String listId = "token-list";
        StatusListCredential token = new StatusListCredential();
        token.setId(listId);
        token.setCredentialType(io.mosip.certify.status.TokenStatusListService.TYPE_CWT);
        token.setCapacityInKB(1L); // what the row says; the token's own lst decides
        when(statusListCredentialRepository.findByIdForUpdate(listId)).thenReturn(Optional.of(token));
        io.mosip.certify.status.TokenStatusListService tokenLists = org.mockito.Mockito.mock(io.mosip.certify.status.TokenStatusListService.class);
        when(tokenLists.capacity(token)).thenReturn(java.util.OptionalLong.of(16));
        @SuppressWarnings("unchecked")
        org.springframework.beans.factory.ObjectProvider<io.mosip.certify.status.TokenStatusListService> provider =
                org.mockito.Mockito.mock(org.springframework.beans.factory.ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(tokenLists);
        org.springframework.test.util.ReflectionTestUtils.setField(credentialStatusService, "tokenStatusLists", provider);

        UpdateCredentialStatusRequest atSize = createValidUpdateCredentialRequest(listId);
        atSize.getCredentialStatus().setStatusListIndex(16L);
        assertEquals("requested_index_is_out_of_bounds_for_status_list_capacity",
                assertThrows(CertifyException.class, () -> credentialStatusService.updateCredentialStatus(atSize)).getErrorCode());

        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class))).thenAnswer(invocation -> invocation.getArgument(0));
        UpdateCredentialStatusRequest inside = createValidUpdateCredentialRequest(listId);
        inside.getCredentialStatus().setStatusListIndex(15L);
        assertEquals(15L, credentialStatusService.updateCredentialStatus(inside).getStatusListIndex());
    }

    /**
     * Review round 5, finding 1: the list's row lock not available within {@code certify.status.update.lock-wait}
     * (PostgreSQL {@code lock_not_available}, wrapped as Spring wraps it) is a retryable refusal and nothing is queued.
     */
    @Test
    public void updateCredentialStatus_ListLockNotAvailable_IsRefusedRetryablyAndQueuesNothing() {
        String listId = "busy-list";
        org.mockito.Mockito.doThrow(new org.springframework.dao.PessimisticLockingFailureException("could not obtain lock",
                        new java.sql.SQLException("canceling statement due to lock timeout", "55P03")))
                .when(statusListCredentialRepository).findByIdForUpdate(listId);
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(listId);

        StatusListBusyException refused = assertThrows(StatusListBusyException.class,
                () -> credentialStatusService.updateCredentialStatus(request));
        assertEquals("status_list_busy_retry_later", refused.getErrorCode());
        assertEquals(listId, refused.listId());
        assertEquals(5L, refused.retryAfterSeconds(), "Retry-After: the lock wait");
        org.mockito.Mockito.verify(credentialStatusTransactionRepository, org.mockito.Mockito.never()).save(any());

        // any other database failure is not dressed up as retryable
        org.mockito.Mockito.doThrow(new org.springframework.dao.DataAccessResourceFailureException("connection refused"))
                .when(statusListCredentialRepository).findByIdForUpdate(listId);
        RuntimeException other = assertThrows(RuntimeException.class, () -> credentialStatusService.updateCredentialStatus(request));
        org.junit.jupiter.api.Assertions.assertFalse(other instanceof StatusListBusyException);
    }

    /** Review round 5, nit 5: a missing index is refused saying so, not as an index outside the list. */
    @Test
    public void updateCredentialStatus_MissingIndex_SaysTheIndexIsMissing() {
        String listId = "bitstring-list";
        StatusListCredential bitstring = new StatusListCredential();
        bitstring.setId(listId);
        bitstring.setCapacityInKB(16L);
        when(statusListCredentialRepository.findByIdForUpdate(listId)).thenReturn(Optional.of(bitstring));
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(listId);
        request.getCredentialStatus().setStatusListIndex(null);

        CertifyException refused = assertThrows(CertifyException.class, () -> credentialStatusService.updateCredentialStatus(request));
        assertEquals("missing_credential_status_details", refused.getErrorCode());
        assertEquals("Status list index is missing: a status change names the index of the credential on status list "
                + listId, refused.getMessage());
        org.mockito.Mockito.verify(credentialStatusTransactionRepository, org.mockito.Mockito.never()).save(any());
    }

    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String statusListCredential) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential);
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialStatus(statusDto);
        request.setStatus(true); // Mark as revoked

        return request;
    }
}