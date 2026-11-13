package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.TokenStatusListService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Review round 1, major 2(b): the index provider marks a list {@code FULL} when its usable capacity is reached. Saving
 * the whole entity — which the JWT path did, pre-existing — writes back the {@code vc_document} read at the top of the
 * method, silently reverting a revocation committed in between. The status is written on its own now, so the document
 * in the table is untouched.
 */
class DatabaseStatusListIndexProviderFullListTest {

    StatusListAvailableIndicesRepository indices = mock(StatusListAvailableIndicesRepository.class);
    StatusListCredentialRepository lists = mock(StatusListCredentialRepository.class);
    DatabaseStatusListIndexProvider provider = new DatabaseStatusListIndexProvider();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(provider, "statusListAvailableIndicesRepository", indices);
        ReflectionTestUtils.setField(provider, "statusListCredentialRepository", lists);
        ReflectionTestUtils.setField(provider, "entityManager", mock(EntityManager.class));
        ReflectionTestUtils.setField(provider, "usableCapacityPercentage", 50);
    }

    @Test
    void aFullListIsMarkedFullWithoutRewritingItsDocument() {
        StatusListCredential stale = new StatusListCredential();
        stale.setId("list-a");
        // the document this caller read; a revocation has been committed to the table since
        stale.setVcDocument("{\"revoked\":false}");
        stale.setCredentialType(TokenStatusListService.TYPE);
        stale.setCapacityInKB(1L);
        stale.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        stale.setCreatedDtimes(LocalDateTime.now());
        when(lists.findById("list-a")).thenReturn(Optional.of(stale));
        when(indices.countByStatusListCredentialIdAndIsAssignedTrue("list-a")).thenReturn(8192L);

        Optional<Long> index = provider.acquireIndex("list-a", java.util.Map.of());

        assertEquals(Optional.empty(), index);
        verify(lists).updateCredentialStatus("list-a", StatusListCredential.CredentialStatus.FULL);
        verify(lists, never()).save(any());
        verify(lists, never()).saveAndFlush(any());
        assertEquals("{\"revoked\":false}", stale.getVcDocument(), "the caller's entity is not written back");
    }

    @Test
    void aListWithRoomIsNotMarkedFull() {
        StatusListCredential list = new StatusListCredential();
        list.setId("list-b");
        list.setVcDocument("{}");
        list.setCredentialType(TokenStatusListService.TYPE);
        list.setCapacityInKB(1L);
        list.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        when(lists.findById("list-b")).thenReturn(Optional.of(list));
        when(indices.countByStatusListCredentialIdAndIsAssignedTrue("list-b")).thenReturn(1L);

        provider.acquireIndex("list-b", java.util.Map.of());

        verify(lists, never()).updateCredentialStatus(eq("list-b"), any());
    }
}
