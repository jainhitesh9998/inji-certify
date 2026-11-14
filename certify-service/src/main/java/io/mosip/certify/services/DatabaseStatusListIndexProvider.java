package io.mosip.certify.services;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.StatusListAvailableIndices;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.TokenStatusListService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class DatabaseStatusListIndexProvider implements StatusListIndexProvider {

    @Autowired
    private StatusListAvailableIndicesRepository statusListAvailableIndicesRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private EntityManager entityManager;

    @Value("${mosip.certify.statuslist.usable-capacity-percentage:50}")
    private int usableCapacityPercentage;

    @Override
    public String getProviderName() {
        return "DatabaseRandomAvailableIndexProvider";
    }

    @Override
    @Transactional
    public Optional<Long> acquireIndex(String listId, Map<String, Object> options) {
        log.debug("Attempting to acquire index for status list: {}", listId);

        try {
            // 1. Get status list and its capacity
            Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(listId);
            if (statusListOpt.isEmpty()) {
                log.error("Status list not found: {}", listId);
                return Optional.empty();
            }

            StatusListCredential statusList = statusListOpt.get();
            // a Token Status List holds exactly the statuses its own lst bits count: capacity_in_kb is a whole-kilobyte
            // column, so a 256-bit list says 1 KB and a pool sized from it would hand out indices outside the list
            // (M-11e review round 1, major 2)
            long physicalCapacity = TokenStatusListService.tokenListBits(statusList)
                    .orElse(statusList.getCapacityInKB() * 1024L * 8L); // Convert KB to bits

            // 2. Calculate effective threshold based on usable capacity
            long effectiveThresholdCount = (long) Math.floor(physicalCapacity * (usableCapacityPercentage / 100.0));

            // 3. Check current assigned count
            long currentAssignedCount = statusListAvailableIndicesRepository
                    .countByStatusListCredentialIdAndIsAssignedTrue(listId);

            if (currentAssignedCount >= effectiveThresholdCount) {
                log.warn("Status list {} has reached usable capacity limit ({}/{})",
                        listId, currentAssignedCount, effectiveThresholdCount);

                // Mark status list as full. credential_status only: saving the whole entity would write back the
                // vc_document read here and revert a revocation committed in between (review round 1, M-11d major 2;
                // the same lost update the CWT path had, pre-existing on the JWT path)
                statusListCredentialRepository.updateCredentialStatus(listId,
                        StatusListCredential.CredentialStatus.FULL);

                return Optional.empty();
            }

            // 4. Attempt to atomically claim an index using native query
            Long claimedIndex = atomicallyClaimIndex(listId);

            if (claimedIndex != null) {
                log.info("Successfully claimed index {} for status list: {}", claimedIndex, listId);
                return Optional.of(claimedIndex);
            } else {
                log.warn("Failed to claim any available index for status list: {}", listId);
                return Optional.empty();
            }

        } catch (Exception e) {
            log.error("Error acquiring index for status list: {}", listId, e);
            return Optional.empty();
        }
    }

    /**
     * Gives an index back to its list's free pool (M-11e, D-M11e-1): the row is freed only while it is still assigned,
     * so one acquisition is given back at most once, however many releases are asked for.
     *
     * <p>credential_status is untouched: a list that was closed as {@code FULL} (no free index at the time) stays closed,
     * because the pool is handed out oldest list first and re-opening a list whose threshold was reached would put it
     * back in front of the lists created after it.
     */
    @Override
    @Transactional
    public boolean releaseIndex(String listId, long index) {
        try {
            Query query = entityManager.createNativeQuery("""
                    UPDATE status_list_available_indices
                    SET is_assigned = false,
                        upd_dtimes = NOW()
                    WHERE status_list_credential_id = :listId
                        AND list_index = :index
                        AND is_assigned = true
                    """);
            query.setParameter("listId", listId);
            query.setParameter("index", index);
            int freed = query.executeUpdate();
            if (freed > 0) {
                log.info("Released index {} of status list {}: the credential it was taken for was not issued", index, listId);
            }
            return freed > 0;
        } catch (Exception e) {
            log.error("Could not release index {} of status list {}", index, listId, e);
            return false;
        }
    }

    /**
     * Atomically claim an available index using database skip lock mechanism
     */
    private Long atomicallyClaimIndex(String listId) {
        try {
            String sql = """
                WITH available_slot AS (
                    SELECT list_index
                    FROM status_list_available_indices
                    WHERE status_list_credential_id = :listId 
                        AND is_assigned = false
                    ORDER BY RANDOM()
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE status_list_available_indices sla
                SET is_assigned = true,
                    upd_dtimes = NOW()
                FROM available_slot avs
                WHERE sla.status_list_credential_id = :listId
                    AND sla.list_index = avs.list_index
                    AND sla.is_assigned = false
                RETURNING sla.list_index
                """;

            Query query = entityManager.createNativeQuery(sql);
            query.setParameter("listId", listId);

            Object result = query.getSingleResult();

            if (result != null) {
                if (result instanceof BigInteger) {
                    return ((BigInteger) result).longValue();
                } else if (result instanceof Long) {
                    return (Long) result;
                } else if (result instanceof Integer) {
                    return ((Integer) result).longValue();
                }
            }

            return null;

        } catch (Exception e) {
            log.debug("No available index found or error in atomic claim for list: {}", listId);
            return null;
        }
    }
}