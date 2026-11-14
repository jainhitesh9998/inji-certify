package io.mosip.certify.services;

import java.util.Map;
import java.util.Optional;

/**
 * Interface for providing status list index assignment strategies
 */
public interface StatusListIndexProvider {

    /**
     * @return A descriptive name or identifier for this index provider strategy
     * (e.g., "DatabaseRandomAvailableIndexProvider", "RedisSequentialIndexProvider").
     */
    String getProviderName();

    /**
     * Attempts to acquire an available index from the specified status list.
     * <p>
     * The implementing class is responsible for ensuring the returned index is unique
     * for the given listId at the time of acquisition and that it respects
     * the list's capacity and any applicable usage policies (like usableCapacity).
     *
     * @param listId  The unique identifier of the status list from which to acquire an index.
     * @param options A map of optional parameters that might influence the index acquisition.
     *                This allows for flexibility in implementations. Examples:
     *                - "preferredIndex": (Long) a hint for a desired index, if supported.
     *                - "purpose": (String) context for why the index is needed, could influence choice.
     */
    Optional<Long> acquireIndex(String listId, Map<String, Object> options);

    /**
     * Gives an index {@link #acquireIndex} took back to its list's free pool, so a status entry that belongs to no
     * credential is handed out again (M-11e, owner decision D-M11e-1). A provider that cannot do that keeps this
     * default and the index is simply gone, as before.
     *
     * @param listId the list the index was acquired from
     * @param index  the index to free; one that is already free, or unknown to the list, changes nothing
     * @return whether a row was freed (so a caller can tell "given back" from "not a pool index")
     */
    default boolean releaseIndex(String listId, long index) {
        return false;
    }
}