package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.status.TokenStatusListService;
import io.mosip.certify.utils.BitStringStatusListUtils;

import java.util.OptionalLong;

/**
 * Which indices a status list has, whatever its kind: what the status-update API checks before it queues a transaction
 * and what the batch job checks before it applies one (M-11d review round 4, finding 2). An index outside the list must
 * never reach the bit array: narrowed to {@code int} it can wrap onto another credential's index.
 */
final class StatusListEntries {

    private StatusListEntries() {
    }

    /**
     * How many statuses {@code list} holds: a Token Status List's own {@code lst} (JWT or CWT,
     * {@link TokenStatusListService#capacity}), or a Bitstring list's {@code capacity_in_kb}.
     *
     * @param tokenLists the token-list service, {@code null} when the application has none
     * @return empty when the size cannot be read; then only the lower bound can be checked, and the list's own update
     *         reports what is wrong with it
     */
    static OptionalLong capacity(StatusListCredential list, TokenStatusListService tokenLists) {
        String type = list.getCredentialType();
        if (TokenStatusListService.TYPE.equals(type) || TokenStatusListService.TYPE_CWT.equals(type)) {
            return tokenLists == null ? OptionalLong.empty() : tokenLists.capacity(list);
        }
        if (list.getCapacityInKB() == null) {
            return OptionalLong.empty();
        }
        try {
            return OptionalLong.of(BitStringStatusListUtils.capacityInBits(list.getCapacityInKB()));
        } catch (RuntimeException e) {
            return OptionalLong.empty();
        }
    }

    /** {@code 0 <= index < capacity}, compared as {@code long}s; with no known capacity, {@code 0 <= index}. */
    static boolean inRange(Long index, OptionalLong capacity) {
        return index != null && index >= 0 && (capacity.isEmpty() || index < capacity.getAsLong());
    }

    /** What a refusal says about the list's size. */
    static String describe(OptionalLong capacity) {
        return capacity.isPresent() ? "[0, " + capacity.getAsLong() + ")" : "[0, its size, which cannot be read)";
    }
}
