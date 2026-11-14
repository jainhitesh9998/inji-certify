package io.mosip.certify.status;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11d review round 4, finding 2: an index is held to {@code [0, bits.length × 8)} as a {@code long}, before anything
 * narrows it. {@code (int) (idx / 8)} wrapped 2^35 to byte 0 and set index 0 — another credential's status — and the
 * transaction was marked processed; a negative index had no complete guard.
 */
class TokenStatusListBitsTest {

    @Test
    void anIndexOutsideTheListNeverReachesTheBitArray() {
        for (long outside : new long[]{-1, -8, Long.MIN_VALUE, 16, 17, 1L << 35, (1L << 35) + 3, (1L << 32) * 8, Long.MAX_VALUE}) {
            byte[] bits = new byte[2];
            assertThrows(IllegalStateException.class, () -> TokenStatusListService.set(bits, outside, true), "set " + outside);
            assertArrayEquals(new byte[2], bits, "nothing changed for " + outside);
            assertThrows(IndexOutOfBoundsException.class, () -> TokenStatusListService.get(bits, outside), "get " + outside);
        }
    }

    @Test
    void theFirstAndLastIndicesAreInside() {
        byte[] bits = new byte[2];
        TokenStatusListService.set(bits, 0, true);
        TokenStatusListService.set(bits, 15, true);
        assertTrue(TokenStatusListService.get(bits, 0));
        assertTrue(TokenStatusListService.get(bits, 15));
        assertFalse(TokenStatusListService.get(bits, 8));
        assertArrayEquals(new byte[]{1, (byte) 0x80}, bits, "least significant bit first (TSL section 4.1)");
        TokenStatusListService.set(bits, 15, false);
        assertFalse(TokenStatusListService.get(bits, 15));
    }
}
