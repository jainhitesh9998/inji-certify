package io.mosip.certify.pki;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** RFC 5280 serial bounds and the Annex B 63 bit floor, on a fixed shape and deterministically. */
class SerialsTest {

    /** A SecureRandom stub: the same bytes every time, so the generator's shape is testable. */
    private static SecureRandom fixed(int fill) {
        return new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                java.util.Arrays.fill(bytes, (byte) fill);
            }
        };
    }

    @Test
    void randomSerialsArePositiveNineOctetsWithAtLeastSixtyFourBits() {
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            BigInteger serial = Serials.random();
            assertTrue(serial.signum() > 0, "positive: " + serial);
            assertEquals(9, Serials.octets(serial), "exactly 9 DER content octets: " + serial);
            assertTrue(serial.bitLength() >= 64, "at least 64 bits: " + serial.bitLength());
            assertEquals(71, serial.bitLength(), "bit 70 is set, so the magnitude is always 71 bits");
            assertFalse(serial.testBit(71), "no sign octet is needed");
            assertTrue(Serials.fits(serial), "fits RFC 5280 and Annex B");
            assertTrue(seen.add(serial), "serials do not repeat");
        }
    }

    @Test
    void theShapeHoldsForAnyRandomOutput() {
        for (int fill : new int[] {0x00, 0x7f, 0x80, 0xff, 0x40, 0x01}) {
            BigInteger serial = Serials.random(fixed(fill));
            assertTrue(serial.signum() > 0, "positive for fill " + fill);
            assertEquals(9, Serials.octets(serial), "9 content octets for fill " + fill);
            assertEquals(71, serial.bitLength(), "71 bits for fill " + fill);
        }
        // a draw whose top bit was set and whose low bits are all ones must still encode as a positive 9 octet integer
        BigInteger worst = Serials.random(fixed(0xff));
        assertTrue(worst.signum() > 0);
        assertTrue(Serials.fits(worst));
    }

    @Test
    void octetsCountsTheSignOctet() {
        assertEquals(1, Serials.octets(BigInteger.ONE));
        assertEquals(1, Serials.octets(BigInteger.valueOf(127)));
        assertEquals(2, Serials.octets(BigInteger.valueOf(128)), "0x80 needs a leading zero octet");
        assertEquals(20, Serials.octets(BigInteger.ONE.shiftLeft(152)), "20 magnitude octets, top bit clear");
        assertEquals(20, Serials.octets(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE)),
                "19 magnitude octets with the top bit set needs a sign octet");
        assertEquals(21, Serials.octets(BigInteger.ONE.shiftLeft(159)), "2^159 does not fit 20 content octets");
    }

    @Test
    void fitsEnforcesRfc5280AndTheAnnexBFloor() {
        assertTrue(Serials.fits(BigInteger.ONE.shiftLeft(63)), "64 bits fits");
        assertTrue(Serials.fits(BigInteger.ONE.shiftLeft(152)), "20 content octets fits");
        assertFalse(Serials.fits(BigInteger.ONE.shiftLeft(159)), "21 content octets does not fit");
        assertFalse(Serials.fits(BigInteger.ONE.shiftLeft(63).subtract(BigInteger.ONE)), "63 bits is too short");
        assertFalse(Serials.fits(BigInteger.ZERO), "zero is not positive");
        assertFalse(Serials.fits(BigInteger.valueOf(-1)), "a negative serial is refused");
        assertFalse(Serials.fits(null), "no serial is refused");
    }
}
