package io.mosip.certify.pki;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Serial numbers for ISO/IEC 18013-5:2021 Annex B certificates. RFC 5280 limits a certificate serial to 20 octets and
 * requires it to be a positive integer; Annex B requires at least 63 bits of output from a CSPRNG, so a serial must
 * not repeat across certificates an IACA signs.
 */
public final class Serials {

    /** RFC 5280 section 4.1.2.2: no more than 20 octets of serial number. */
    public static final int MAX_OCTETS = 20;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Serials() {}

    /** A fresh serial: positive, 9 octets, 71 random bits, top bit cleared. */
    public static BigInteger random() {
        return random(RANDOM);
    }

    /** A fresh serial from the given source: positive, 9 octets, 71 random bits, top bit cleared. */
    public static BigInteger random(SecureRandom random) {
        byte[] bytes = new byte[9];
        BigInteger serial;
        do {
            random.nextBytes(bytes);
            bytes[0] &= 0x7f; // DER INTEGER: mantissa only, no sign octet
            serial = new BigInteger(1, bytes);
        } while (serial.signum() == 0);
        return serial;
    }

    /** Whether a serial fits RFC 5280: positive and no longer than 20 octets. */
    public static boolean fits(BigInteger serial) {
        return serial != null && serial.signum() > 0 && octets(serial) <= MAX_OCTETS;
    }

    /** Serial length in octets as a DER INTEGER mantissa. */
    public static int octets(BigInteger serial) {
        return (serial.abs().bitLength() + 7) / 8;
    }
}
