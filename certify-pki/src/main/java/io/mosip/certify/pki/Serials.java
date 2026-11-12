package io.mosip.certify.pki;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Serial numbers for ISO/IEC 18013-5:2021 Annex B certificates. RFC 5280 section 4.1.2.2 limits a certificate serial to
 * 20 octets of DER INTEGER content and requires it to be a positive integer; Annex B requires at least 63 bits of
 * output from a CSPRNG, so a serial must not repeat across the certificates an IACA signs.
 *
 * <p>The generator produces a fixed-shape serial: 9 content octets, positive, with the top bit of the 71 bit magnitude
 * set. Clearing the DER sign bit alone would leave the length and the entropy to chance (a fifth of the draws would be
 * shorter than 64 bits); setting bit 70 keeps every serial at 71 bits, 70 of them random, and the DER encoding at nine
 * content octets with no sign octet.
 */
public final class Serials {

    /** RFC 5280 section 4.1.2.2: no more than 20 octets of DER INTEGER content, sign octet included. */
    public static final int MAX_OCTETS = 20;

    /**
     * The builders' floor: a serial a builder writes or accepts has at least 64 bits, so Annex B's 63 bits of CSPRNG
     * output fit. The validator cannot measure entropy and applies a lower heuristic,
     * {@link AnnexBValidator#MIN_SERIAL_BITS}, to certificates obtained elsewhere.
     */
    public static final int MIN_BITS = 64;

    /** Content octets of a serial this class generates: 71 bits of magnitude, no sign octet needed. */
    public static final int OCTETS = 9;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Serials() {}

    /** A fresh serial: positive, exactly {@value #OCTETS} content octets, 71 bits long. */
    public static BigInteger random() {
        return random(RANDOM);
    }

    /**
     * A fresh serial from the given source: positive, exactly {@value #OCTETS} content octets, 71 bits long. Bit 70 is
     * set after the sign bit is cleared, so the length and the lower bound hold for every draw.
     */
    public static BigInteger random(SecureRandom random) {
        byte[] bytes = new byte[OCTETS];
        random.nextBytes(bytes);
        bytes[0] &= 0x7f; // DER INTEGER: the sign bit stays clear, so the value is positive
        bytes[0] |= 0x40; // bit 70: the magnitude is 71 bits, never shorter than the 64 bit floor
        return new BigInteger(1, bytes);
    }

    /** Whether a builder accepts the serial: positive, at least {@value #MIN_BITS} bits, at most 20 DER content octets. */
    public static boolean fits(BigInteger serial) {
        return serial != null && serial.signum() > 0
                && serial.bitLength() >= MIN_BITS && octets(serial) <= MAX_OCTETS;
    }

    /**
     * The length of the DER INTEGER content, in octets, sign octet included: the magnitude octets, plus one leading
     * zero octet when the top bit of the magnitude is set. {@code 2^159} is 20 magnitude octets with the top bit set, so
     * it needs 21 content octets and does not fit.
     */
    public static int octets(BigInteger serial) {
        int magnitude = magnitudeOctets(serial);
        if (magnitude == 0) {
            return 0;
        }
        return serial.abs().testBit(magnitude * 8 - 1) ? magnitude + 1 : magnitude;
    }

    /** The magnitude octets of the serial, sign octet excluded. */
    public static int magnitudeOctets(BigInteger serial) {
        return (serial.abs().bitLength() + 7) / 8;
    }
}
