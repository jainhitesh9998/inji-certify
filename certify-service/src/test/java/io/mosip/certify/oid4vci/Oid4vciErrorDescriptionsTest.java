package io.mosip.certify.oid4vci;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * OpenID4VCI 1.0 section 8.3.1.2 gives {@code error_description} the grammar of RFC 6749 appendix A.7:
 * {@code 1*( %x20-21 / %x23-5B / %x5D-7E )}. A description Certify derives from a certificate subject, a key alias or an
 * exception message can hold anything, so it is made safe at the protocol boundary (M-11e review round 1, minor 5).
 */
class Oid4vciErrorDescriptionsTest {

    /** The ABNF of RFC 6749 appendix A.7, spelled out: printable US-ASCII without the double quote and the backslash. */
    private static final Pattern ALLOWED = Pattern.compile("^[\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]*$");

    @Test
    void aDescriptionThatIsAlreadySafeIsReturnedUnchanged() {
        String message = "Issuance failed: status_list_unavailable: ISO/IEC 18013-5 second edition 12.3.6.1: an mDoc"
                + " status list carries only revoked/valid (D-M11-5)";

        assertSame(message, Oid4vciErrorDescriptions.safe(message), "no character is replaced, so it is the same object");
        assertTrue(ALLOWED.matcher(message).matches(), "the test's own fixture is inside the grammar");
    }

    /** A certificate subject with a country name a deployment configured in its own alphabet. */
    @Test
    void aUnicodeCertificateSubjectIsMadeSafe() {
        String safe = Oid4vciErrorDescriptions.safe("the certificate CN=Lorem Ípsum DŚC Ünïcode is not issued by any IACA");

        assertEquals("the certificate CN=Lorem ?psum D?C ?n?code is not issued by any IACA", safe);
        assertTrue(ALLOWED.matcher(safe).matches(), safe);
    }

    /** A quote and a backslash are printable ASCII and still outside the grammar. */
    @Test
    void quotesAndBackslashesAreReplaced() {
        String safe = Oid4vciErrorDescriptions.safe("signing.x5c \"none\" is not allowed: C:\\keys\\dsc.p12");

        assertEquals("signing.x5c ?none? is not allowed: C:?keys?dsc.p12", safe);
        assertTrue(ALLOWED.matcher(safe).matches(), safe);
        assertFalse(safe.contains("\""), safe);
        assertFalse(safe.contains("\\"), safe);
    }

    /** An exception message that carries a newline, a carriage return, a tab or another control character. */
    @Test
    void newlinesTabsAndControlCharactersAreReplaced() {
        String safe = Oid4vciErrorDescriptions.safe("first line\nsecond line\r\n\tindented\u0007bell\u001b[31m");

        assertEquals("first line?second line???indented?bell?[31m", safe);
        assertTrue(ALLOWED.matcher(safe).matches(), safe);
    }

    /** The boundary of the grammar itself: 0x20 and 0x21 are in, 0x22 out, 0x5B and 0x5D are in, 0x5C out, 0x7E in. */
    @Test
    void theGrammarsEdgesAreHeld() {
        assertEquals(" !?#[]~", Oid4vciErrorDescriptions.safe(" !?#[]~"));
        assertEquals("???", Oid4vciErrorDescriptions.safe("\"\\\u007F"));
        assertEquals("?", Oid4vciErrorDescriptions.safe("\u0080"));
    }

    @Test
    void aNullDescriptionStaysNull() {
        assertNull(Oid4vciErrorDescriptions.safe(null));
    }
}
