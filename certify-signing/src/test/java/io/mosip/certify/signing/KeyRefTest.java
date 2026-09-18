package io.mosip.certify.signing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRefTest {

    @Test
    void parsesProviderAliasAndVersion() {
        KeyRef ref = KeyRef.parse("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN");
        assertEquals("keymanager", ref.provider());
        assertEquals("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", ref.alias());
        assertTrue(ref.versionOpt().isEmpty());
        assertEquals("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", ref.toString());

        KeyRef versioned = KeyRef.parse("jca:dev-es256@3");
        assertEquals("3", versioned.version());
        assertEquals("jca:dev-es256@3", versioned.toString());
    }

    @Test
    void rejectsMalformedReferences() {
        assertThrows(IllegalArgumentException.class, () -> KeyRef.parse("no-colon"));
        assertThrows(IllegalArgumentException.class, () -> KeyRef.parse("jca:"));
        assertThrows(IllegalArgumentException.class, () -> new KeyRef(" ", "x"));
    }
}
