package io.mosip.certify.status;

import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static io.mosip.certify.status.StatusListTestKeys.DEDICATED;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static io.mosip.certify.status.StatusListTestKeys.SIGNER;
import static io.mosip.certify.status.StatusListTestKeys.key;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11c: signer pinning and retirement (docs/design/wp/M-11-status-list-under-iaca.md sections 4.3 and 4.4). A list
 * belongs to one signer — Credo accepts an mDL's list only when the list's validated chain equals the mDL's issuance
 * chain — so the stored envelope records the key reference to re-sign with and the SHA-256 of the leaf certificate, and
 * re-signing refuses a signer whose certificate changed or expired.
 *
 * <p>The retirement tests use the <b>real</b> {@link JcaKeyProvider}, not a stub: it is the provider that refuses an
 * expired {@code mdoc-dsc} alias outright, so resolving before checking the stored certificate would turn D-M11-7's
 * {@code 410} into a plain {@code STATUS_SIGNER_GONE} 503 forever. {@code resolve} therefore judges the stored leaf's
 * {@code notAfter} first and only then asks the provider for the pinned reference.
 */
class StatusListSignersTest {

    @Test
    void pinGivesTheVersionedX509FileReference() {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.add("mdl-dsc@2026-11", DSC_KEYS.getPrivate(), CertificateChain.of(DSC, IACA), SignatureAlgorithm.ES256,
                "mdoc-dsc");
        KeyProviderRegistry registry = new KeyProviderRegistry(List.of(provider));
        // the configuration names the unversioned alias; the provider resolves its current version
        SigningContext signing = registry.signingContext(
                SigningConfig.of(KeyRef.parse("x509-file:mdl-dsc"), SignatureAlgorithm.ES256));

        StatusListSigners.Pinned pinned = new StatusListSigners(registry).pin(signing);
        assertEquals("x509-file:mdl-dsc@2026-11", pinned.keyRef().toString(),
                "the list stays on the version that allocated its indices, across a later rotation");
        assertEquals(StatusListSigners.x5tS256(DSC), pinned.x5tS256());
    }

    @Test
    void pinGivesTheConfiguredReferenceForKeymanager() {
        // keymanager reports a certificate thumbprint as the kid, not the alias, and rotates inside one reference
        StatusListTestKeys.MutableProvider provider = new StatusListTestKeys.MutableProvider("keymanager",
                key("thumbprint", DSC_KEYS, DSC, IACA));
        KeyProviderRegistry registry = new KeyProviderRegistry(List.of(provider));
        SigningContext signing = new SigningContext(
                SigningConfig.of(KeyRef.parse("keymanager:APP/REF"), SignatureAlgorithm.ES256),
                key("thumbprint", DSC_KEYS, DSC, IACA), SIGNER);

        StatusListSigners.Pinned pinned = new StatusListSigners(registry).pin(signing);
        assertEquals("keymanager:APP/REF", pinned.keyRef().toString());
        assertEquals(StatusListSigners.x5tS256(DSC), pinned.x5tS256());
    }

    @Test
    void pinKeepsTheConfiguredReferenceWhenTheVersionedOneNamesAnotherCertificate() {
        // the kid claims a version, but that reference resolves to another certificate: the list is pinned to the
        // configured reference instead, and the mismatch is logged at DEBUG
        SigningContext signing = new SigningContext(
                SigningConfig.of(KeyRef.parse("keymanager:APP"), SignatureAlgorithm.ES256),
                key("APP@v1", DSC_KEYS, DSC, IACA), SIGNER);
        StatusListTestKeys.MutableProvider provider = new StatusListTestKeys.MutableProvider("keymanager",
                key("APP@v1", DEDICATED_KEYS, DEDICATED, IACA));

        StatusListSigners.Pinned pinned = new StatusListSigners(new KeyProviderRegistry(List.of(provider))).pin(signing);
        assertEquals("keymanager:APP", pinned.keyRef().toString());
        assertEquals(StatusListSigners.x5tS256(DSC), pinned.x5tS256(), "the signing certificate's hash is what is pinned");
    }

    @Test
    void pinRefusesAKeyWithoutACertificate() {
        SigningContext signing = new SigningContext(
                SigningConfig.of(KeyRef.parse("keymanager:APP/REF"), SignatureAlgorithm.ES256),
                key("thumbprint", DSC_KEYS), SIGNER);
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> new StatusListSigners(new KeyProviderRegistry(List.of())).pin(signing));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), refused.getMessage());
    }

    @Test
    void resolveReturnsThePinnedSignerWithItsOwnAlgorithm() throws Exception {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.add("mdl-dsc@2026-11", DSC_KEYS.getPrivate(), CertificateChain.of(DSC, IACA), SignatureAlgorithm.ES256,
                "mdoc-dsc");
        KeyProviderRegistry registry = new KeyProviderRegistry(List.of(provider));
        StatusListSigners signers = new StatusListSigners(registry);
        StatusListSigners.Pinned pinned = signers.pin(registry.signingContext(
                SigningConfig.of(KeyRef.parse("x509-file:mdl-dsc"), SignatureAlgorithm.ES256)));

        SigningContext resolved = signers.resolve(pinned, DSC);
        assertEquals(pinned.keyRef(), resolved.key().ref());
        assertEquals(SignatureAlgorithm.ES256, resolved.key().algorithm());
        assertArrayEquals(DSC.getEncoded(), resolved.key().chain().leaf().orElseThrow().getEncoded());
        assertEquals(pinned.keyRef(), resolved.config().keyRef());
    }

    @Test
    void resolveRefusesAKeymanagerKeyRotatedUnderTheSameReference() {
        StatusListTestKeys.MutableProvider provider = new StatusListTestKeys.MutableProvider("keymanager",
                key("thumbprint", DSC_KEYS, DSC, IACA));
        KeyProviderRegistry registry = new KeyProviderRegistry(List.of(provider));
        StatusListSigners signers = new StatusListSigners(registry);
        StatusListSigners.Pinned pinned = signers.pin(new SigningContext(
                SigningConfig.of(KeyRef.parse("keymanager:APP/REF"), SignatureAlgorithm.ES256),
                key("thumbprint", DSC_KEYS, DSC, IACA), SIGNER));

        // the provider now hands out another certificate under the same reference: the indices on this list belong to
        // the old one, so no token is signed with the new one
        provider.holds(key("thumbprint", DEDICATED_KEYS, DEDICATED, IACA));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> signers.resolve(pinned, DSC));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_GONE: "), refused.getMessage());
    }

    @Test
    void resolveRetiresAnUnversionedDscWhoseStoredCertificateExpired() {
        // the real provider: an expired mdoc-dsc alias resolves to nothing, so checking the stored certificate first is
        // what keeps D-M11-7's 410 reachable (a GONE here would be a 503 forever)
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.add("mdl-dsc", EXPIRED_KEYS.getPrivate(), CertificateChain.of(EXPIRED, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        StatusListSigners signers = new StatusListSigners(new KeyProviderRegistry(List.of(provider)));
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(KeyRef.parse("x509-file:mdl-dsc"),
                StatusListSigners.x5tS256(EXPIRED));

        assertThrows(StatusListRetiredException.class, () -> signers.resolve(pinned, EXPIRED));
    }

    @Test
    void resolveRetiresAKeymanagerShapedListRotatedAfterItsCertificateExpired() {
        // the provider already holds the new certificate under the one reference keymanager rotates; the stored token
        // still names the old, expired one, which is the retirement decision
        JcaKeyProvider provider = new JcaKeyProvider("keymanager");
        provider.add("APP/REF", DEDICATED_KEYS.getPrivate(), CertificateChain.of(DEDICATED, IACA),
                SignatureAlgorithm.ES256, JcaKeyProvider.PURPOSE_VC_SIGNING);
        StatusListSigners signers = new StatusListSigners(new KeyProviderRegistry(List.of(provider)));
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(KeyRef.parse("keymanager:APP/REF"),
                StatusListSigners.x5tS256(EXPIRED));

        assertThrows(StatusListRetiredException.class, () -> signers.resolve(pinned, EXPIRED));
    }

    @Test
    void resolveWrapsAProviderFailureAsGone() {
        // the pinned reference is gone from the provider: the cause is kept, and the type is the one the service maps
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        StatusListSigners signers = new StatusListSigners(new KeyProviderRegistry(List.of(provider)));
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(KeyRef.parse("x509-file:mdl-dsc"),
                StatusListSigners.x5tS256(DSC));

        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> signers.resolve(pinned, DSC));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_GONE: "), refused.getMessage());
        assertTrue(refused.getCause() instanceof io.mosip.certify.signing.SigningException, "the provider's cause is kept");
    }

    @Test
    void resolveRefusesAStoredLeafThatIsNotThePinnedOne() {
        StatusListTestKeys.MutableProvider provider = new StatusListTestKeys.MutableProvider("keymanager",
                key("thumbprint", DSC_KEYS, DSC, IACA));
        StatusListSigners signers = new StatusListSigners(new KeyProviderRegistry(List.of(provider)));
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(KeyRef.parse("keymanager:APP/REF"),
                StatusListSigners.x5tS256(DSC));

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> signers.resolve(pinned, DEDICATED));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_GONE: "), refused.getMessage());
        assertTrue(refused.getMessage().contains("not the one the list was pinned to"), refused.getMessage());
    }

    @Test
    void resolveRefusesAPinnedSignerWithoutACertificate() {
        SigningKey withoutChain = key("thumbprint", DSC_KEYS);
        StatusListTestKeys.MutableProvider provider = new StatusListTestKeys.MutableProvider("keymanager", withoutChain);
        StatusListSigners signers = new StatusListSigners(new KeyProviderRegistry(List.of(provider)));
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(KeyRef.parse("keymanager:APP/REF"),
                StatusListSigners.x5tS256(DSC));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> signers.resolve(pinned, DSC));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), refused.getMessage());
    }

    @Test
    void thePinnedHashIsTheBase64urlSha256OfTheLeafDer() throws Exception {
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(DSC.getEncoded()));
        assertEquals(expected, StatusListSigners.x5tS256(DSC));
        assertTrue(!expected.contains("=") && !expected.contains("+") && !expected.contains("/"),
                "base64url, unpadded: " + expected);
    }
}
