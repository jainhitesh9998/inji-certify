package io.mosip.certify.status;

import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.SigningContext;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.function.Executable;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.mosip.certify.status.StatusListTestKeys.BEHIND_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static io.mosip.certify.status.StatusListTestKeys.IACA_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.NO_DIGITAL_SIGNATURE;
import static io.mosip.certify.status.StatusListTestKeys.NO_DIGITAL_SIGNATURE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.NOT_YET_VALID;
import static io.mosip.certify.status.StatusListTestKeys.NOT_YET_VALID_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.OTHER_CA;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER_DSC;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER_DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.UNTRUSTED;
import static io.mosip.certify.status.StatusListTestKeys.UNTRUSTED_KEYS;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11c: {@link StatusListSignerPolicy}, rule by rule (docs/design/wp/M-11-status-list-under-iaca.md section 4.7).
 * Each named rule has a test that breaks only that rule and is refused with the rule as the message prefix, and the
 * coverage of {@link StatusListSignerPolicy#RULES} is recorded, not declared
 * ({@link #everyNamedRuleHasANegativeTest}, run last).
 *
 * <p>Two groups, as for the mDoc Document Signer: the rules that hold whatever is configured, and — only once an
 * {@code mdoc-iaca} anchor exists (D16's enforcement switch) — the trust anchor, revocation, CRL freshness and the
 * extended key usage of the mode. The mode is the one real difference between a Document Signer and a dedicated
 * signer: {@code 1.0.18013.5.1.2} versus {@code 1.3.6.1.5.5.7.3.45}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StatusListSignerPolicyTest {

    static final Set<String> REFUSED = ConcurrentHashMap.newKeySet();
    static final Instant NOW = Instant.now();

    static void refused(String rule, Executable executable) {
        IllegalStateException refused = assertThrows(IllegalStateException.class, executable, rule);
        assertTrue(refused.getMessage().startsWith(rule + ": "), "the refusal names " + rule + ": " + refused.getMessage());
        REFUSED.add(rule);
    }

    static StatusListSignerPolicy enforcedBy(X509Certificate... iacas) {
        StatusListSignerPolicy policy = new StatusListSignerPolicy(trusting(iacas));
        assertTrue(policy.enforced());
        return policy;
    }

    /** A registry trusting {@code iacas} under ids {@code iaca-0}, {@code iaca-1}…, with CRLs by id. */
    static TrustAnchorRegistry registry(List<X509Certificate> iacas, Map<String, X509CRL> crls) {
        List<TrustAnchorRegistry.Anchor> anchors = new ArrayList<>();
        for (int i = 0; i < iacas.size(); i++) {
            anchors.add(new TrustAnchorRegistry.Anchor("iaca-" + i, TrustAnchorRegistry.MDOC_IACA, iacas.get(i)));
        }
        return new TrustAnchorRegistry() {
            @Override
            public List<Anchor> entries(String purpose) {
                return TrustAnchorRegistry.MDOC_IACA.equals(purpose) ? List.copyOf(anchors) : List.of();
            }

            @Override
            public Optional<X509CRL> crl(String anchorId) {
                return Optional.ofNullable(crls.get(anchorId));
            }
        };
    }

    static TrustAnchorRegistry trusting(X509Certificate... iacas) {
        return registry(List.of(iacas), Map.of());
    }

    static TrustAnchorRegistry withCrl(X509CRL crl) {
        return registry(List.of(IACA), Map.of("iaca-0", crl));
    }

    // ---- without anchors: only the rules that always hold -------------------------------------------------------

    @Test
    void withoutAnchorsOnlyTheAlwaysGroupRuns() {
        StatusListSignerPolicy policy = StatusListSignerPolicy.notEnforced();
        assertFalse(policy.enforced());
        assertFalse(new StatusListSignerPolicy(null).enforced(), "no registry means no anchors");

        // a signer with no EKU at all, and one no IACA issued (keymanager's master-signed certificate): nothing checks
        // purpose or trust without anchors, exactly as MdocDscPolicy behaves (D16 refined; CLAUDE.md rule 1)
        assertDoesNotThrow(() -> policy.check(context(NO_EKU_KEYS, NO_EKU, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertDoesNotThrow(() -> policy.check(context(UNTRUSTED_KEYS, UNTRUSTED, OTHER_CA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));

        // the always group still holds
        refused(StatusListSignerPolicy.NO_CHAIN, () -> policy.check(
                context(DSC_KEYS, CertificateChain.EMPTY), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.SELF_SIGNED, () -> policy.check(
                context(IACA_KEYS, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.EXPIRED, () -> policy.check(
                context(EXPIRED_KEYS, EXPIRED, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.NOT_YET_VALID, () -> policy.check(
                context(NOT_YET_VALID_KEYS, NOT_YET_VALID, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.CHAIN_LINK_INVALID, () -> policy.check(
                context(DSC_KEYS, DSC, OTHER_CA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.CARRIES_ANCHOR, () -> policy.check(
                context(ROLLOVER_DSC_KEYS, ROLLOVER_DSC, ROLLOVER, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    // ---- with an anchor: the trust path ------------------------------------------------------------------------

    @Test
    void anAnnexBDocumentSignerPassesOnceTheIacaIsAnAnchor() {
        StatusListSignerPolicy policy = enforcedBy(IACA);
        assertDoesNotThrow(() -> policy.check(context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "[DSC, IACA] as an x509-file provider holds it");
        assertDoesNotThrow(() -> policy.check(context(DSC_KEYS, DSC), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "a leaf-only chain is issued by the anchor directly");
        assertDoesNotThrow(() -> policy.check(context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE, IACA),
                NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "the chain's top certificate is the intermediate the IACA issued, and the emitted x5chain keeps it");
    }

    @Test
    void aSignerNoConfiguredIacaIssuedIsRefused() {
        refused(StatusListSignerPolicy.NO_TRUSTED_IACA, () -> enforcedBy(IACA).check(
                context(UNTRUSTED_KEYS, UNTRUSTED, OTHER_CA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // the same signer under a registry that does trust its CA passes: the rule is about the configured anchors
        assertDoesNotThrow(() -> enforcedBy(OTHER_CA).check(context(UNTRUSTED_KEYS, UNTRUSTED, OTHER_CA), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void aRevokedSignerIsRefused() {
        X509CRL revoking = StatusListTestKeys.crl(Instant.now().minus(1, java.time.temporal.ChronoUnit.HOURS),
                Instant.now().plus(20, java.time.temporal.ChronoUnit.DAYS), DSC.getSerialNumber());
        refused(StatusListSignerPolicy.REVOKED, () -> new StatusListSignerPolicy(withCrl(revoking)).check(
                context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void aStaleCrlIsRefused() {
        refused(StatusListSignerPolicy.CRL_STALE, () -> new StatusListSignerPolicy(withCrl(StatusListTestKeys.staleCrl()))
                .check(context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // a fresh CRL that lists nothing lets the signer through
        assertDoesNotThrow(() -> new StatusListSignerPolicy(withCrl(StatusListTestKeys.freshCrl()))
                .check(context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void theExtendedKeyUsageIsTheModes() {
        StatusListSignerPolicy policy = enforcedBy(IACA);
        refused(StatusListSignerPolicy.PURPOSE, () -> policy.check(
                context(NO_EKU_KEYS, NO_EKU, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.PURPOSE, () -> policy.check(
                context(DEDICATED_KEYS, DEDICATED, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.PURPOSE, () -> policy.check(
                context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DEDICATED));
        refused(StatusListSignerPolicy.PURPOSE, () -> policy.check(
                context(NO_DIGITAL_SIGNATURE_KEYS, NO_DIGITAL_SIGNATURE, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // each mode accepts its own purpose
        assertDoesNotThrow(() -> policy.check(context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertDoesNotThrow(() -> policy.check(context(DEDICATED_KEYS, DEDICATED, IACA), NOW, StatusListSignerPolicy.Mode.DEDICATED));
    }

    // ---- the two layers fail alike ----------------------------------------------------------------------------

    @Test
    void anEnvelopeRefusalMapsLikeAPolicyRefusal() {
        // M-11a's envelope refuses three things itself, with the same prefixes
        SigningException envelope = new SigningException("STATUS_SIGNER_NO_CHAIN: the signing key has no certificate");
        RuntimeException mapped = StatusListSignerPolicy.refusal(envelope);
        assertEquals(IllegalStateException.class, mapped.getClass());
        assertEquals(envelope.getMessage(), mapped.getMessage());
        assertSame(envelope, mapped.getCause());

        // the policy's own refusals pass through unchanged
        IllegalStateException policyRefusal = new IllegalStateException("CRL_STALE: the CRL passed its nextUpdate");
        assertSame(policyRefusal, StatusListSignerPolicy.refusal(policyRefusal));

        // anything else keeps its own type
        SigningException unrelated = new SigningException("Key manager is down");
        assertSame(unrelated, StatusListSignerPolicy.refusal(unrelated));
        IllegalArgumentException callerError = new IllegalArgumentException("bad claim");
        assertSame(callerError, StatusListSignerPolicy.refusal(callerError));
    }

    @Test
    void theCodecEnvelopeAndPolicyRefuseAlikeEndToEnd() {
        // the policy refuses the expired signer itself
        IllegalStateException policyRefusal = assertThrows(IllegalStateException.class,
                () -> enforcedBy(IACA).check(context(EXPIRED_KEYS, EXPIRED, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertTrue(policyRefusal.getMessage().startsWith(StatusListSignerPolicy.EXPIRED + ": "));
        // and a signer the policy let through but whose chain is unusable is refused by the envelope, in the same shape
        SigningContext noChain = context(DSC_KEYS, CertificateChain.EMPTY);
        SigningException envelope = assertThrows(SigningException.class, () -> TokenStatusListCwt.encode(
                "https://issuer.example.test/1", NOW, NOW.plusSeconds(7200), java.time.Duration.ofHours(1),
                new byte[1], noChain));
        assertTrue(StatusListSignerPolicy.refusal(envelope) instanceof IllegalStateException);
    }

    // ---- coverage ---------------------------------------------------------------------------------------------

    @Test
    @Order(Integer.MAX_VALUE)
    void everyNamedRuleHasANegativeTest() {
        assertEquals(StatusListSignerPolicy.RULES, Set.copyOf(REFUSED),
                "each rule of section 4.7 has a test that breaks only it: " + StatusListSignerPolicy.RULES);
    }

    @Test
    void theModeIsRequired() {
        StatusListSignerPolicy policy = StatusListSignerPolicy.notEnforced();
        assertThrows(NullPointerException.class, () -> policy.check(context(DSC_KEYS, DSC, IACA), NOW, null));
        assertThrows(NullPointerException.class, () -> policy.check(null, NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertThrows(NullPointerException.class, () -> policy.check(context(DSC_KEYS, DSC, IACA), null,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    private static SigningContext context(java.security.KeyPair keys, X509Certificate... chain) {
        return StatusListTestKeys.context(keys, chain);
    }

    private static SigningContext context(java.security.KeyPair keys, CertificateChain chain) {
        return StatusListTestKeys.context(keys, chain);
    }
}
