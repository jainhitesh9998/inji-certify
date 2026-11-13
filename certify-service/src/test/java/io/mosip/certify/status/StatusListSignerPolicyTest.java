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

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static io.mosip.certify.status.StatusListTestKeys.BEHIND_DEEP_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_DEEP_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_END_ENTITY_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_END_ENTITY_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_IACA_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_IACA_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_SHORT_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.BEHIND_SHORT_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DEEP_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.END_ENTITY_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.END_ENTITY_INTERMEDIATE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_IACA;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.FUTURE_IACA;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static io.mosip.certify.status.StatusListTestKeys.IACA_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.IACA_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.MULTI_TIER_ROOT;
import static io.mosip.certify.status.StatusListTestKeys.NO_DIGITAL_SIGNATURE;
import static io.mosip.certify.status.StatusListTestKeys.NO_DIGITAL_SIGNATURE_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.NOT_YET_VALID;
import static io.mosip.certify.status.StatusListTestKeys.NOT_YET_VALID_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.OTHER_CA;
import static io.mosip.certify.status.StatusListTestKeys.PATHLEN_ZERO;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER_DSC;
import static io.mosip.certify.status.StatusListTestKeys.ROLLOVER_DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.SHORT_IACA;
import static io.mosip.certify.status.StatusListTestKeys.SHORT_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.SUB_INTERMEDIATE;
import static io.mosip.certify.status.StatusListTestKeys.SUB_INTERMEDIATE_DSC;
import static io.mosip.certify.status.StatusListTestKeys.SUB_INTERMEDIATE_DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_EXPIRED_IACA;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_EXPIRED_IACA_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_FUTURE_IACA;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_FUTURE_IACA_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_SHORT_IACA;
import static io.mosip.certify.status.StatusListTestKeys.UNDER_SHORT_IACA_KEYS;
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
 * coverage of {@link StatusListSignerPolicy#RULES} — read by reflection off the rule constants — is recorded, not
 * declared ({@link #everyNamedRuleHasANegativeTest}, run last).
 *
 * <p>Two groups, as for the mDoc Document Signer: the rules that hold whatever is configured (including RFC 5280
 * section 6.1.4 for every certificate that issues another one in the path, a trust anchor the chain carries included),
 * and — only once an {@code mdoc-iaca}
 * anchor exists (D16's enforcement switch) — the trust anchor and its validity, revocation of the certificate the IACA
 * issued, CRL freshness, and the extended key usage of the mode. The mode is the one real difference between a
 * Document Signer and a dedicated signer: {@code 1.0.18013.5.1.2} versus {@code 1.3.6.1.5.5.7.3.45}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StatusListSignerPolicyTest {

    static final Set<String> REFUSED = ConcurrentHashMap.newKeySet();
    static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

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
        return registry(iacas, crls, TrustAnchorRegistry.DEFAULT_STALE_CRL_GRACE);
    }

    static TrustAnchorRegistry registry(List<X509Certificate> iacas, Map<String, X509CRL> crls, Duration grace) {
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

            @Override
            public Duration staleCrlGrace() {
                return grace;
            }
        };
    }

    static TrustAnchorRegistry trusting(X509Certificate... iacas) {
        return registry(List.of(iacas), Map.of());
    }

    static TrustAnchorRegistry withCrl(X509CRL crl) {
        return registry(List.of(IACA), Map.of("iaca-0", crl));
    }

    /** The multi-tier test root as the only anchor, with its CRL. */
    static TrustAnchorRegistry withRootCrl(X509CRL crl) {
        return registry(List.of(MULTI_TIER_ROOT), Map.of("iaca-0", crl));
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
        // the rollover intermediate is self-issued, so it does not count against the IACA's pathLenConstraint 0
        // (RFC 5280 section 6.1.4 (l)): the chain is refused for carrying it, not for its length
        refused(StatusListSignerPolicy.CARRIES_ANCHOR, () -> policy.check(
                context(ROLLOVER_DSC_KEYS, ROLLOVER_DSC, ROLLOVER, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    // ---- RFC 5280 6.1.4: whoever issues another certificate must be a CA ----------------------------------------

    @Test
    void anEndEntityCertificateCannotActAsAnIntermediate() {
        // [leaf, end entity, IACA]: every signature verifies, but no RFC 5280 verifier would build the path
        refused(StatusListSignerPolicy.ISSUER_NOT_CA, () -> StatusListSignerPolicy.notEnforced().check(
                context(BEHIND_END_ENTITY_INTERMEDIATE_KEYS, BEHIND_END_ENTITY_INTERMEDIATE, END_ENTITY_INTERMEDIATE, IACA),
                NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void pathLenConstraintIsRespected() {
        // an intermediate with pathLenConstraint 0 has a CA intermediate below it: refused whatever the anchor allows,
        // and whether or not the chain carries the anchor
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> StatusListSignerPolicy.notEnforced().check(
                context(SUB_INTERMEDIATE_DSC_KEYS, SUB_INTERMEDIATE_DSC, SUB_INTERMEDIATE, PATHLEN_ZERO),
                NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> StatusListSignerPolicy.notEnforced()
                .check(context(SUB_INTERMEDIATE_DSC_KEYS, SUB_INTERMEDIATE_DSC, SUB_INTERMEDIATE, PATHLEN_ZERO,
                        MULTI_TIER_ROOT), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertTrue(refused.getMessage().startsWith(StatusListSignerPolicy.PATH_LENGTH + ": the certificate "
                + PATHLEN_ZERO.getSubjectX500Principal()), refused.getMessage());
    }

    @Test
    void theAnchorsPathLenConstraintAppliesWhenTheChainCarriesIt() {
        // IACA (Annex B, pathLenConstraint 0) -> intermediate -> signer: the path Annex B forbids. RFC 5280 section
        // 6.1.1 would let a verifier ignore the anchor's constraint, but Multipaz and OpenSSL enforce it (RFC 5937),
        // so the token would be refused on arrival; with or without anchors configured, the chain says so itself
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> StatusListSignerPolicy.notEnforced().check(
                context(BEHIND_IACA_INTERMEDIATE_KEYS, BEHIND_IACA_INTERMEDIATE, IACA_INTERMEDIATE, IACA), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> enforcedBy(IACA).check(
                context(BEHIND_IACA_INTERMEDIATE_KEYS, BEHIND_IACA_INTERMEDIATE, IACA_INTERMEDIATE, IACA), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // the count, not just "any intermediate": a root allowing one is refused with two below it
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> StatusListSignerPolicy.notEnforced().check(
                context(BEHIND_DEEP_INTERMEDIATE_KEYS, BEHIND_DEEP_INTERMEDIATE, DEEP_INTERMEDIATE, INTERMEDIATE,
                        MULTI_TIER_ROOT), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void theAnchorsPathLenConstraintAppliesWhenOnlyTheRegistryHoldsIt() {
        // the chain stops below the anchor, so only the anchor the registry supplies can say the path is too long
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> enforcedBy(IACA).check(
                context(BEHIND_IACA_INTERMEDIATE_KEYS, BEHIND_IACA_INTERMEDIATE, IACA_INTERMEDIATE), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.PATH_LENGTH, () -> enforcedBy(MULTI_TIER_ROOT).check(
                context(BEHIND_DEEP_INTERMEDIATE_KEYS, BEHIND_DEEP_INTERMEDIATE, DEEP_INTERMEDIATE, INTERMEDIATE), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // and an "anchor" that is no CA at all issues nothing (cA and keyCertSign are the anchor's too)
        refused(StatusListSignerPolicy.ISSUER_NOT_CA, () -> new StatusListSignerPolicy(trusting(END_ENTITY_INTERMEDIATE))
                .check(context(BEHIND_END_ENTITY_INTERMEDIATE_KEYS, BEHIND_END_ENTITY_INTERMEDIATE), NOW,
                        StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        // without anchors there is no anchor to judge: the D16 switch, as for every other trust rule
        assertDoesNotThrow(() -> StatusListSignerPolicy.notEnforced().check(
                context(BEHIND_IACA_INTERMEDIATE_KEYS, BEHIND_IACA_INTERMEDIATE, IACA_INTERMEDIATE), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    // ---- with an anchor: the trust path ------------------------------------------------------------------------

    @Test
    void anAnnexBDocumentSignerPassesOnceTheIacaIsAnAnchor() {
        StatusListSignerPolicy policy = enforcedBy(IACA);
        assertDoesNotThrow(() -> policy.check(context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "[DSC, IACA] as an x509-file provider holds it: no intermediate, so pathLenConstraint 0 holds");
        assertDoesNotThrow(() -> policy.check(context(DSC_KEYS, DSC), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "a leaf-only chain is issued by the anchor directly");
    }

    @Test
    void anIntermediateIsAcceptedWhereTheAnchorAllowsOne() {
        // a root with pathLenConstraint 1, carried or supplied: one intermediate is exactly what it allows
        assertDoesNotThrow(() -> StatusListSignerPolicy.notEnforced().check(
                context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE, MULTI_TIER_ROOT), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        StatusListSignerPolicy policy = enforcedBy(MULTI_TIER_ROOT);
        assertDoesNotThrow(() -> policy.check(
                context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE, MULTI_TIER_ROOT), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER),
                "the chain's top certificate is the CA intermediate the root issued, and the emitted x5chain keeps it");
        assertDoesNotThrow(() -> policy.check(context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER), "and without the root in the chain");
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
    void theIacaMustBeValidAtTheSigningInstant() {
        // a leaf-only chain leaves the anchor's own window to this rule (the chain holds only the signer)
        refused(StatusListSignerPolicy.IACA_EXPIRED, () -> enforcedBy(EXPIRED_IACA).check(
                context(UNDER_EXPIRED_IACA_KEYS, UNDER_EXPIRED_IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        refused(StatusListSignerPolicy.IACA_NOT_YET_VALID, () -> enforcedBy(FUTURE_IACA).check(
                context(UNDER_FUTURE_IACA_KEYS, UNDER_FUTURE_IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void aRevokedSignerIsRefused() {
        X509CRL revoking = StatusListTestKeys.crl(NOW.minus(1, ChronoUnit.HOURS), NOW.plus(20, ChronoUnit.DAYS),
                DSC.getSerialNumber());
        refused(StatusListSignerPolicy.REVOKED, () -> new StatusListSignerPolicy(withCrl(revoking)).check(
                context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void aRevokedIntermediateIsRefused() {
        // the anchor's CRL lists the certificate the anchor issued, which is the intermediate here, not the leaf
        X509CRL revoking = StatusListTestKeys.rootCrl(NOW.minus(1, ChronoUnit.HOURS), NOW.plus(20, ChronoUnit.DAYS),
                INTERMEDIATE.getSerialNumber());
        refused(StatusListSignerPolicy.REVOKED, () -> new StatusListSignerPolicy(withRootCrl(revoking)).check(
                context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE, MULTI_TIER_ROOT), NOW,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
    }

    @Test
    void theIacasCrlIsReadForTheCertificateTheIacaIssued() {
        // an unrelated serial, and the leaf's own serial, are not revocations of the intermediate the anchor issued
        for (BigInteger serial : List.of(BigInteger.valueOf(424242), BEHIND_INTERMEDIATE.getSerialNumber())) {
            X509CRL crl = StatusListTestKeys.rootCrl(NOW.minus(1, ChronoUnit.HOURS), NOW.plus(20, ChronoUnit.DAYS), serial);
            assertDoesNotThrow(() -> new StatusListSignerPolicy(withRootCrl(crl)).check(
                    context(BEHIND_INTERMEDIATE_KEYS, BEHIND_INTERMEDIATE, INTERMEDIATE, MULTI_TIER_ROOT), NOW,
                    StatusListSignerPolicy.Mode.DOCUMENT_SIGNER), "serial " + serial);
        }
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
    void theStaleCrlWindowIsNextUpdatePlusTheGraceAndNothingElse() {
        // grace is a non-zero hour here: 30 minutes past nextUpdate is inside the window, one second past the window
        // is stale — no clock skew is added on top, exactly as MdocDscPolicy holds for an mDL
        Duration grace = Duration.ofHours(1);
        TrustAnchorRegistry inside = registry(List.of(IACA), Map.of("iaca-0",
                StatusListTestKeys.crl(NOW.minus(2, ChronoUnit.HOURS), NOW.minus(30, ChronoUnit.MINUTES))), grace);
        assertDoesNotThrow(() -> new StatusListSignerPolicy(inside).check(
                context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        TrustAnchorRegistry past = registry(List.of(IACA), Map.of("iaca-0",
                StatusListTestKeys.crl(NOW.minus(2, ChronoUnit.HOURS), NOW.minus(1, ChronoUnit.HOURS).minusSeconds(1))),
                grace);
        refused(StatusListSignerPolicy.CRL_STALE, () -> new StatusListSignerPolicy(past).check(
                context(DSC_KEYS, DSC, IACA), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
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

    // ---- how long a token may stay valid ----------------------------------------------------------------------

    @Test
    void validUntilIsTheEarliestNotAfterOfTheChainAndItsAnchor() {
        // the leaf, when it ends first
        assertEquals(DSC.getNotAfter().toInstant(),
                StatusListSignerPolicy.notEnforced().validUntil(context(DSC_KEYS, DSC, IACA)));
        // an intermediate that ends before the leaf
        assertEquals(SHORT_INTERMEDIATE.getNotAfter().toInstant(), StatusListSignerPolicy.notEnforced().validUntil(
                context(BEHIND_SHORT_INTERMEDIATE_KEYS, BEHIND_SHORT_INTERMEDIATE, SHORT_INTERMEDIATE, MULTI_TIER_ROOT)));
        // the IACA the registry supplies, when it ends before the leaf it issued; without anchors it is unknown
        assertTrue(SHORT_IACA.getNotAfter().before(UNDER_SHORT_IACA.getNotAfter()));
        assertEquals(SHORT_IACA.getNotAfter().toInstant(),
                enforcedBy(SHORT_IACA).validUntil(context(UNDER_SHORT_IACA_KEYS, UNDER_SHORT_IACA)));
        assertEquals(UNDER_SHORT_IACA.getNotAfter().toInstant(),
                StatusListSignerPolicy.notEnforced().validUntil(context(UNDER_SHORT_IACA_KEYS, UNDER_SHORT_IACA)));
        refused(StatusListSignerPolicy.NO_CHAIN, () -> StatusListSignerPolicy.notEnforced()
                .validUntil(context(DSC_KEYS, CertificateChain.EMPTY)));
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
        IllegalStateException envelope = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.encode(
                "https://issuer.example.test/1", NOW, NOW.plusSeconds(7200), Duration.ofHours(1), new byte[1], noChain,
                StatusListSignerPolicy.notEnforced(), NOW, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER));
        assertTrue(envelope.getMessage().startsWith(StatusListSignerPolicy.NO_CHAIN + ": "), envelope.getMessage());
        // the policy refuses a chain-less signer before the envelope is reached; the envelope's own three refusals map
        // to exactly this shape (anEnvelopeRefusalMapsLikeAPolicyRefusal holds that mapping)
        SigningException fromEnvelope = new SigningException(StatusListSignerPolicy.NO_CHAIN + ": no certificate");
        RuntimeException mapped = StatusListSignerPolicy.refusal(fromEnvelope);
        assertEquals(IllegalStateException.class, mapped.getClass());
        assertEquals(fromEnvelope.getMessage(), mapped.getMessage());
        assertSame(fromEnvelope, mapped.getCause());
    }

    // ---- coverage ---------------------------------------------------------------------------------------------

    @Test
    @Order(Integer.MAX_VALUE)
    void everyNamedRuleHasANegativeTest() {
        assertEquals(StatusListSignerPolicy.RULES, Set.copyOf(REFUSED),
                "each rule of section 4.7 has a test that breaks only it: " + StatusListSignerPolicy.RULES);
    }

    @Test
    void theRuleGuardSeesEveryConstant() {
        // the guard is only as good as the reflection behind RULES: a rule constant missing from it would pass unseen
        assertTrue(StatusListSignerPolicy.RULES.containsAll(Set.of(StatusListSignerPolicy.NO_CHAIN,
                StatusListSignerPolicy.SELF_SIGNED, StatusListSignerPolicy.EXPIRED, StatusListSignerPolicy.NOT_YET_VALID,
                StatusListSignerPolicy.CHAIN_LINK_INVALID, StatusListSignerPolicy.ISSUER_NOT_CA,
                StatusListSignerPolicy.PATH_LENGTH, StatusListSignerPolicy.CARRIES_ANCHOR, StatusListSignerPolicy.NO_TRUSTED_IACA,
                StatusListSignerPolicy.IACA_EXPIRED, StatusListSignerPolicy.IACA_NOT_YET_VALID,
                StatusListSignerPolicy.REVOKED, StatusListSignerPolicy.CRL_STALE, StatusListSignerPolicy.PURPOSE)));
        assertFalse(StatusListSignerPolicy.RULES.contains(StatusListSignerPolicy.PREFIX), "the prefix is not a rule");
        assertFalse(StatusListSignerPolicy.RULES.contains(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU),
                "an EKU OID is not a rule");
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
