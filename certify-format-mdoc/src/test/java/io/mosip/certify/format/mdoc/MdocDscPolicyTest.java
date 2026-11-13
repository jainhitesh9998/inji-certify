package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.JwsHeaderPolicy.ChainInclusion;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.function.Executable;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static io.mosip.certify.format.mdoc.AnnexBFixtures.DSC;
import static io.mosip.certify.format.mdoc.AnnexBFixtures.IACA;
import static io.mosip.certify.format.mdoc.AnnexBFixtures.OTHER_DSC;
import static io.mosip.certify.format.mdoc.AnnexBFixtures.OTHER_IACA;
import static io.mosip.certify.format.mdoc.AnnexBFixtures.trusting;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link MdocDscPolicy}, rule by rule (docs/design/20-mdl-issuer.md M-06): each named rule has a test that breaks only
 * that rule and is refused with {@code certificate_chain_invalid} and the rule's name; the coverage of
 * {@link MdocDscPolicy#RULES} is recorded, not declared ({@link #everyNamedRuleHasANegativeTest}, run last).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MdocDscPolicyTest {

    static final Set<String> REFUSED = ConcurrentHashMap.newKeySet();
    static final Instant NOW = Instant.now();

    static void refused(String rule, Executable executable) {
        FormatException refused = assertThrows(FormatException.class, executable, rule);
        assertEquals("certificate_chain_invalid", refused.getErrorCode(), refused.getMessage());
        assertTrue(refused.getMessage().startsWith(rule + ": ") || refused.getMessage().contains(rule),
                "the refusal names " + rule + ": " + refused.getMessage());
        REFUSED.add(rule);
    }

    static MdocDscPolicy enforcedBy(X509Certificate... iacas) {
        MdocDscPolicy policy = new MdocDscPolicy(trusting(iacas));
        assertTrue(policy.enforced());
        return policy;
    }

    // ---- not enforced: the behaviour before M-06 -----------------------------------------------------------------

    @Test
    void withoutAnchorsOnlyTheRulesThatAlwaysHoldApply() {
        MdocDscPolicy policy = MdocDscPolicy.notEnforced();
        assertFalse(policy.enforced());
        assertFalse(new MdocDscPolicy(null).enforced());
        // a dev-CA certificate that is no Annex B DSC (keymanager's master-signed certificate is the same case) still signs
        assertDoesNotThrow(() -> policy.check(MdlFixtures.dsc().chain(), MdlFixtures.NOW));
        assertDoesNotThrow(() -> policy.check(CertificateChain.of(MdlFixtures.dsc().chain().leaf().orElseThrow()), MdlFixtures.NOW));
    }

    // ---- enforced: the anchor, its validity, the profiles, revocation ---------------------------------------------

    @Test
    void anAnnexBDscIssuedByAConfiguredIacaPasses() {
        MdocDscPolicy policy = enforcedBy(OTHER_IACA, IACA);
        assertDoesNotThrow(() -> policy.check(CertificateChain.of(DSC, IACA), NOW), "[DSC, IACA] as x509-file holds it");
        assertDoesNotThrow(() -> policy.check(CertificateChain.of(DSC), NOW), "a leaf-only DSC finds its IACA in the registry");
    }

    @Test
    void aDscNoConfiguredIacaIssuedIsRefused() {
        MdocDscPolicy policy = enforcedBy(IACA);
        refused(MdocDscPolicy.DSC_NO_TRUSTED_IACA, () -> policy.check(CertificateChain.of(OTHER_DSC, OTHER_IACA), NOW));
        // the master-signed or dev-CA certificate a keymanager or plain dev key carries (D16: refused once IACAs are configured)
        refused(MdocDscPolicy.DSC_NO_TRUSTED_IACA, () -> policy.check(MdlFixtures.dsc().chain(), MdlFixtures.NOW));
    }

    /** Review round 1: signed by a configured IACA but with an AKI that names another key is the Annex B rule, not "no IACA". */
    @Test
    void aDscAConfiguredIacaSignedWithAForeignAuthorityKeyIdentifierNamesTheAnnexBRule() {
        X509Certificate foreign = AnnexBFixtures.dscWithForeignAki();
        FormatException refused = assertThrows(FormatException.class, () -> enforcedBy(OTHER_IACA, IACA).check(CertificateChain.of(foreign), NOW));
        assertEquals("certificate_chain_invalid", refused.getErrorCode());
        assertTrue(refused.getMessage().startsWith("DS_AKI_MISMATCH: "), refused.getMessage());
        assertFalse(refused.getMessage().contains(MdocDscPolicy.DSC_NO_TRUSTED_IACA), refused.getMessage());
    }

    @Test
    void theSigningInstantMustLieInsideTheDscValidity() {
        MdocDscPolicy policy = enforcedBy(IACA);
        CertificateChain chain = CertificateChain.of(DSC, IACA);
        refused(MdocDscPolicy.DSC_NOT_YET_VALID, () -> policy.check(chain, DSC.getNotBefore().toInstant().minusSeconds(1)));
        refused(MdocDscPolicy.DSC_EXPIRED, () -> policy.check(chain, DSC.getNotAfter().toInstant().plusSeconds(1)));
        // the same rules hold without anchors: an expired DSC never signed
        refused(MdocDscPolicy.DSC_EXPIRED, () -> MdocDscPolicy.notEnforced().check(chain, DSC.getNotAfter().toInstant().plusSeconds(1)));
    }

    @Test
    void everyLinkOfTheChainMustVerify() {
        refused(MdocDscPolicy.CHAIN_LINK_INVALID, () -> MdocDscPolicy.notEnforced().check(CertificateChain.of(DSC, OTHER_IACA), NOW));
    }

    @Test
    void theIacaMustBeValidAtTheSigningInstant() {
        // a conforming DSC never outlives its IACA, so the IACA's own window is tested with a certificate the builders refuse
        MdocDscPolicy policy = enforcedBy(IACA);
        KeyPair keys = AnnexBFixtures.p256();
        Instant iacaEnd = IACA.getNotAfter().toInstant();
        X509Certificate outlives = AnnexBFixtures.bareCertificate(keys, "C=IN,CN=Outlives Its IACA", NOW, iacaEnd.plus(2, ChronoUnit.DAYS));
        refused(MdocDscPolicy.IACA_EXPIRED, () -> policy.check(CertificateChain.of(outlives), iacaEnd.plus(1, ChronoUnit.DAYS)));
        Instant iacaStart = IACA.getNotBefore().toInstant();
        X509Certificate early = AnnexBFixtures.bareCertificate(keys, "C=IN,CN=Before Its IACA", iacaStart.minus(2, ChronoUnit.DAYS), NOW.plus(1, ChronoUnit.DAYS));
        refused(MdocDscPolicy.IACA_NOT_YET_VALID, () -> policy.check(CertificateChain.of(early), iacaStart.minus(1, ChronoUnit.DAYS)));
    }

    @Test
    void theDscMustMeetTheAnnexBProfileOfItsIaca() {
        // signed by the configured IACA, valid now, but without AKI, key usage, EKU, issuerAltName or CRL DP
        X509Certificate bare = AnnexBFixtures.bareCertificate(AnnexBFixtures.p256(), "C=IN,CN=Not A Document Signer",
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(30, ChronoUnit.DAYS));
        FormatException refused = assertThrows(FormatException.class, () -> enforcedBy(IACA).check(CertificateChain.of(bare), NOW));
        assertEquals("certificate_chain_invalid", refused.getErrorCode());
        for (String rule : List.of("DS_EKU_MISSING", "DS_AKI_MISSING", "DS_KEY_USAGE_MISSING")) {
            assertTrue(refused.getMessage().contains(rule), rule + " is named: " + refused.getMessage());
        }
        assertTrue(refused.getMessage().startsWith("DS_"), "the message starts with the AnnexBValidator rules: " + refused.getMessage());
    }

    @Test
    void theIacaMustMeetTheAnnexBIacaProfile() {
        // the formatter fixtures' dev CA is a CA, not an IACA: trusting it does not make its leaves Document Signers
        X509Certificate devCa = MdlFixtures.dscWithIaca().chain().root().orElseThrow();
        FormatException refused = assertThrows(FormatException.class,
                () -> enforcedBy(devCa).check(MdlFixtures.dscWithIaca().chain(), MdlFixtures.NOW));
        assertTrue(refused.getMessage().contains("IACA_CRL_DP_MISSING") && refused.getMessage().contains("DS_EKU_MISSING"),
                refused.getMessage());
    }

    @Test
    void aDscTheIacaRevokedIsRefused() {
        TrustAnchorRegistry revoking = AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", AnnexBFixtures.crlRevoking(DSC.getSerialNumber())));
        refused(MdocDscPolicy.DSC_REVOKED, () -> new MdocDscPolicy(revoking).check(CertificateChain.of(DSC), NOW));
        TrustAnchorRegistry other = AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", AnnexBFixtures.crlRevoking(BigInteger.valueOf(1L << 62))));
        assertDoesNotThrow(() -> new MdocDscPolicy(other).check(CertificateChain.of(DSC), NOW), "another serial's revocation");
        TrustAnchorRegistry empty = AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", AnnexBFixtures.crlRevoking()));
        assertDoesNotThrow(() -> new MdocDscPolicy(empty).check(CertificateChain.of(DSC), NOW), "an empty CRL");
    }

    /**
     * Review round 1, item 2 (decision log 2026-11-13, refining D16): an IACA CRL more than the grace past its
     * nextUpdate refuses signing; within it signing continues; a revocation it lists is named first.
     */
    @Test
    void aCrlPastItsNextUpdateByMoreThanTheGraceRefusesSigning() {
        java.security.cert.X509CRL crl = AnnexBFixtures.crlRevoking();
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        Instant graceEnd = nextUpdate.plus(TrustAnchorRegistry.DEFAULT_STALE_CRL_GRACE);
        MdocDscPolicy policy = new MdocDscPolicy(AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", crl)));
        assertDoesNotThrow(() -> policy.check(CertificateChain.of(DSC), graceEnd), "within the grace signing continues");
        refused(MdocDscPolicy.CRL_STALE, () -> policy.check(CertificateChain.of(DSC), graceEnd.plusSeconds(1)));

        TrustAnchorRegistry anchors = AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", crl));
        TrustAnchorRegistry strict = new TrustAnchorRegistry() {
            @Override
            public List<Anchor> entries(String purpose) {
                return anchors.entries(purpose);
            }

            @Override
            public java.util.Optional<java.security.cert.X509CRL> crl(String anchorId) {
                return anchors.crl(anchorId);
            }

            @Override
            public Duration staleCrlGrace() {
                return Duration.ZERO;
            }
        };
        assertDoesNotThrow(() -> new MdocDscPolicy(strict).check(CertificateChain.of(DSC), nextUpdate));
        refused(MdocDscPolicy.CRL_STALE, () -> new MdocDscPolicy(strict).check(CertificateChain.of(DSC), nextUpdate.plusSeconds(1)));

        TrustAnchorRegistry revoking = AnnexBFixtures.registry(List.of(IACA), Map.of("iaca-0", AnnexBFixtures.crlRevoking(DSC.getSerialNumber())));
        Instant stale = revoking.crl("iaca-0").orElseThrow().getNextUpdate().toInstant().plus(Duration.ofDays(2));
        refused(MdocDscPolicy.DSC_REVOKED, () -> new MdocDscPolicy(revoking).check(CertificateChain.of(DSC), stale));
    }

    // ---- x5chain rules, whatever is configured --------------------------------------------------------------------

    @Test
    void theX5chainRulesHoldWithAndWithoutAnchors() {
        refused(MdocDscPolicy.X5CHAIN_MISSING, () -> MdocDscPolicy.requireX5chain(ChainInclusion.WITHOUT_ANCHOR, CertificateChain.EMPTY));
        refused(MdocDscPolicy.DSC_SELF_SIGNED, () -> MdocDscPolicy.requireX5chain(ChainInclusion.WITHOUT_ANCHOR,
                MdlFixtures.selfSignedSigner().chain()));
        refused(MdocDscPolicy.X5CHAIN_NONE, () -> MdocDscPolicy.requireX5chain(ChainInclusion.NONE, CertificateChain.of(DSC, IACA)));
        refused(MdocDscPolicy.X5CHAIN_DROPS_INTERMEDIATES, () -> MdocDscPolicy.requireX5chain(ChainInclusion.LEAF,
                CertificateChain.of(DSC, OTHER_DSC)));
        refused(MdocDscPolicy.X5CHAIN_CARRIES_ANCHOR, () -> MdocDscPolicy.requireX5chain(ChainInclusion.FULL, CertificateChain.of(DSC, IACA)));
        assertDoesNotThrow(() -> MdocDscPolicy.requireX5chain(ChainInclusion.WITHOUT_ANCHOR, CertificateChain.of(DSC, IACA)));
        assertDoesNotThrow(() -> MdocDscPolicy.requireX5chain(ChainInclusion.LEAF, CertificateChain.of(DSC, IACA)));
    }

    // ---- through the formatter: sign() and the v2 dry run ---------------------------------------------------------

    @Test
    void signRefusesADscNoConfiguredIacaIssuedOnEverySurface() {
        MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)), enforcedBy(IACA));
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(MdlFixtures.mdl()), MdlFixtures.configuration(formatter),
                MdlFixtures.context(), MdlFixtures.holder());
        refused(MdocDscPolicy.DSC_NO_TRUSTED_IACA, () -> formatter.sign(unsigned, MdlFixtures.signing(MdlFixtures.dsc()), MdlFixtures.context()));
        assertDoesNotThrow(() -> formatter.sign(unsigned, MdlFixtures.signing(AnnexBFixtures.dsc()), MdlFixtures.context()));
    }

    @Test
    void theDryRunChecksTheKeyOnlyWhenThePolicyIsEnforced() {
        AtomicBoolean resolved = new AtomicBoolean();
        Supplier<SigningContext> lookup = () -> {
            resolved.set(true);
            return MdlFixtures.signing(MdlFixtures.dsc());
        };
        MdocFormatter open = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)));
        open.checkSigningKey(lookup, MdlFixtures.configuration(open), MdlFixtures.context());
        assertFalse(resolved.get(), "without anchors the preview resolves no key, as before M-06");

        MdocFormatter enforced = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)), enforcedBy(IACA));
        refused(MdocDscPolicy.DSC_NO_TRUSTED_IACA, () -> enforced.checkSigningKey(lookup, MdlFixtures.configuration(enforced), MdlFixtures.context()));
        assertTrue(resolved.get());
        assertDoesNotThrow(() -> enforced.checkSigningKey(() -> MdlFixtures.signing(AnnexBFixtures.dsc()),
                MdlFixtures.configuration(enforced), MdlFixtures.context()));
        refused(MdocDscPolicy.KEY_UNRESOLVED, () -> enforced.checkSigningKey(() -> {
            throw new IllegalStateException("No key with alias 'mdl-dsc'");
        }, MdlFixtures.configuration(enforced), MdlFixtures.context()));
    }

    /** Round 2, item 1: a caller that knows anchors are configured but cannot obtain the policy refuses (fail closed). */
    @Test
    void anUnavailablePolicyOverConfiguredAnchorsRefuses() {
        refused(MdocDscPolicy.TRUST_ANCHORS_UNAVAILABLE, () -> {
            throw MdocDscPolicy.unavailable("2 TrustAnchorRegistry beans hold mdoc-iaca anchors and none is primary");
        });
    }

    @Test
    @Order(Integer.MAX_VALUE)
    void everyNamedRuleHasANegativeTest() {
        assertEquals(new TreeSet<>(MdocDscPolicy.RULES), new TreeSet<>(REFUSED),
                "every rule MdocDscPolicy names must be refused by a test in this class");
    }
}
