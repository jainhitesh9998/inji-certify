package io.mosip.certify.status;

import io.mosip.certify.signing.SigningException;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11d review round 2, major 2: a CWT list's update failure is permanent only when no retry or passage of time can
 * clear it. Every rule {@link StatusListSignerPolicy} names is classified on purpose, so a rule added later cannot fall
 * into the default without a decision.
 */
class TokenStatusListUpdateExceptionTest {

    @Test
    void refusalsThatOnlyAnOperatorCanClearArePermanent() {
        for (String rule : List.of(StatusListSignerPolicy.REVOKED, StatusListSignerPolicy.PURPOSE,
                StatusListSignerPolicy.NO_TRUSTED_IACA, StatusListSignerPolicy.SELF_SIGNED,
                StatusListSignerPolicy.CARRIES_ANCHOR, StatusListSignerPolicy.ISSUER_NOT_CA,
                StatusListSignerPolicy.PATH_LENGTH)) {
            TokenStatusListUpdateException classified = TokenStatusListUpdateException.signing("list",
                    new IllegalStateException(rule + ": refused"));
            assertTrue(classified.permanent(), rule);
            assertEquals(rule, classified.rule());
        }
    }

    @Test
    void refusalsThatClearByTimeOrRoutineOperationAreTransient() {
        for (String rule : List.of(StatusListSignerPolicy.CRL_STALE, StatusListSignerPolicy.NOT_YET_VALID,
                StatusListSignerPolicy.IACA_NOT_YET_VALID)) {
            TokenStatusListUpdateException classified = TokenStatusListUpdateException.signing("list",
                    new IllegalStateException(rule + ": not now"));
            assertFalse(classified.permanent(), rule);
            assertEquals(rule, classified.rule());
        }
    }

    /** {@code STATUS_SIGNER_EXPIRED} and {@code STATUS_SIGNER_IACA_EXPIRED} are different rules: the prefix is the rule plus ':'. */
    @Test
    void aRuleIsMatchedWholeNotByPrefix() {
        assertEquals(StatusListSignerPolicy.IACA_EXPIRED, TokenStatusListUpdateException.signing("list",
                new IllegalStateException(StatusListSignerPolicy.IACA_EXPIRED + ": the IACA expired")).rule());
        assertEquals(StatusListSignerPolicy.IACA_NOT_YET_VALID, TokenStatusListUpdateException.signing("list",
                new IllegalStateException(StatusListSignerPolicy.IACA_NOT_YET_VALID + ": later")).rule());
    }

    @Test
    void goneIsPermanentWhenTheReferenceNamesAnotherCertificateAndTransientWhenTheProviderFailed() {
        TokenStatusListUpdateException rotated = TokenStatusListUpdateException.signing("list",
                new IllegalStateException(StatusListSigners.GONE + ": the pinned signer now holds another certificate"));
        assertTrue(rotated.permanent(), "no retry makes the reference name the pinned certificate again");

        TokenStatusListUpdateException outage = TokenStatusListUpdateException.signing("list",
                new IllegalStateException(StatusListSigners.GONE + ": the pinned signer cannot be resolved (HSM down)",
                        new SigningException("HSM down")));
        assertFalse(outage.permanent(), "the provider failed: an outage, or a key an operator may restore");
        assertEquals(StatusListSigners.GONE, outage.rule());
    }

    @Test
    void aSigningFailureWithoutARuleIsTransient() {
        TokenStatusListUpdateException classified = TokenStatusListUpdateException.signing("list",
                new SigningException("HSM session lost"));
        assertFalse(classified.permanent());
        assertEquals(TokenStatusListUpdateException.SIGNING_FAILED, classified.rule());
        assertEquals("HSM session lost", classified.getMessage());
        assertEquals("list", classified.listId());
    }

    @Test
    void everyRuleThePolicyNamesIsClassifiedOnPurpose() {
        Set<String> classified = new HashSet<>(TokenStatusListUpdateException.PERMANENT_RULES);
        classified.addAll(TokenStatusListUpdateException.TRANSIENT_RULES);
        assertEquals(StatusListSignerPolicy.RULES, classified,
                "a new StatusListSignerPolicy rule needs a decision: permanent (quarantine) or transient (back-off)");
        Set<String> both = new HashSet<>(TokenStatusListUpdateException.PERMANENT_RULES);
        both.retainAll(TokenStatusListUpdateException.TRANSIENT_RULES);
        assertTrue(both.isEmpty(), both.toString());
    }
}
