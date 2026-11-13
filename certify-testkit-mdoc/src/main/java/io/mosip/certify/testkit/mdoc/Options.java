/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

/**
 * Which rules {@link IndependentMdocVerifier#verify} enforces.
 *
 * <p>{@link #strict(String)} runs every check; the conformance run uses it and holds each sample to exactly the gaps
 * its producer declared ({@link AcceptedGaps}). {@link #baseline(String)} reports the checks an open gap blocks as
 * {@link VerificationReport.State#SKIPPED} instead (G1 untagged or fractional tdate, G2 element typing, G9 the trust
 * anchor in {@code x5chain}, chain-to-IACA without an IACA), for tests that exercise one specific check.
 *
 * <p>There is no per-check switch on purpose: a suite that turns one rule off must turn them all off and say so,
 * because the interesting failure is a check that stopped running.
 */
public record Options(String expectedDocType, boolean strict) {

    public Options {
        if (expectedDocType == null || expectedDocType.isBlank()) {
            throw new IllegalArgumentException("expectedDocType is required (MSO docType check)");
        }
    }

    /** The checks an open gap blocks are reported as skipped, never as passed. */
    public static Options baseline(String expectedDocType) {
        return new Options(expectedDocType, false);
    }

    /** Every check the harness implements, including the chain to the IACA; failures are named, never skipped. */
    public static Options strict(String expectedDocType) {
        return new Options(expectedDocType, true);
    }
}
