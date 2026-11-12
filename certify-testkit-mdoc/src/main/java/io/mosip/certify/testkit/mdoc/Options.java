/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

/**
 * Which rules {@link IndependentMdocVerifier#verify} enforces.
 *
 * <p>{@link #baseline(String)} runs every check that today's formatter output can already satisfy and reports the
 * rest as {@link VerificationReport.State#SKIPPED} with the gap that blocks them (G1 tdate precision, G2 element
 * typing, G9 the trust anchor in {@code x5chain}, M-06 chain-to-IACA). {@link #strict(String)} runs all of them and
 * is the merge gate the M-02, M-03 and M-06 work packages switch the default output over to.
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

    /** What today's output passes; everything else is reported as skipped, never as passed. */
    public static Options baseline(String expectedDocType) {
        return new Options(expectedDocType, false);
    }

    /** Every check the harness implements, including the chain to the IACA: the merge gate after M-02/M-03/M-06. */
    public static Options strict(String expectedDocType) {
        return new Options(expectedDocType, true);
    }
}
