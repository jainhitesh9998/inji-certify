/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

/**
 * Which rules {@link IndependentMdocVerifier#verify} enforces. {@link #baseline(String)} is what today's formatter
 * output can pass; {@link #strict(String)} is the merge gate the M-02, M-03 and M-06 work packages turn on.
 */
public record Options(String expectedDocType, boolean strictTdate, boolean requireNoSelfSignedInChain,
                      boolean checkMdlElementTypes) {

    public Options {
        if (expectedDocType == null || expectedDocType.isBlank()) {
            throw new IllegalArgumentException("expectedDocType is required (MSO docType check)");
        }
    }

    /**
     * The checks today's output passes: validityInfo parses but may carry fractional seconds (gap G1), the
     * x5chain may carry a self-signed certificate (gap G9) and mDL element types are not enforced (gap G2).
     */
    public static Options baseline(String expectedDocType) {
        return new Options(expectedDocType, false, false, false);
    }

    /** Every check the harness implements; the merge gate once M-02/M-03/M-06 have landed. */
    public static Options strict(String expectedDocType) {
        return new Options(expectedDocType, true, true, true);
    }
}
