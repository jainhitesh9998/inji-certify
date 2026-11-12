/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import java.util.List;

/**
 * The outcome of {@link IndependentMdocVerifier#verify}: one named check per ISO/IEC 18013-5 rule the harness
 * verifies, each with a pass flag and a human-readable message. A failing check never throws out of
 * {@code verify}; call {@link #assertAllPassed()} to turn the report into an assertion.
 */
public final class VerificationReport {

    public record Check(String name, boolean passed, String message) {
        @Override
        public String toString() {
            return (passed ? "PASS " : "FAIL ") + name + ": " + message;
        }
    }

    private final List<Check> checks;

    public VerificationReport(List<Check> checks) {
        this.checks = List.copyOf(checks);
    }

    public List<Check> checks() {
        return checks;
    }

    public List<Check> failures() {
        return checks.stream().filter(c -> !c.passed()).toList();
    }

    public boolean passed() {
        return failures().isEmpty();
    }

    /** @throws AssertionError listing every failed check, so a CI log names the clause that broke. */
    public VerificationReport assertAllPassed() {
        if (!passed()) {
            StringBuilder message = new StringBuilder("independent mDoc verification failed:");
            for (Check failure : failures()) {
                message.append(System.lineSeparator()).append("  ").append(failure);
            }
            throw new AssertionError(message.toString());
        }
        return this;
    }

    public Check check(String name) {
        return checks.stream().filter(c -> c.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no check named " + name + " in " + checks));
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder(passed() ? "independent mDoc verification passed:" : "independent mDoc verification failed:");
        for (Check check : checks) {
            out.append(System.lineSeparator()).append("  ").append(check);
        }
        return out.toString();
    }
}
