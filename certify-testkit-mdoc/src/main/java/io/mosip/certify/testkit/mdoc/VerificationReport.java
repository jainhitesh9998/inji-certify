/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import java.util.List;
import java.util.Set;

/**
 * The outcome of {@link IndependentMdocVerifier#verify}: one named check per ISO/IEC 18013-5 rule the harness
 * verifies, each with a state, a human-readable message and, when it failed, <b>every</b> problem it found, each under
 * a stable problem code ({@code expired}, {@code untyped:birth_date}). A failing check never throws out of
 * {@code verify}; call {@link #assertAllPassed()} to turn the report into an assertion, or hold it to a sample's
 * declared gaps with {@link AcceptedGaps#assertMatches}, which compares codes, not check names.
 *
 * <p>A check that was not run is {@link State#SKIPPED}, and a skipped check is <b>not</b> a pass: a suite that
 * silently stops checking something must go red, so {@link #passed()} and {@link #assertAllPassed()} only accept
 * {@link State#PASS}. A caller that knows exactly which checks cannot run yet (the baseline options) says so explicitly
 * through {@link #assertAllPassed(Set)} and therefore also states, in the test, which checks were not performed.
 */
public final class VerificationReport {

    public enum State { PASS, FAIL, SKIPPED }

    /**
     * One thing a check found wrong. {@code code} is stable and is what a {@code .gaps} line names
     * ({@code <check>:<code>}); {@code message} says what exactly is wrong in this credential.
     */
    public record Problem(String code, String message) {

        @Override
        public String toString() {
            return "[" + code + "] " + message;
        }
    }

    /** A check's result. {@code problems} is empty unless the state is {@link State#FAIL}, and never empty then. */
    public record Check(String name, State state, String message, List<Problem> problems) {

        public Check {
            problems = List.copyOf(problems);
            if ((state == State.FAIL) == problems.isEmpty()) {
                throw new IllegalArgumentException(name + ": a failed check carries its problems, any other carries none");
            }
        }

        public static Check pass(String name, String message) {
            return new Check(name, State.PASS, message, List.of());
        }

        public static Check fail(String name, List<Problem> problems) {
            return new Check(name, State.FAIL, problems.stream().map(Problem::toString)
                    .collect(java.util.stream.Collectors.joining("; ")), problems);
        }

        public static Check fail(String name, String code, String message) {
            return fail(name, List.of(new Problem(code, message)));
        }

        public static Check skipped(String name, String message) {
            return new Check(name, State.SKIPPED, message, List.of());
        }

        public boolean passed() {
            return state == State.PASS;
        }

        public boolean skipped() {
            return state == State.SKIPPED;
        }

        /** The problem codes of this check, in the order they were found. */
        public List<String> codes() {
            return problems.stream().map(Problem::code).toList();
        }

        @Override
        public String toString() {
            return state + " " + name + ": " + message;
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
        return checks.stream().filter(c -> c.state() == State.FAIL).toList();
    }

    public List<Check> skipped() {
        return checks.stream().filter(Check::skipped).toList();
    }

    /** True only when every check ran and passed; a skipped check is not a pass. */
    public boolean passed() {
        return checks.stream().allMatch(Check::passed);
    }

    public VerificationReport assertAllPassed() {
        return assertAllPassed(Set.of());
    }

    /**
     * @param allowedSkipped check names the caller explicitly accepts as not run; every other skipped check, and
     *                       every failed check, fails the assertion. Naming them keeps the acceptance visible in
     *                       the test instead of hidden in the harness.
     * @throws AssertionError listing every failed or unexpectedly skipped check, so a CI log names the clause
     */
    public VerificationReport assertAllPassed(Set<String> allowedSkipped) {
        StringBuilder message = new StringBuilder();
        for (Check check : checks) {
            if (check.state() == State.FAIL) {
                message.append(System.lineSeparator()).append("  failed ").append(check);
            } else if (check.skipped() && !allowedSkipped.contains(check.name())) {
                message.append(System.lineSeparator()).append("  skipped but not accepted ").append(check);
            }
        }
        if (!message.isEmpty()) {
            throw new AssertionError("independent mDoc verification failed:" + message);
        }
        return this;
    }

    public Check check(String name) {
        return checks.stream().filter(c -> c.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no check named " + name + " in " + checks));
    }

    /**
     * The names of the skipped checks, so a test can assert exactly what was not verified. An allowed-skip set is
     * meant to be compared with this, not guessed.
     */
    public Set<String> skippedNames() {
        return skipped().stream().map(Check::name).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder(passed() ? "independent mDoc verification passed:" : "independent mDoc verification did not pass:");
        for (Check check : checks) {
            out.append(System.lineSeparator()).append("  ").append(check);
        }
        return out.toString();
    }
}
