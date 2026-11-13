/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The problems one sample is known to have, each with the reason and the work package that fixes it: the
 * {@code <sample>.gaps} sidecar. A gap names one <b>problem code</b> of one check ({@code mso.validityInfo:signedAfterValidFrom}),
 * never a whole check, so accepting one defect cannot hide another one the same check finds. The producing test
 * declares the gaps next to the bytes it wrote, and {@link #assertMatches} holds the verification report to exactly
 * that list: a reported problem whose code is not declared fails, and a declared code the check no longer reports fails
 * too ("gap no longer present, remove it"), so the fix that closes a gap has to delete its line in the same change.
 *
 * <p>One sidecar serves one <b>combined</b> report per sample: the credential's own checks
 * ({@link IndependentMdocVerifier#PROBLEM_CODES}) and, when its MSO carries
 * {@code status.status_list}, the status list's checks ({@link IndependentStatusListVerifier#PROBLEM_CODES},
 * {@code statusList.*} and {@code statusList.mso}). The two registries name disjoint checks, so a line has exactly one
 * owner, and the exact both ways rule holds across both reports at once (M-11b review round 1).
 *
 * <p>Format, one gap per line, {@code #} comments and blank lines ignored, the reason mandatory:
 * <pre>
 * mso.validityInfo.tdateTags:fractionalSeconds:signed # G1: tdate carries milliseconds; fixed by M-02
 * mdl.elementTypes:missing:given_name # G3: no mandatory-element check; M-03
 * </pre>
 * Check names and codes are those of {@link IndependentMdocVerifier#PROBLEM_CODES} or
 * {@link IndependentStatusListVerifier#PROBLEM_CODES}; anything else is refused, and so is a bare check name. There is no optional marker: a gap is declared exactly when the sample has it, so a producer
 * whose output varies from run to run (a keymanager serial is negative in about half the runs, G27) decides from the
 * bytes it wrote.
 */
public final class AcceptedGaps {

    /** One accepted problem: a check, one of its problem codes, and why it cannot pass yet. */
    public record Gap(String check, String code, String reason) {

        public Gap {
            Map<String, List<String>> registry = registryOf(check);
            if (registry == null) {
                throw new IllegalArgumentException("unknown check " + check + "; the verifiers run "
                        + IndependentMdocVerifier.CHECKS + " and " + IndependentStatusListVerifier.CHECKS);
            }
            if (!knownProblemCode(check, code)) {
                throw new IllegalArgumentException("unknown problem code " + check + ":" + code + "; " + check
                        + " reports " + registry.get(check));
            }
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("the gap " + check + ":" + code + " needs a reason");
            }
        }

        public String key() {
            return check + ":" + code;
        }

        String line() {
            return key() + " # " + reason;
        }
    }

    private static final Pattern LINE = Pattern.compile("([A-Za-z0-9_.]+):(\\S+)\\s+#\\s*(\\S.*)");
    private static final Pattern BARE = Pattern.compile("[A-Za-z0-9_.]+\\??(\\s+#.*)?");

    private final Map<String, Gap> gaps;

    private AcceptedGaps(Map<String, Gap> gaps) {
        this.gaps = Collections.unmodifiableMap(gaps);
    }

    public static AcceptedGaps none() {
        return new AcceptedGaps(new LinkedHashMap<>());
    }

    /** This list plus the problem {@code check:code}. */
    public AcceptedGaps gap(String check, String code, String reason) {
        return with(new Gap(check, code, reason));
    }

    /** This list plus every gap of {@code other}. */
    public AcceptedGaps plus(AcceptedGaps other) {
        AcceptedGaps result = this;
        for (Gap gap : other.gaps.values()) {
            result = result.with(gap);
        }
        return result;
    }

    /** This list without the gaps of {@code check}, for a mutation that repairs what they accept. */
    public AcceptedGaps without(String check) {
        Map<String, Gap> copy = new LinkedHashMap<>(gaps);
        copy.values().removeIf(gap -> gap.check().equals(check));
        return new AcceptedGaps(copy);
    }

    private AcceptedGaps with(Gap gap) {
        Map<String, Gap> copy = new LinkedHashMap<>(gaps);
        if (copy.putIfAbsent(gap.key(), gap) != null) {
            throw new IllegalArgumentException("the gap " + gap.key() + " is declared twice");
        }
        return new AcceptedGaps(copy);
    }

    /** The registry that owns {@code check}, or null when neither verifier reports it. */
    private static Map<String, List<String>> registryOf(String check) {
        if (IndependentMdocVerifier.PROBLEM_CODES.containsKey(check)) {
            return IndependentMdocVerifier.PROBLEM_CODES;
        }
        return IndependentStatusListVerifier.PROBLEM_CODES.get(check) == null ? null
                : IndependentStatusListVerifier.PROBLEM_CODES;
    }

    private static boolean knownProblemCode(String check, String code) {
        return IndependentMdocVerifier.isProblemCode(check, code) || IndependentStatusListVerifier.isProblemCode(check, code);
    }

    /** The gaps by {@code check:code}. */
    public Map<String, Gap> gaps() {
        return gaps;
    }

    /** Parses a {@code .gaps} sidecar; {@code source} names it in the error. */
    public static AcceptedGaps parse(String text, String source) {
        AcceptedGaps parsed = none();
        String[] lines = text.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String where = source + " line " + (i + 1);
            if (BARE.matcher(line).matches()) {
                throw new IllegalArgumentException(where + " names a whole check (" + line + "): a gap names one problem "
                        + "code, \"<check>:<code> # <reason>\", and the optional marker '?' is gone");
            }
            Matcher matcher = LINE.matcher(line);
            if (!matcher.matches()) {
                throw new IllegalArgumentException(where + " is not \"<check>:<code> # <reason>\": " + line);
            }
            try {
                parsed = parsed.with(new Gap(matcher.group(1), matcher.group(2), matcher.group(3).strip()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(where + ": " + e.getMessage(), e);
            }
        }
        return parsed;
    }

    /** The sidecar text, with a header that says what the file is for. */
    public String format(String sample) {
        StringBuilder out = new StringBuilder()
                .append("# Accepted gaps of the mDoc sample ").append(sample).append(" (docs/design/20-mdl-issuer.md M-01).\n")
                .append("# One problem per line, \"<check>:<code> # <reason>\" (IndependentMdocVerifier and\n")
                .append("# IndependentStatusListVerifier PROBLEM_CODES: the credential and its status list share this file).\n")
                .append("# certify-conformance-mdoc fails on a reported problem not listed here and on a listed one no longer reported.\n");
        gaps.values().forEach(gap -> out.append(gap.line()).append('\n'));
        return out.toString();
    }

    /**
     * Holds {@code report} to exactly these gaps: every problem a failed check reports must be a declared code of that
     * check, every declared code must still be reported, and no check may be skipped (a gap covers a problem that was
     * found, never a check that did not run).
     *
     * @throws AssertionError naming every difference as {@code check:code}, plus the whole report
     */
    public void assertMatches(VerificationReport report, String sample) {
        List<String> problems = new ArrayList<>();
        for (VerificationReport.Check check : report.checks()) {
            List<Gap> declared = gaps.values().stream().filter(gap -> gap.check().equals(check.name())).toList();
            if (check.skipped()) {
                problems.add("not verified: " + check + " was skipped, and a gap cannot cover a check that did not run");
                continue;
            }
            for (VerificationReport.Problem problem : check.problems()) {
                if (!gaps.containsKey(check.name() + ":" + problem.code())) {
                    problems.add("not an accepted gap of " + sample + ": " + check.name() + ":" + problem.code()
                            + " " + problem.message());
                }
            }
            for (Gap gap : declared) {
                if (!check.codes().contains(gap.code())) {
                    problems.add("gap no longer present, remove " + gap.key() + " from " + sample + ".gaps: "
                            + (check.passed() ? check.name() + " passes now" : check.name() + " reports " + check.codes())
                            + " (declared: " + gap.reason() + ")");
                }
            }
        }
        for (Gap gap : gaps.values()) {
            if (report.checks().stream().noneMatch(check -> check.name().equals(gap.check()))) {
                problems.add(sample + ".gaps lists " + gap.key() + ", but the report has no check " + gap.check());
            }
        }
        if (!problems.isEmpty()) {
            throw new AssertionError(sample + " does not match its declared gaps:" + System.lineSeparator() + "  "
                    + String.join(System.lineSeparator() + "  ", problems) + System.lineSeparator() + report);
        }
    }
}
