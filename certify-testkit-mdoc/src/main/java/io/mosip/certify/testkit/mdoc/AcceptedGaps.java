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
 * The checks one sample is known not to pass yet, each with the reason and the work package that fixes it: the
 * {@code <sample>.gaps} sidecar. The producing test declares them next to the bytes it wrote, and
 * {@link #assertMatches} holds the verification report to exactly that list: a check outside it that does not pass
 * fails, and a listed check that passes fails too ("gap no longer present, remove it"), so the fix that closes a gap
 * has to delete its line in the same change.
 *
 * <p>Format, one gap per line, {@code #} comments and blank lines ignored:
 * <pre>
 * mso.validityInfo.tdateTags # G1: tdate carries milliseconds; fixed by M-02
 * x5chain.serialNumber? # G27: random serial sign; M-06
 * </pre>
 * A trailing {@code ?} marks an <em>intermittent</em> gap: the product draws the failing value at random (a
 * keymanager certificate serial is negative in about half the runs), so the check may pass or fail; it still has to
 * run, and the line still needs its reason. The reason is mandatory.
 */
public final class AcceptedGaps {

    /** One accepted gap. */
    public record Gap(String check, String reason, boolean intermittent) {

        public Gap {
            if (!IndependentMdocVerifier.CHECKS.contains(check)) {
                throw new IllegalArgumentException("unknown check " + check + "; the verifier runs " + IndependentMdocVerifier.CHECKS);
            }
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("the gap " + check + " needs a reason");
            }
        }

        String line() {
            return check + (intermittent ? "?" : "") + " # " + reason;
        }
    }

    private static final Pattern LINE = Pattern.compile("([A-Za-z0-9_.]+)(\\?)?\\s+#\\s*(\\S.*)");

    private final Map<String, Gap> gaps;

    private AcceptedGaps(Map<String, Gap> gaps) {
        this.gaps = Collections.unmodifiableMap(gaps);
    }

    public static AcceptedGaps none() {
        return new AcceptedGaps(new LinkedHashMap<>());
    }

    /** This list plus a gap the check always fails today. */
    public AcceptedGaps gap(String check, String reason) {
        return with(new Gap(check, reason, false));
    }

    /** This list plus a gap whose failure depends on a value the product draws at random. */
    public AcceptedGaps intermittent(String check, String reason) {
        return with(new Gap(check, reason, true));
    }

    private AcceptedGaps with(Gap gap) {
        Map<String, Gap> copy = new LinkedHashMap<>(gaps);
        if (copy.putIfAbsent(gap.check(), gap) != null) {
            throw new IllegalArgumentException("the gap " + gap.check() + " is declared twice");
        }
        return new AcceptedGaps(copy);
    }

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
            Matcher matcher = LINE.matcher(line);
            if (!matcher.matches()) {
                throw new IllegalArgumentException(source + " line " + (i + 1) + " is not \"<check>[?] # <reason>\": " + line);
            }
            try {
                parsed = parsed.with(new Gap(matcher.group(1), matcher.group(3).strip(), matcher.group(2) != null));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(source + " line " + (i + 1) + ": " + e.getMessage(), e);
            }
        }
        return parsed;
    }

    /** The sidecar text, with a header that says what the file is for. */
    public String format(String sample) {
        StringBuilder out = new StringBuilder()
                .append("# Accepted gaps of the mDoc sample ").append(sample).append(" (docs/design/20-mdl-issuer.md M-01).\n")
                .append("# One check per line, \"<check>[?] # <reason>\"; '?' marks an intermittent gap.\n")
                .append("# certify-conformance-mdoc fails when an unlisted check does not pass, and when a listed one passes.\n");
        gaps.values().forEach(gap -> out.append(gap.line()).append('\n'));
        return out.toString();
    }

    /**
     * Holds {@code report} to exactly these gaps: every check that did not pass must be listed, and every listed check
     * that is not intermittent must still not pass.
     *
     * @throws AssertionError naming every difference, plus the whole report
     */
    public void assertMatches(VerificationReport report, String sample) {
        List<String> problems = new ArrayList<>();
        for (VerificationReport.Check check : report.checks()) {
            Gap gap = gaps.get(check.name());
            if (check.passed()) {
                if (gap != null && !gap.intermittent()) {
                    problems.add("gap no longer present, remove it from " + sample + ".gaps: " + check.name()
                            + " passes now (declared: " + gap.reason() + ")");
                }
            } else if (gap == null) {
                problems.add("not an accepted gap of " + sample + ": " + check);
            }
        }
        for (String declared : gaps.keySet()) {
            if (report.checks().stream().noneMatch(check -> check.name().equals(declared))) {
                problems.add(sample + ".gaps lists " + declared + ", which the report does not contain");
            }
        }
        if (!problems.isEmpty()) {
            throw new AssertionError(sample + " does not match its declared gaps:" + System.lineSeparator() + "  "
                    + String.join(System.lineSeparator() + "  ", problems) + System.lineSeparator() + report);
        }
    }
}
