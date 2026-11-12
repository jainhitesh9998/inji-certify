/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.conformance.mdoc;

import io.mosip.certify.testkit.mdoc.IndependentMdocVerifier;
import io.mosip.certify.testkit.mdoc.MdocSamples;
import io.mosip.certify.testkit.mdoc.Options;
import io.mosip.certify.testkit.mdoc.VerificationReport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The merge gate of M-01 (G24): every mDoc the product's own tests issue is re-verified here by the independent
 * verifier — Multipaz parses and checks the signature, the MSO, the namespaces and the digests, Authlete verifies the
 * same IssuerAuth, and the samples carry the holder key, the doctype and (when the chain has one) the IACA for the
 * trust decision. Nothing in this module knows how a credential is written, so a formatter change cannot make the
 * check agree with itself.
 *
 * <p>Every check runs ({@link Options#strict}) on the bytes as received; each sample is held to exactly the problem
 * codes its producer declared in the {@code .gaps} sidecar: a reported problem whose {@code <check>:<code>} is not
 * declared fails, and a declared code that is no longer reported fails too, so the fix that closes a gap removes its
 * line in the same change and one accepted problem cannot hide another one in the same check.
 *
 * <p>The samples are produced by tests in other modules and read from their {@code target/} directories (see
 * {@link #EXPECTED_SAMPLES}). This module is listed after {@code certify-service} in the parent POM, so a reactor
 * build runs the producing tests first. With {@code CI} set the run must find exactly the expected samples, all
 * written after this build started ({@code mdoc.samples.buildStart}, the reactor's {@code maven.build.timestamp});
 * locally a sample older than the build is reported and skipped, never verified as if it were current.
 */
class MdocSampleConformanceTest {

    static final Path ROOT = Path.of("..");
    static final List<Path> SAMPLE_DIRECTORIES = List.of(Path.of("certify-format-mdoc", "target", "mdoc-samples"),
            Path.of("certify-service", "target", "mdoc-samples"));

    /**
     * Every sample a full build must produce, as {@code <module>/<TestClass>-<surface>}. A new producer adds its line
     * here, so CI cannot lose a sample without failing. {@code VcIssuancePluginGoldenTest} is not here on purpose: its
     * mso_mdoc credential is a plugin's opaque bytes passed through unchanged, not an IssuerSigned Certify built.
     */
    static final List<String> EXPECTED_SAMPLES = List.of(
            "certify-format-mdoc/MdocIndependentVerificationTest-ed25519-fixture",
            "certify-format-mdoc/MdocIndependentVerificationTest-formatter",
            "certify-service/D13GoldenReplayTest-d13",
            "certify-service/IssuanceGoldenCoreTest-legacy",
            "certify-service/IssuanceGoldenCoreTest-oid4vci",
            "certify-service/IssuanceGoldenTest-legacy",
            "certify-service/IssuanceGoldenTest-oid4vci");

    static final boolean CI = System.getenv("CI") != null;

    /** One sample found on disk: its module-qualified name, its .mdoc and whether this build wrote it. */
    record Found(String id, Path mdoc, boolean fresh) {}

    @Test
    void ciProducedExactlyTheExpectedSamplesInThisBuild() {
        Assumptions.assumeTrue(CI, "local run: the expected-sample and freshness gate runs with CI set");
        Optional<Instant> buildStart = buildStart();
        assertTrue(buildStart.isPresent(), "mdoc.samples.buildStart is not set: run through Maven (surefire passes "
                + "maven.build.timestamp), or the freshness of the samples cannot be decided");
        List<Found> found = found(buildStart);
        assertEquals(new TreeSet<>(EXPECTED_SAMPLES), new TreeSet<>(found.stream().map(Found::id).toList()),
                "the build must produce exactly the expected mDoc samples: a missing one means a producing test did not "
                        + "run, an extra one must be added to EXPECTED_SAMPLES");
        List<String> stale = found.stream().filter(f -> !f.fresh()).map(Found::id).toList();
        assertEquals(List.of(), stale, "samples (or sidecars) older than this build (" + buildStart.get()
                + "): they were not written by the tests that just ran");
    }

    @TestFactory
    Stream<DynamicTest> everySampleVerifiesWithExactlyItsDeclaredGaps() {
        Optional<Instant> buildStart = buildStart();
        List<Found> found = found(buildStart);
        List<Found> current = found.stream().filter(Found::fresh).toList();
        found.stream().filter(f -> !f.fresh()).forEach(f -> System.out.println("[mdoc-conformance] stale sample, older "
                + "than this build and not verified: " + f.mdoc()));
        if (current.isEmpty()) {
            String message = "no current mDoc samples under " + SAMPLE_DIRECTORIES + ": the tests that issue "
                    + "credentials did not run in this build";
            if (CI) {
                fail(message);
            }
            // locally, `mvn -pl certify-conformance-mdoc test` alone has nothing to check; say so instead of passing
            Assumptions.assumeTrue(false, message);
        }
        return current.stream().map(sample -> DynamicTest.dynamicTest(sample.id(), () -> verify(sample)));
    }

    static void verify(Found found) {
        MdocSamples.Sample sample = MdocSamples.read(found.mdoc());
        // the bytes as the wallet received them: a draft-13 Document is the verifier's credential.shape problem, and
        // its docType is held to the MSO's by mso.docType, so neither is decided here
        VerificationReport report = new IndependentMdocVerifier().verify(sample.received(), sample.holder(),
                sample.iaca(), Instant.now(), Options.strict(sample.docType()));
        assertEquals(IndependentMdocVerifier.CHECKS, report.checks().stream().map(VerificationReport.Check::name).toList(),
                found.id() + ": the verifier did not run every check");
        assertFalse(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).message().isBlank());
        sample.gaps().assertMatches(report, found.id());
        System.out.println("[mdoc-conformance] " + found.id() + " accepted " + report.checks().stream()
                .flatMap(check -> check.codes().stream().map(code -> check.name() + ":" + code)).toList() + "; " + report);
    }

    static List<Found> found(Optional<Instant> buildStart) {
        List<Found> found = new ArrayList<>();
        for (Path directory : SAMPLE_DIRECTORIES) {
            Path absolute = ROOT.resolve(directory);
            if (!Files.isDirectory(absolute)) {
                continue;
            }
            try (Stream<Path> files = Files.list(absolute)) {
                for (Path mdoc : files.filter(p -> p.getFileName().toString().endsWith(MdocSamples.MDOC)).sorted().toList()) {
                    String name = mdoc.getFileName().toString();
                    String id = directory.getName(0) + "/" + name.substring(0, name.length() - MdocSamples.MDOC.length());
                    found.add(new Found(id, mdoc, buildStart.map(start -> writtenSince(mdoc, start)).orElse(true)));
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot list " + absolute, e);
            }
        }
        return found;
    }

    /** True when the sample and every sidecar next to it were written at or after {@code start}. */
    static boolean writtenSince(Path mdoc, Instant start) {
        for (Path file : MdocSamples.files(mdoc)) {
            try {
                if (Files.getLastModifiedTime(file).toInstant().isBefore(start)) {
                    return false;
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot read the modification time of " + file, e);
            }
        }
        return true;
    }

    /** The reactor build's start, which surefire passes from {@code maven.build.timestamp} (whole seconds, UTC). */
    static Optional<Instant> buildStart() {
        String value = System.getProperty("mdoc.samples.buildStart");
        if (value == null || value.isBlank() || value.contains("${")) {
            return Optional.empty();
        }
        return Optional.of(Instant.parse(value));
    }
}
