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
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
 * <p>The samples are produced by tests in other modules and read from their {@code target/} directories:
 * <ul>
 *     <li>{@code certify-service/target/mdoc-samples/} — both mDoc issuance paths through the running service
 *     ({@code IssuanceGoldenTest}), i.e. what a wallet actually receives;</li>
 *     <li>{@code certify-format-mdoc/target/mdoc-samples/} — the formatter's own output.</li>
 * </ul>
 *
 * <p>This module is listed after {@code certify-service} in the parent POM, so a reactor build runs the producing
 * tests first. {@code mvn -pl certify-conformance-mdoc} on its own does <b>not</b>: run the service tests first, or
 * set {@code CI} so an empty sample directory fails instead of passing quietly.
 */
class MdocSampleConformanceTest {

    static final Path SERVICE_SAMPLES = Path.of("..", "certify-service", "target", "mdoc-samples");
    static final Path FORMAT_SAMPLES = Path.of("..", "certify-format-mdoc", "target", "mdoc-samples");

    /** The checks today's output cannot pass yet; the same set the producing tests accept, by name. */
    static final Set<String> BASELINE_GAPS = Set.of(IndependentMdocVerifier.CHECK_TDATE_TAGS,
            IndependentMdocVerifier.CHECK_NO_SELF_SIGNED, IndependentMdocVerifier.CHECK_ELEMENT_TYPES);

    @Test
    void everyRecordedSampleVerifiesWithAnIndependentImplementation() throws IOException {
        List<Path> samples = new ArrayList<>();
        samples.addAll(mdocSamples(SERVICE_SAMPLES));
        samples.addAll(mdocSamples(FORMAT_SAMPLES));
        if (samples.isEmpty()) {
            String message = "no mDoc samples under " + SERVICE_SAMPLES + " or " + FORMAT_SAMPLES
                    + ": the tests that issue credentials did not run in this build";
            if (System.getenv("CI") != null) {
                fail(message);
            }
            // locally, `mvn -pl certify-conformance-mdoc test` alone has nothing to check; say so instead of passing
            org.junit.jupiter.api.Assumptions.assumeTrue(false, message);
        }

        Set<Path> names = new LinkedHashSet<>();
        for (Path sample : samples) {
            assertTrue(names.add(sample.getFileName()), "two modules wrote the same sample name " + sample.getFileName());
            MdocSamples.Sample parsed = MdocSamples.read(sample);
            IndependentMdocVerifier verifier = new IndependentMdocVerifier();
            VerificationReport report = verifier.verify(Files.readAllBytes(sample), parsed.holder(), parsed.iaca(),
                    java.time.Instant.now(), Options.baseline(parsed.docType()));

            Set<String> allowed = new LinkedHashSet<>(BASELINE_GAPS);
            if (parsed.iaca().isEmpty()) {
                allowed.add(IndependentMdocVerifier.CHECK_CHAIN_TO_IACA);
            }
            try {
                report.assertAllPassed(allowed);
            } catch (AssertionError e) {
                throw new AssertionError(sample + " does not verify independently:" + System.lineSeparator()
                        + e.getMessage() + System.lineSeparator() + report, e);
            }
            assertEquals(allowed, report.skippedNames(), sample + " skipped a different set of checks than the "
                    + "open gaps, so something stopped running" + System.lineSeparator() + report);
            assertFalse(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).message().isBlank());
        }
        assertTrue(samples.size() >= 1, "at least one sample was verified");
    }

    static List<Path> mdocSamples(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(path -> path.getFileName().toString().endsWith(MdocSamples.MDOC))
                    .sorted()
                    .toList();
        }
    }
}
