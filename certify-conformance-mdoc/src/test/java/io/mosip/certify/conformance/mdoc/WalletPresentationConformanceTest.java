/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.conformance.mdoc;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.mosip.certify.testkit.mdoc.IndependentDeviceResponseVerifier;
import io.mosip.certify.testkit.mdoc.VerificationReport;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.BuildersKt;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.multipaz.cbor.Bstr;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.CborArray;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.Simple;
import org.multipaz.cbor.Tstr;
import org.multipaz.verification.VerificationUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The merge gate of plan section 4.14 for the demo wallet's presentation (P5-03b): every {@code DeviceResponse} the
 * page builds is re-verified by <b>Multipaz</b>, a library Certify does not maintain, so a defect in
 * {@code static/offer/mdoc.js} cannot make its own tests pass by agreeing with itself.
 *
 * <p>The samples come from {@code docs/design/tools/check-offer-wallet.mjs} (`$WALLET_SAMPLES_DIR`, default
 * {@code target/wallet-samples/}): each is the response bytes, the transcript inputs the page signed over, the
 * verifier's own inputs and expectations, and the IACA to anchor to. The suite:
 * </p>
 * <ul>
 *   <li>builds the OpenID4VP 1.0 B.2.6.1 {@code SessionTranscript} itself from the verifier's inputs, in CBOR written
 *       here, and checks that construction against Multipaz's own {@code VerificationUtil.vpSessionTranscript} where
 *       that can express the sample (no thumbprint);</li>
 *   <li>verifies each response with {@link IndependentDeviceResponseVerifier} (Multipaz reads it, checks the issuer
 *       signature and chain to the IACA, every disclosed item's digest and the device signature over that transcript)
 *       and holds an accepted sample to exactly the elements it expects and a rejected one to the check it expects
 *       ({@code deviceSignature} or {@code digest});</li>
 *   <li>records a sample it cannot read - a malformed {@code expected.json}, a missing file, a {@code now} that is not
 *       an instant - as that sample's failure and goes on to the next one: a harness defect in one sample must not stop
 *       the gate from checking the others.</li>
 * </ul>
 *
 * <p>Whether samples must exist is the caller's call, not the environment's: with
 * {@code -Dwallet.samples.required=true} no samples is a failure, and every other run skips with a message.
 * {@code mvn verify} in CI runs before the Node harness has written anything, so keying the failure on {@code CI} made
 * every fresh build red; the dedicated Multipaz step passes the property right after the harness has run instead.</p>
 */
class WalletPresentationConformanceTest {

    static final Path ROOT = Path.of("..");
    /**
     * Set by the step that runs this suite on purpose, after the harness wrote the samples. Absent, a missing sample
     * directory is a skip: {@code mvn verify} runs before the harness in CI, and a developer who has not run it should
     * not see a red build.
     */
    static final boolean SAMPLES_REQUIRED = Boolean.getBoolean("wallet.samples.required");
    /** Where the harness wrote its samples; a CI job may point it elsewhere. */
    static final Path SAMPLES = Path.of(System.getProperty("wallet.samples.dir",
            ROOT.resolve("target/wallet-samples").toString()));

    private static final String SAMPLE_RESPONSE = "device-response.cbor";
    private static final String SAMPLE_EXPECTED = "expected.json";
    private static final String SAMPLE_IACA = "iaca.pem";
    /**
     * Multipaz's own wording for these two checks, matched exactly: a bare {@code (?i)signature} also matches its
     * issuer-signature messages ({@code Signature on MSO failed to verify}), so a document signed by another DSC
     * would satisfy a device-signature negative for the wrong reason (review round 1, finding 3).
     */
    private static final Pattern DEVICE_SIGNATURE = Pattern.compile(
            "Device authentication signature failed to verify");
    private static final Pattern DIGEST = Pattern.compile("Digest mismatch for data element");

    @Test
    void everySampleTheWalletProducedIsVerifiedByMultipaz() throws IOException {
        List<Path> samples = requiredSamples();
        SampleReport report = verifySamples(samples);
        assertTrue(report.failures.isEmpty(), "independent DeviceResponse verification failed for "
                + report.failures.size() + " of " + samples.size() + " samples:" + System.lineSeparator()
                + String.join(System.lineSeparator(), report.failures));
        assertTrue(report.accepted > 0 && report.rejected > 0, "the samples cover both outcomes: " + report.accepted
                + " accepted, " + report.rejected + " rejected");
        System.out.println("[wallet-presentation] Multipaz verified " + samples.size() + " samples: "
                + report.accepted + " accepted, " + report.rejected + " rejected");
    }

    /**
     * The transcript this test writes must be the one Multipaz's own verifier writes, or the two sides of the gate would
     * disagree about the bytes a device signature covers. Multipaz's `vpSessionTranscript` takes the verifier's private
     * response-encryption key, so the check runs on the samples whose third element is null (plaintext direct_post) and
     * the thumbprint form is covered by `@owf/mdoc`'s `SessionTranscript.forOid4Vp` in the Node probe.
     */
    @Test
    void multipazComputesTheSameSessionTranscript() throws IOException {
        List<Path> samples = requiredSamples();
        List<String> failures = new ArrayList<>();
        int checked = 0;
        for (Path sample : samples) {
            try {
                JsonObject request = json(sample.resolve(SAMPLE_EXPECTED)).getAsJsonObject("verifier");
                if (!request.get("jwkThumbprint").isJsonNull()) {
                    continue;
                }
                String clientId = request.get("clientId").getAsString();
                String nonce = request.get("nonce").getAsString();
                String responseUri = request.get("responseUri").getAsString();
                DataItem theirs = MultipazHandover.transcript(null, clientId, nonce, responseUri);
                assertEquals(hex(transcriptOf(request)), hex(Cbor.INSTANCE.encode(theirs)),
                        sample.getFileName() + ": this test's OpenID4VPHandover must be Multipaz's");
                checked += 1;
            } catch (AssertionError | RuntimeException | IOException e) {
                failures.add(sample.getFileName() + ": " + describe(e));
            }
        }
        assertTrue(failures.isEmpty(), "the transcript could not be cross-checked for " + failures.size() + " of "
                + samples.size() + " samples:" + System.lineSeparator()
                + String.join(System.lineSeparator(), failures));
        assertTrue(checked > 0, "no plaintext sample to cross-check the transcript against");
    }

    /**
     * A sample the harness got wrong is that sample's failure, not the end of the run: a sidecar without the members a
     * sample needs, a {@code now} that is not an instant, and a missing file are each reported against their own
     * directory, and the good sample beside them is still verified (review round 2, finding 1). Before this, the first
     * such sample threw out of {@link #transcriptOf} and stopped both tests.
     */
    @Test
    void aMalformedSidecarFailsOnlyItsOwnSample(@TempDir Path directory) throws IOException {
        List<Path> samples = requiredSamples();
        Path source = samples.get(0);
        Path good = copySample(source, directory.resolve("good-sample"));
        Path sidecar = copySample(source, directory.resolve("bad-sidecar"));
        Files.writeString(sidecar.resolve(SAMPLE_EXPECTED), "{\"expect\":\"accepted\"}" + System.lineSeparator(),
                StandardCharsets.UTF_8);
        Path clock = copySample(source, directory.resolve("bad-now"));
        JsonObject wrongClock = json(clock.resolve(SAMPLE_EXPECTED));
        wrongClock.addProperty("now", "yesterday");
        Files.writeString(clock.resolve(SAMPLE_EXPECTED), wrongClock + System.lineSeparator(), StandardCharsets.UTF_8);
        Path incomplete = copySample(source, directory.resolve("missing-iaca"));
        Files.delete(incomplete.resolve(SAMPLE_IACA));

        Outcome sourceOutcome = verifySample(new IndependentDeviceResponseVerifier(), source);
        SampleReport report = verifySamples(samplesIn(directory));
        assertEquals(4, report.accepted + report.rejected + report.failures.size(),
                "every sample in the directory is accounted for: " + report.failures);
        assertEquals(3, report.failures.size(), "one failure each, for the three malformed samples: " + report.failures);
        for (String malformed : List.of("bad-now", "bad-sidecar", "missing-iaca")) {
            assertTrue(report.failures.stream().anyMatch(failure -> failure.startsWith(malformed + ": ")),
                    malformed + " is reported by name: " + report.failures);
        }
        assertTrue(report.failures.stream().noneMatch(failure -> failure.startsWith("good-sample: ")),
                "the good sample is not reported as a failure: " + report.failures);
        assertEquals(sourceOutcome == Outcome.ACCEPTED ? 1 : 0, report.accepted,
                "the good sample beside them is still verified: " + report.failures);
        assertEquals(sourceOutcome == Outcome.REJECTED ? 1 : 0, report.rejected,
                "the good sample beside them is still verified: " + report.failures);
        assertTrue(Files.isRegularFile(good.resolve(SAMPLE_RESPONSE)), "the good sample is a directory");
        assertEquals(hex(Files.readAllBytes(source.resolve(SAMPLE_RESPONSE))),
                hex(Files.readAllBytes(good.resolve(SAMPLE_RESPONSE))),
                "the good sample is the one beside them, byte for byte");
    }

    /**
     * OpenID4VP 1.0 Appendix B.2.6.1, written here in CBOR rather than by the page: `[null, null, ["OpenID4VPHandover",
     * SHA-256(CBOR([client_id, nonce, jwkThumbprint or null, response_uri]))]]`. The page's own builder is held to the
     * appendix's vectors by `check-offer-wallet.mjs`; this is the verifier's side.
     */
    static byte[] transcriptOf(JsonObject request) throws IOException {
        byte[] thumbprint = request.get("jwkThumbprint").isJsonNull() ? null
                : Base64.getUrlDecoder().decode(request.get("jwkThumbprint").getAsString());
        DataItem info = new CborArray(List.of(new Tstr(request.get("clientId").getAsString()),
                new Tstr(request.get("nonce").getAsString()),
                thumbprint == null ? Simple.Companion.getNULL() : new Bstr(thumbprint),
                new Tstr(request.get("responseUri").getAsString())), false);
        DataItem handover = new CborArray(List.of(new Tstr("OpenID4VPHandover"),
                new Bstr(sha256(Cbor.INSTANCE.encode(info)))), false);
        return Cbor.INSTANCE.encode(new CborArray(List.of(Simple.Companion.getNULL(), Simple.Companion.getNULL(),
                handover), false));
    }

    /**
     * Multipaz's own builder, so the two can be compared.
     *
     * <p>{@code vpSessionTranscript$multipaz} is Kotlin-{@code internal}, so this is a deliberate reach past the
     * library's published surface, pinned to 0.102.0: no public API builds an OpenID4VP 1.0 transcript. The public
     * alternatives take a whole verification ({@code verifyOpenID4VPResponse} builds the transcript it needs inside),
     * so none can hand the transcript back to be compared with the one written in {@link #transcriptOf}. The method's
     * signature is fixed by Kotlin's {@code $multipaz} name mangling, and the POM pins the version, so a rename shows
     * up as a compile error in the upgrade that changes it, not as a silent skip.</p>
     */
    private static final class MultipazHandover {

        static DataItem transcript(Object responseKey, String clientId, String nonce, String responseUri) {
            Function2<kotlinx.coroutines.CoroutineScope, Continuation<? super DataItem>, Object> runner =
                    (scope, continuation) -> VerificationUtil.INSTANCE.vpSessionTranscript$multipaz(
                            (org.multipaz.crypto.EcPrivateKey) responseKey, clientId, nonce, responseUri, continuation);
            try {
                @SuppressWarnings("unchecked")
                DataItem result = (DataItem) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, runner);
                return result;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while building the transcript with Multipaz", e);
            }
        }
    }

    /* ---------------------------------------------------------------- helpers */

    /** What a run over a directory of samples found: the counts, and every sample that failed with why. */
    static final class SampleReport {
        int accepted;
        int rejected;
        final List<String> failures = new ArrayList<>();
    }

    /** What one sample was held to. */
    enum Outcome { ACCEPTED, REJECTED }

    /**
     * The sample directories, or a skip when the harness has not written any - a failure when the step that ran this
     * suite said the samples must exist. Every test here starts this way, so the decision lives in one place.
     */
    static List<Path> requiredSamples() throws IOException {
        List<Path> samples = samples();
        if (samples.isEmpty() && SAMPLES_REQUIRED) {
            fail(noSamples());
        }
        Assumptions.assumeTrue(!samples.isEmpty(), noSamples());
        return samples;
    }

    /**
     * Verifies every sample of a directory, recording a failure against the sample it came from: a malformed
     * {@code expected.json}, a missing file, or a {@code now} that is not an instant is that sample's report entry and
     * the run goes on to the next one (review round 2, finding 1).
     */
    static SampleReport verifySamples(List<Path> samples) {
        IndependentDeviceResponseVerifier verifier = new IndependentDeviceResponseVerifier();
        SampleReport report = new SampleReport();
        for (Path sample : samples) {
            try {
                if (verifySample(verifier, sample) == Outcome.ACCEPTED) {
                    report.accepted += 1;
                } else {
                    report.rejected += 1;
                }
            } catch (AssertionError | RuntimeException | IOException e) {
                report.failures.add(sample.getFileName() + ": " + describe(e));
            }
        }
        return report;
    }

    /** One sample, held to its {@code expected.json}; throws instead of returning an outcome when it fails. */
    static Outcome verifySample(IndependentDeviceResponseVerifier verifier, Path sample) throws IOException {
        String name = sample.getFileName().toString();
        JsonObject expected = json(sample.resolve(SAMPLE_EXPECTED));
        byte[] response = Files.readAllBytes(sample.resolve(SAMPLE_RESPONSE));
        String iaca = Files.readString(sample.resolve(SAMPLE_IACA), StandardCharsets.US_ASCII);
        JsonObject request = expected.getAsJsonObject("verifier");
        byte[] transcript = transcriptOf(request);
        String docType = expected.get("docType").getAsString();
        Instant at = Instant.parse(expected.get("now").getAsString());
        String expect = expected.get("expect").getAsString();
        if ("accepted".equals(expect)) {
            IndependentDeviceResponseVerifier.Result result = verifier.verify(response, transcript, iaca, at,
                    docType, elements(expected.getAsJsonArray("elements")));
            result.report().assertAllPassed();
            assertEquals(docType, mdocDocType(response), name + ": the docType Multipaz read");
            assertEquals(elements(expected.getAsJsonArray("elements")), result.disclosedElements(),
                    name + ": the elements Multipaz read back");
            return Outcome.ACCEPTED;
        }
        // a negative sample may disclose whatever it does; what matters is the check that refuses it
        IndependentDeviceResponseVerifier.Result result = verifier.verify(response, transcript, iaca, at, docType, null);
        String rejectedBy = expected.get("rejectedBy").getAsString();
        VerificationReport.Check deviceAuth = result.report().check(IndependentDeviceResponseVerifier.CHECK_DEVICE_AUTH);
        assertFalse(deviceAuth.passed(), name + ": Multipaz accepted a response it must reject"
                + System.lineSeparator() + result.report());
        Pattern expectedPattern = "digest".equals(rejectedBy) ? DIGEST : DEVICE_SIGNATURE;
        assertTrue(expectedPattern.matcher(String.valueOf(deviceAuth.message())).find(),
                name + ": rejected as \"" + deviceAuth.message() + "\", not at the " + rejectedBy + " check");
        return Outcome.REJECTED;
    }

    /** A failure as one line: an assertion's own message, or the exception's kind and message when it has none. */
    static String describe(Throwable failure) {
        String message = failure.getMessage() == null ? "" : failure.getMessage().trim();
        if (failure instanceof AssertionError) {
            return message.isEmpty() ? "assertion failed" : message;
        }
        return message.isEmpty() ? failure.getClass().getSimpleName()
                : failure.getClass().getSimpleName() + ": " + message;
    }

    /** Copies a sample's files, so a test can break a copy of it without touching the harness's own samples. */
    static Path copySample(Path source, Path target) throws IOException {
        Files.createDirectories(target);
        for (String file : List.of(SAMPLE_RESPONSE, SAMPLE_EXPECTED, SAMPLE_IACA)) {
            Files.copy(source.resolve(file), target.resolve(file));
        }
        return target;
    }

    /** The sample directories, sorted; a sample is a directory holding a device-response.cbor. */
    static List<Path> samples() throws IOException {
        return samplesIn(SAMPLES);
    }

    static List<Path> samplesIn(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.filter(entry -> Files.isRegularFile(entry.resolve(SAMPLE_RESPONSE)))
                    .sorted().toList();
        }
    }

    static JsonObject json(Path file) throws IOException {
        return JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
    }

    /** Why there is nothing to verify, for the skip and for the failure the required run reports. */
    static String noSamples() {
        return "no wallet presentation samples in " + SAMPLES.toAbsolutePath()
                + "; node docs/design/tools/check-offer-wallet.mjs writes them (plan 4.14)";
    }

    /** `[[namespace, elementIdentifier], …]` as `namespace/elementIdentifier` strings. */
    static Set<String> elements(JsonArray pairs) {
        Set<String> elements = new TreeSet<>();
        for (JsonElement pair : pairs) {
            elements.add(pair.getAsJsonArray().get(0).getAsString() + "/"
                    + pair.getAsJsonArray().get(1).getAsString());
        }
        return new LinkedHashSet<>(elements);
    }

    /** The docType Multipaz reads from the response's document, independent of the verifier's report. */
    static String mdocDocType(byte[] response) {
        DataItem item = Cbor.INSTANCE.decode(response);
        return item.get("documents").get(0).get("docType").getAsTstr();
    }

    static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
