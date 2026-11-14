/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.time.Instant;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cose.Cose;
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;
import org.multipaz.mdoc.issuersigned.IssuerNamespaces;
import org.multipaz.mdoc.issuersigned.IssuerSignedItem;
import org.multipaz.mdoc.response.DeviceResponse;
import org.multipaz.mdoc.response.MdocDocument;
import org.multipaz.storage.ephemeral.EphemeralStorage;
import org.multipaz.trustmanagement.TrustManager;
import org.multipaz.trustmanagement.TrustMetadata;
import org.multipaz.trustmanagement.TrustResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * An ISO/IEC 18013-5 {@code DeviceResponse} verifier built on OpenWallet Foundation <b>Multipaz</b>, the second library
 * (with {@code @owf/mdoc} in {@code docs/design/tools/wallet-probe/}) that verifies what the demo wallet's page builds
 * (docs/design/wp/P5-03-demo-wallet-presentation.md, plan section 4.14, P5-03b). Certify maintains neither, so a defect
 * in {@code static/offer/mdoc.js} cannot make its own tests pass by agreeing with itself.
 *
 * <p>What Multipaz checks here, each as its own named check ({@link #CHECKS}, {@link VerificationReport}):</p>
 * <ul>
 *   <li>{@code deviceResponse.parse}: Multipaz's own {@code DeviceResponse.fromDataItem} reads the response;</li>
 *   <li>{@code deviceResponse.status}: version {@code "1.0"} and status 0 (ISO/IEC 18013-5 8.3.2.1.2.2 and the
 *       {@code Status} table);</li>
 *   <li>{@code deviceResponse.documents}: exactly one document, with an {@code issuerAuth} (HAIP 1.0 section 5.3.1:
 *       "each ISO mdoc MUST be returned in a separate DeviceResponse");</li>
 *   <li>{@code document.docType}: the docType the caller expects, from the MSO;</li>
 *   <li>{@code deviceAuth.verify}: Multipaz verifies the issuer signature, every disclosed item's digest against the
 *       MSO's {@code valueDigests}, and the device signature over {@code DeviceAuthenticationBytes} built from the
 *       session transcript **the caller supplies** - so a wallet that signed another transcript or with another key
 *       fails here (9.1.2.5, 9.1.3.4, 9.1.3.6). Certificate trust is switched off for this call
 *       ({@code disableTrustChecks}) because the next check is the trust decision, so a chain problem cannot hide a
 *       signature problem;</li>
 *   <li>{@code issuerAuth.chain}: the document signer chains to the IACA the caller anchors to, through Multipaz's own
 *       {@code TrustManager} ({@code addX509Cert} + {@code verify}) at the instant the sample was built for. It runs
 *       after the verification because Multipaz fills the document's certificate chain while it verifies;</li>
 *   <li>{@code issuerSigned.disclosed}: the set of {@code (namespace, elementIdentifier)} pairs Multipaz read back is
 *       exactly the set the caller expects - an element the user did not choose must not be disclosed, and one that
 *       was chosen must be.</li>
 * </ul>
 *
 * <p>Every check collects its problems rather than throwing (like {@link IndependentMdocVerifier}), so an assertion
 * names all of them; {@link Result#report()} can be turned into an assertion with
 * {@link VerificationReport#assertAllPassed()}.</p>
 */
public final class IndependentDeviceResponseVerifier {

    public static final String CHECK_PARSE = "deviceResponse.parse";
    public static final String CHECK_STATUS = "deviceResponse.status";
    public static final String CHECK_DOCUMENTS = "deviceResponse.documents";
    public static final String CHECK_DOC_TYPE = "document.docType";
    public static final String CHECK_ISSUER_CHAIN = "issuerAuth.chain";
    public static final String CHECK_DEVICE_AUTH = "deviceAuth.verify";
    public static final String CHECK_DISCLOSED = "issuerSigned.disclosed";

    /** Every check, in report order. */
    public static final List<String> CHECKS = List.of(CHECK_PARSE, CHECK_STATUS, CHECK_DOCUMENTS, CHECK_DOC_TYPE,
            CHECK_DEVICE_AUTH, CHECK_ISSUER_CHAIN, CHECK_DISCLOSED);

    /** Reported when a check throws unexpectedly: a harness defect or a malformed input, never a pass. */
    public static final String ERROR = "error";

    /** What one DocumentResponse was verified to be: the report and the disclosed elements, by namespace. */
    public record Result(VerificationReport report, Map<String, Set<String>> disclosed) {

        public Result {
            disclosed = Map.copyOf(disclosed);
        }

        /** The disclosed elements as {@code namespace/element} strings, the same spelling the samples use. */
        public Set<String> disclosedElements() {
            Set<String> elements = new LinkedHashSet<>();
            disclosed.forEach((namespace, identifiers) -> identifiers.forEach(id -> elements.add(namespace + "/" + id)));
            return elements;
        }
    }

    /**
     * Verifies one response against the verifier's own inputs.
     *
     * @param deviceResponse     the response as the wallet produced it
     * @param sessionTranscript  the {@code SessionTranscript} bytes the verifier computed from the request object
     *                           (OpenID4VP 1.0 B.2.6.1)
     * @param iacaPem            the trust anchor the document signer is expected to chain to
     * @param at                 the instant the response is verified at (the sample's clock)
     * @param expectedDocType    the docType the query asked for, or null to accept the response's own
     * @param expectedElements   the {@code namespace/element} pairs that must be disclosed, or null to accept any set
     */
    public Result verify(byte[] deviceResponse, byte[] sessionTranscript, String iacaPem, java.time.Instant at,
                         String expectedDocType, Set<String> expectedElements) {
        Instant instant = Instant.Companion.fromEpochMilliseconds(at.toEpochMilli());
        Map<String, Set<String>> disclosed = new LinkedHashMap<>();
        List<VerificationReport.Check> checks = new ArrayList<>();

        DeviceResponse parsed;
        try {
            DataItem responseItem = Cbor.INSTANCE.decode(deviceResponse);
            parsed = await(c -> DeviceResponse.Companion.fromDataItem(responseItem, c));
        } catch (Throwable e) {
            rethrowIfFatal(e);
            String reason = "not run: the DeviceResponse did not parse (" + describe(e) + ")";
            List<VerificationReport.Check> unparsed = new ArrayList<>();
            for (String name : CHECKS) {
                unparsed.add(name.equals(CHECK_PARSE) ? VerificationReport.Check.fail(name, ERROR, describe(e))
                        : VerificationReport.Check.fail(name, "notRun", reason));
            }
            return new Result(new VerificationReport(unparsed), disclosed);
        }
        final DeviceResponse response = parsed;
        // Multipaz's DeviceResponse parses its documents while it verifies, so each is read here by Multipaz's own
        // MdocDocument parser: the docType, the namespaces and the issuerAuth are available before any signature check
        List<MdocDocument> documents = new ArrayList<>();
        for (DataItem item : Cbor.INSTANCE.decode(deviceResponse).get("documents").getAsArray()) {
            documents.add(await(c -> MdocDocument.Companion.fromDataItem(item, c)));
        }
        checks.add(run(CHECK_PARSE, p -> {
            if (documents.isEmpty()) p.add("noDocuments", "the response carries no documents");
            return "Multipaz read " + documents.size() + " document(s), version " + response.getVersion();
        }));
        checks.add(run(CHECK_STATUS, p -> {
            if (!"1.0".equals(response.getVersion())) p.add("version", "version is " + response.getVersion());
            if (response.getStatus() != DeviceResponse.STATUS_OK) p.add("status", "status is " + response.getStatus());
            return "version 1.0, status 0";
        }));
        checks.add(run(CHECK_DOCUMENTS, p -> {
            if (documents.size() != 1) {
                p.add("count", documents.size() + " documents; HAIP 1.0 section 5.3.1 asks for one per DeviceResponse");
            }
            for (MdocDocument document : documents) {
                if (document.getIssuerAuth() == null) p.add("noIssuerAuth", document.getDocType() + " has no issuerAuth");
            }
            return documents.isEmpty() ? "none" : documents.get(0).getDocType();
        }));
        if (documents.isEmpty()) {
            // nothing further can be read; the checks above already failed
            for (String name : CHECKS.subList(3, CHECKS.size())) {
                checks.add(VerificationReport.Check.fail(name, "noDocuments", "the response carries no documents"));
            }
            return new Result(new VerificationReport(checks), disclosed);
        }
        MdocDocument document = documents.get(0);
        checks.add(run(CHECK_DOC_TYPE, p -> {
            String docType = document.getDocType();
            if (expectedDocType != null && !expectedDocType.equals(docType)) {
                p.add("mismatch", "the response carries " + docType + ", not the requested " + expectedDocType);
            }
            return docType;
        }));
        checks.add(run(CHECK_DEVICE_AUTH, p -> {
            DataItem transcript = Cbor.INSTANCE.decode(sessionTranscript);
            // certificate trust is the next check, so a chain problem cannot hide a signature or digest problem here
            await(c -> response.verify(transcript, null, null, null, instant, true, c));
            return "issuer signature, " + digestCount(document) + " digest(s) and the device signature over the"
                    + " verifier's own session transcript";
        }));
        checks.add(run(CHECK_ISSUER_CHAIN, p -> {
            X509Cert anchor = X509Cert.Companion.fromPem(iacaPem);
            TrustManager trust = new TrustManager(new EphemeralStorage(), "wallet-presentation", "wallet");
            TrustMetadata metadata = new TrustMetadata("wallet presentation fixture IACA", null, null, null, null, true,
                    Map.of());
            await(c -> trust.addX509Cert(anchor, metadata, c));
            // the x5chain of the issuerAuth's unprotected header (ISO/IEC 18013-5 9.1.2.4, RFC 9360 label 33), as
            // Multipaz parsed the header it received; a DSC-only chain is the bare bstr form
            DataItem header = document.getIssuerAuth().getUnprotectedHeaders().get(new CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN));
            if (header == null) {
                p.add("noX5chain", "the issuerAuth carries no x5chain");
                return null;
            }
            X509CertChain chain = X509CertChain.Companion.fromDataItem(header);
            if (chain.getCertificates().isEmpty()) {
                p.add("noX5chain", "the issuerAuth's x5chain carries no certificate");
                return null;
            }
            TrustResult result = await(c -> trust.verify(chain.getCertificates(), instant, true, c));
            if (!result.isTrusted()) {
                p.add("untrusted", "Multipaz does not trust the chain" + (result.getError() == null ? ""
                        : ": " + describe(result.getError())));
            }
            return result.isTrusted() ? "trusted, " + chain.getCertificates().size() + " certificate(s)" : null;
        }));
        checks.add(run(CHECK_DISCLOSED, p -> {
            Map<String, Set<String>> read = disclosedElements(document);
            if (expectedElements != null) {
                Set<String> actual = new LinkedHashSet<>();
                read.forEach((namespace, identifiers) -> identifiers.forEach(id -> actual.add(namespace + "/" + id)));
                Set<String> unexpected = new LinkedHashSet<>(actual);
                unexpected.removeAll(expectedElements);
                Set<String> missing = new LinkedHashSet<>(expectedElements);
                missing.removeAll(actual);
                if (!unexpected.isEmpty()) p.add("unexpected", "not chosen but disclosed: " + unexpected);
                if (!missing.isEmpty()) p.add("missing", "chosen but not disclosed: " + missing);
            }
            read.forEach((namespace, identifiers) -> disclosed.computeIfAbsent(namespace, key -> new LinkedHashSet<>())
                    .addAll(identifiers));
            return read.isEmpty() ? "no element is disclosed" : read.size() + " namespace(s)";
        }));
        return new Result(new VerificationReport(checks), disclosed);
    }

    /** The disclosed elements of one document, by namespace; empty when it carries no {@code nameSpaces}. */
    private static Map<String, Set<String>> disclosedElements(MdocDocument document) {
        Map<String, Set<String>> read = new LinkedHashMap<>();
        IssuerNamespaces namespaces = document.getIssuerNamespaces();
        if (namespaces == null) {
            return read;
        }
        // IssuerNamespaces is namespace -> elementIdentifier -> item (Multipaz reads the map it received)
        for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
            read.put(namespace.getKey(), new LinkedHashSet<>(namespace.getValue().keySet()));
        }
        return read;
    }

    /** How many items the document discloses, for the check's message. */
    private static int digestCount(MdocDocument document) {
        return disclosedElements(document).values().stream().mapToInt(Set::size).sum();
    }

    @FunctionalInterface
    interface Probe {
        /** Adds every problem it finds and returns what it verified, or null when it reported one. */
        String run(Problems problems) throws Exception;
    }

    /** The problems one check found, by code, in the order found. */
    static final class Problems {

        private final Map<String, String> found = new LinkedHashMap<>();

        void add(String code, String message) {
            found.merge(code, message, (a, b) -> a.equals(b) ? a : a + "; " + b);
        }

        boolean isEmpty() {
            return found.isEmpty();
        }

        List<VerificationReport.Problem> list() {
            return found.entrySet().stream().map(e -> new VerificationReport.Problem(e.getKey(), e.getValue())).toList();
        }
    }

    /** Runs one check; anything it throws is that check's problem, so one bad response cannot take the report down. */
    static VerificationReport.Check run(String name, Probe probe) {
        Problems problems = new Problems();
        String message = null;
        try {
            message = probe.run(problems);
        } catch (Throwable e) {
            rethrowIfFatal(e);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            problems.add(ERROR, describe(e));
        }
        return problems.isEmpty() ? VerificationReport.Check.pass(name, message)
                : VerificationReport.Check.fail(name, problems.list());
    }

    /** {@code OutOfMemoryError}, {@code InternalError}, {@code UnknownError}: nothing sensible is left to report. */
    private static void rethrowIfFatal(Throwable e) {
        if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
            throw fatal;
        }
    }

    /** Multipaz's exceptions explain themselves; a bare type name is the last resort. */
    private static String describe(Throwable e) {
        String message = e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : e.getClass().getSimpleName()
                + ": " + message.replaceAll("\\s+", " ").trim();
    }

    /**
     * Runs a Multipaz suspend function to completion. Multipaz's verifier is suspending because an Android app awaits
     * the JVM; {@code runBlocking} keeps that an implementation detail of this class.
     */
    private static <T> T await(Function<Continuation<? super T>, Object> block) {
        Function2<CoroutineScope, Continuation<? super T>, Object> runner = new Function2<>() {
            @Override
            public Object invoke(CoroutineScope scope, Continuation<? super T> continuation) {
                return block.apply(continuation);
            }
        };
        try {
            @SuppressWarnings("unchecked")
            T result = (T) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, runner);
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while verifying with Multipaz", e);
        }
    }
}
