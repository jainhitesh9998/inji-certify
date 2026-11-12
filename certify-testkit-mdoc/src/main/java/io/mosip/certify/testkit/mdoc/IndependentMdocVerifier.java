/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;
import kotlinx.io.bytestring.ByteString;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.CborMap;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.MajorType;
import org.multipaz.cbor.Tagged;
import org.multipaz.cbor.Tstr;
import org.multipaz.cose.Cose;
import org.multipaz.cose.CoseKey;
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.cose.CoseSign1;
import org.multipaz.crypto.Algorithm;
import org.multipaz.crypto.Crypto;
import org.multipaz.crypto.EcPublicKey;
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate;
import org.multipaz.crypto.EcPublicKeyOkp;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;
import org.multipaz.crypto.X509CertChainJvmKt;
import org.multipaz.documenttype.DocumentAttribute;
import org.multipaz.documenttype.DocumentAttributeType;
import org.multipaz.documenttype.MdocDataElement;
import org.multipaz.documenttype.MdocNamespace;
import org.multipaz.documenttype.knowntypes.DrivingLicense;
import org.multipaz.mdoc.issuersigned.IssuerNamespaces;
import org.multipaz.mdoc.issuersigned.IssuerSignedItem;
import org.multipaz.mdoc.mso.MobileSecurityObject;
import org.multipaz.validation.ValidationFinding;
import org.multipaz.validation.ValidationResult;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An ISO/IEC 18013-5 IssuerSigned verifier built on libraries Certify does not maintain, so a formatter change cannot
 * make its own tests pass by agreeing with itself: OpenWallet Foundation <b>Multipaz</b> parses the CBOR, the MSO,
 * the namespaces and the x5chain and checks the COSE_Sign1 signature and digests; <b>Authlete CBOR</b> parses and
 * verifies the same IssuerAuth independently as a second COSE oracle; the JDK PKIX validator anchors the chain at an
 * IACA. Every rule becomes a named check in a {@link VerificationReport}, and a check that did not run is
 * {@link VerificationReport.State#SKIPPED} rather than a pass.
 *
 * <p>Every check collects <b>all</b> its problems, each under a stable problem code from {@link #PROBLEM_CODES}
 * ({@code mso.validityInfo:expired}, {@code mdl.elementTypes:untyped:birth_date}), so an accepted gap names the one
 * defect it accepts and cannot hide another one inside the same check ({@link AcceptedGaps}).
 * {@code docs/design/tools/verify_mdoc.py} reports the same codes for the rules it implements; the registry there is
 * compared with this one by {@code ProblemCodeRegistryTest}.
 *
 * <p>Digests are computed over the bytes the credential actually carried ({@link WireIssuerSignedItems});
 * {@code IssuerSignedItem.calculateDigest} is kept as a second opinion precisely because it re-encodes. The MSO fields
 * are read from the MSO as sent with Multipaz's CBOR and COSE_Key decoders, so whether Multipaz's
 * {@code MobileSecurityObject} model accepts the MSO is one check ({@code mso.parse}) instead of a cascade.
 *
 * <p>See {@code docs/design/20-mdl-issuer.md} (M-01, decision D9). Multipaz is pinned in the parent POM; its Kotlin
 * dependencies stay inside {@code certify-testkit-mdoc}.
 */
public final class IndependentMdocVerifier {

    public static final String CHECK_SHAPE = "credential.shape";
    public static final String CHECK_PARSE = "issuerSigned.parse";
    public static final String CHECK_UNTAGGED = "issuerAuth.untagged";
    public static final String CHECK_SIGNATURE_MULTIPAZ = "issuerAuth.signature.multipaz";
    public static final String CHECK_SIGNATURE_AUTHLETE = "issuerAuth.signature.authlete";
    public static final String CHECK_MSO_PAYLOAD_TAG = "mso.payloadTag24";
    public static final String CHECK_MSO_PARSE = "mso.parse";
    public static final String CHECK_VALUE_DIGESTS = "mso.valueDigests";
    public static final String CHECK_CALCULATED_DIGESTS = "mso.valueDigests.calculateDigest";
    public static final String CHECK_NAMESPACES = "mso.nameSpaces";
    public static final String CHECK_DIGEST_IDS_UNIQUE = "mso.valueDigests.digestIdsUnique";
    public static final String CHECK_DEVICE_KEY = "mso.deviceKey";
    public static final String CHECK_DOC_TYPE = "mso.docType";
    public static final String CHECK_VALIDITY_INFO = "mso.validityInfo";
    public static final String CHECK_TDATE_TAGS = "mso.validityInfo.tdateTags";
    public static final String CHECK_CHAIN_TO_IACA = "x5chain.iaca";
    public static final String CHECK_NO_SELF_SIGNED = "x5chain.noSelfSigned";
    public static final String CHECK_SERIAL_NUMBER = "x5chain.serialNumber";
    public static final String CHECK_ELEMENT_TYPES = "mdl.elementTypes";

    /** Every check, in report order. A credential that does not parse reports all of them as failed. */
    public static final List<String> CHECKS = List.of(CHECK_SHAPE, CHECK_PARSE, CHECK_UNTAGGED,
            CHECK_SIGNATURE_MULTIPAZ, CHECK_SIGNATURE_AUTHLETE, CHECK_MSO_PAYLOAD_TAG, CHECK_MSO_PARSE, CHECK_NAMESPACES,
            CHECK_VALUE_DIGESTS, CHECK_CALCULATED_DIGESTS, CHECK_DIGEST_IDS_UNIQUE, CHECK_DEVICE_KEY, CHECK_DOC_TYPE,
            CHECK_VALIDITY_INFO, CHECK_TDATE_TAGS, CHECK_CHAIN_TO_IACA, CHECK_NO_SELF_SIGNED, CHECK_SERIAL_NUMBER,
            CHECK_ELEMENT_TYPES);

    /**
     * The problem codes each check reports. A code ending in {@code :*} takes a parameter (an element identifier, a
     * validityInfo field, a certificate index, {@code <namespace>/<identifier>}), written {@code untyped:birth_date}.
     * These are the only codes a {@code .gaps} line may name; {@code verify_mdoc.py} carries the same table.
     */
    public static final Map<String, List<String>> PROBLEM_CODES = problemCodes();

    /** Reported when a check throws unexpectedly; a harness defect or a malformed input, never an accepted gap. */
    public static final String ERROR = "error";
    /** Reported by every check when the credential does not parse; never an accepted gap. */
    public static final String NOT_RUN = "notRun";

    private static final Pattern CODE = Pattern.compile("([A-Za-z][A-Za-z0-9]*)(?::([A-Za-z0-9_.\\-/]+))?");
    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    private static final int LABEL_ALG = 1;
    private static final int LABEL_X5CHAIN = 33;
    private static final long COSE_KEY_D = -4;
    private static final int MAX_SERIAL_OCTETS = 20;
    private static final List<String> VALIDITY_FIELDS = List.of("signed", "validFrom", "validUntil", "expectedUpdate");
    /** RFC 3339 date-time as ISO/IEC 18013-5 uses it; the groups are the fraction and the offset. */
    private static final Pattern RFC3339 = Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})");
    private static final Pattern FULL_DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
    private static final Pattern MULTIPAZ_FRACTIONAL =
            Pattern.compile("MSO (signed|validFrom|validUntil|expectedUpdate) timestamp must not have fractional seconds");
    /**
     * ISO/IEC 18013-5 Table 5 where Multipaz 0.102.0's {@code DrivingLicense} disagrees: {@code issue_date} and
     * {@code expiry_date} are "tdate or full-date" (Multipaz: full-date only) and {@code portrait_capture_date} is a
     * tdate (Multipaz: full-date). {@code driving_privileges} is modelled from 7.2.4, because Multipaz carries no
     * embedded attributes for it.
     */
    private static final Set<String> TDATE_OR_FULL_DATE = Set.of("issue_date", "expiry_date");
    private static final Set<String> TDATE_ONLY = Set.of("portrait_capture_date");
    private static final String DRIVING_PRIVILEGES = "driving_privileges";

    private static Map<String, List<String>> problemCodes() {
        Map<String, List<String>> codes = new LinkedHashMap<>();
        codes.put(CHECK_SHAPE, List.of("documentWrapper"));
        codes.put(CHECK_PARSE, List.of("malformed"));
        codes.put(CHECK_UNTAGGED, List.of("tagged"));
        codes.put(CHECK_SIGNATURE_MULTIPAZ, List.of("noAlg", "unsupportedAlg", "invalid"));
        codes.put(CHECK_SIGNATURE_AUTHLETE, List.of("notCoseSign1", "noX5chain", "invalid"));
        codes.put(CHECK_MSO_PAYLOAD_TAG, List.of("notTag24"));
        codes.put(CHECK_MSO_PARSE, List.of("refused"));
        codes.put(CHECK_NAMESPACES, List.of("empty", "emptyNamespace:*", "noValueDigests:*", "duplicateIdentifier:*",
                "multipazStructural", "multipazAgainstMso"));
        codes.put(CHECK_VALUE_DIGESTS, List.of("badAlgorithm", "empty", "noItems", "nonPreferredHead:*", "noNamespace:*",
                "noEntry:*", "mismatch:*", "duplicateHidden"));
        codes.put(CHECK_CALCULATED_DIGESTS, List.of("badAlgorithm", "noEntry:*", "mismatch:*"));
        codes.put(CHECK_DIGEST_IDS_UNIQUE, List.of("duplicate:*"));
        codes.put(CHECK_DEVICE_KEY, List.of("noHolder", "unsupportedHolder", "missing", "privateKey", "kty", "crv", "x",
                "y", "yOnOkp", "multipazUnreadable", "multipazMismatch"));
        codes.put(CHECK_DOC_TYPE, List.of("missing", "mismatch", "documentMismatch"));
        codes.put(CHECK_VALIDITY_INFO, List.of("missing:*", "notDate:*", "signedAfterValidFrom",
                "validFromNotBeforeValidUntil", "expectedUpdateBeforeValidFrom", "expectedUpdateNotBeforeValidUntil",
                "notYetValid", "expired", "multipazDisagrees:*", "multipazRejects"));
        codes.put(CHECK_TDATE_TAGS, List.of("missing:*", "untagged:*", "notTdate:*", "notRfc3339:*",
                "fractionalSeconds:*", "notZulu:*", "notCalendar:*"));
        codes.put(CHECK_CHAIN_TO_IACA, List.of("noAnchorSupplied", "onlyAnchor", "notIssuedBy:*", "notAnchored",
                "notValidAt:*", "pkix:*", "multipaz"));
        codes.put(CHECK_NO_SELF_SIGNED, List.of("selfSigned:*"));
        codes.put(CHECK_SERIAL_NUMBER, List.of("nonPositive", "zero", "tooLong"));
        codes.put(CHECK_ELEMENT_TYPES, List.of("noNamespace", "missing:*", "untyped:*", "notInDocType:*", "unmodelled:*"));
        if (!List.copyOf(codes.keySet()).equals(CHECKS)) {
            throw new IllegalStateException("PROBLEM_CODES must list every check in report order");
        }
        return Collections.unmodifiableMap(codes);
    }

    /** True when {@code code} is one {@code check} reports: a registered code, or a parameterised one with its parameter. */
    public static boolean isProblemCode(String check, String code) {
        List<String> codes = PROBLEM_CODES.get(check);
        Matcher matcher = code == null ? null : CODE.matcher(code);
        if (codes == null || matcher == null || !matcher.matches()) {
            return false;
        }
        return matcher.group(2) == null ? codes.contains(code) : codes.contains(matcher.group(1) + ":*");
    }

    /** A code parameter as both verifiers spell it: every character outside {@code [A-Za-z0-9_.-/]} becomes {@code _}. */
    static String parameter(String value) {
        StringBuilder out = new StringBuilder();
        String text = String.valueOf(value);
        text.codePoints().forEach(c -> out.append(c < 128 && (Character.isLetterOrDigit(c) || "_.-/".indexOf(c) >= 0)
                ? (char) c : '_'));
        return out.isEmpty() ? "_" : out.toString();
    }

    /**
     * Verifies a credential as a wallet received it: a bare {@code IssuerSigned} or the draft-13 {@code Document}
     * {@code {docType, issuerSigned}}, whose {@code issuerSigned} is read from the received bytes without re-encoding
     * and which fails {@code credential.shape}.
     */
    public VerificationReport verify(byte[] credential, JWK expectedHolderKey, Optional<X509Certificate> iaca,
                                     Instant at, Options options) {
        Doc doc;
        try {
            doc = Doc.parse(credential, options);
        } catch (Throwable e) {
            rethrowIfFatal(e);
            // a missing x5chain or issuerAuth is a failed check, not an exception out of the harness
            String reason = "not run: the credential did not parse (" + describe(e) + ")";
            List<VerificationReport.Check> unparsed = new ArrayList<>();
            for (String name : CHECKS) {
                unparsed.add(name.equals(CHECK_PARSE) ? VerificationReport.Check.fail(name, "malformed", describe(e))
                        : VerificationReport.Check.fail(name, NOT_RUN, reason));
            }
            return new VerificationReport(unparsed);
        }
        List<VerificationReport.Check> checks = new ArrayList<>();
        checks.add(run(CHECK_SHAPE, doc::shape));
        checks.add(VerificationReport.Check.pass(CHECK_PARSE, "Multipaz reads issuerAuth, nameSpaces and x5chain; "
                + doc.wireItems.size() + " IssuerSignedItems on the wire"));
        checks.add(run(CHECK_UNTAGGED, doc::untagged));
        checks.add(run(CHECK_SIGNATURE_MULTIPAZ, doc::signatureWithMultipaz));
        checks.add(run(CHECK_SIGNATURE_AUTHLETE, doc::signatureWithAuthlete));
        checks.add(run(CHECK_MSO_PAYLOAD_TAG, doc::msoPayloadIsTag24));
        checks.add(run(CHECK_MSO_PARSE, doc::msoParses));
        checks.add(run(CHECK_NAMESPACES, doc::namespacesValidate));
        checks.add(run(CHECK_VALUE_DIGESTS, doc::digestsMatchValueDigests));
        checks.add(run(CHECK_CALCULATED_DIGESTS, doc::calculateDigestAgrees));
        checks.add(run(CHECK_DIGEST_IDS_UNIQUE, doc::digestIdsAreUnique));
        checks.add(run(CHECK_DEVICE_KEY, p -> doc.deviceKey(p, expectedHolderKey)));
        checks.add(run(CHECK_DOC_TYPE, p -> doc.docType(p, options.expectedDocType())));
        checks.add(run(CHECK_VALIDITY_INFO, p -> doc.validityInfo(p, at)));
        checks.add(run(CHECK_TDATE_TAGS, p -> doc.tdateTags(p, options.strict())));
        checks.add(run(CHECK_CHAIN_TO_IACA, p -> doc.chainToIaca(p, iaca, at, options.strict())));
        checks.add(run(CHECK_NO_SELF_SIGNED, p -> doc.noSelfSignedInChain(p, options.strict())));
        checks.add(run(CHECK_SERIAL_NUMBER, doc::serialNumbers));
        checks.add(run(CHECK_ELEMENT_TYPES, p -> doc.mdlElementTypes(p, options.strict())));
        return new VerificationReport(checks);
    }

    @FunctionalInterface
    interface Probe {
        /** Adds every problem it finds to {@code problems} and returns what it verified when there is none. */
        String run(Problems problems) throws Exception;
    }

    /** The problems one check found, by code, in the order found; the same code twice keeps both messages. */
    static final class Problems {

        private final String check;
        private final Map<String, String> found = new LinkedHashMap<>();

        Problems(String check) {
            this.check = check;
        }

        void add(String code, String message) {
            if (!ERROR.equals(code) && !isProblemCode(check, code)) {
                throw new IllegalStateException("the harness reports the unregistered problem code " + check + ":" + code
                        + "; add it to IndependentMdocVerifier.PROBLEM_CODES and verify_mdoc.py");
            }
            found.merge(code, message, (a, b) -> a.equals(b) ? a : a + "; " + b);
        }

        boolean isEmpty() {
            return found.isEmpty();
        }

        boolean contains(String code) {
            return found.containsKey(code);
        }

        List<VerificationReport.Problem> list() {
            return found.entrySet().stream().map(e -> new VerificationReport.Problem(e.getKey(), e.getValue())).toList();
        }
    }

    /** A check that was not run because the gap it covers is still open (baseline mode); never a pass. */
    private static final class Skipped extends RuntimeException {
        Skipped(String message) {
            super(message, null, false, false);
        }
    }

    private static String skip(String message) {
        throw new Skipped(message);
    }

    /**
     * Runs one check. Anything a check throws is that check's {@code error} problem, Errors included (a Kotlin
     * {@code NotImplementedError}, a {@code StackOverflowError} on deeply nested CBOR), next to whatever it had found
     * by then, so one bad credential cannot take the report down; only a VM failure that leaves nothing to report on
     * propagates.
     */
    static VerificationReport.Check run(String name, Probe probe) {
        Problems problems = new Problems(name);
        String message = null;
        try {
            message = probe.run(problems);
        } catch (Skipped e) {
            return VerificationReport.Check.skipped(name, e.getMessage());
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

    private static String describe(Throwable e) {
        return e.getMessage() == null ? e.getClass().getName() : e.getClass().getSimpleName() + ": " + e.getMessage();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /** A parsed IssuerSigned. Everything the checks share is decoded once, by Multipaz. */
    private static final class Doc {

        private final boolean document;
        private final String documentDocType;
        private final byte[] issuerSignedCbor;
        private final Long issuerAuthTag;
        private final CoseSign1 issuerAuth;
        private final DataItem payload;
        private final DataItem msoItem;
        private final DataItem nameSpacesItem;
        private final IssuerNamespaces namespaces;
        private final List<WireIssuerSignedItems.Item> wireItems;
        private final X509CertChain chain;
        private final List<X509Certificate> certificates;
        private final boolean strict;
        private Optional<MobileSecurityObject> asSent;
        private Optional<MobileSecurityObject> repaired;
        /** Why Multipaz could not read the MSO as sent, or null when it could. */
        private Throwable parseFailure;

        private Doc(boolean document, String documentDocType, byte[] issuerSignedCbor, Long issuerAuthTag,
                    CoseSign1 issuerAuth, DataItem payload, DataItem msoItem, DataItem nameSpacesItem,
                    IssuerNamespaces namespaces, List<WireIssuerSignedItems.Item> wireItems, X509CertChain chain,
                    List<X509Certificate> certificates, boolean strict) {
            this.document = document;
            this.documentDocType = documentDocType;
            this.issuerSignedCbor = issuerSignedCbor;
            this.issuerAuthTag = issuerAuthTag;
            this.issuerAuth = issuerAuth;
            this.payload = payload;
            this.msoItem = msoItem;
            this.nameSpacesItem = nameSpacesItem;
            this.namespaces = namespaces;
            this.wireItems = wireItems;
            this.chain = chain;
            this.certificates = certificates;
            this.strict = strict;
        }

        static Doc parse(byte[] credential, Options options) {
            DataItem top = Cbor.INSTANCE.decode(credential);
            boolean document = top.getMajorType() == MajorType.MAP && top.getOrNull("issuerSigned") != null;
            String documentDocType = null;
            byte[] issuerSignedCbor = credential;
            DataItem issuerSigned = top;
            if (document) {
                // the IssuerSigned exactly as it arrived inside the Document, never a re-encoding
                issuerSignedCbor = WireIssuerSignedItems.valueOf(credential, "issuerSigned");
                issuerSigned = Cbor.INSTANCE.decode(issuerSignedCbor);
                DataItem docType = top.getOrNull("docType");
                documentDocType = docType != null && docType.getMajorType() == MajorType.UNICODE_STRING
                        ? docType.getAsTstr() : null;
            }
            DataItem issuerAuthItem = requirePresent(issuerSigned.getOrNull("issuerAuth"), "issuerSigned.issuerAuth");
            Long issuerAuthTag = null;
            if (issuerAuthItem.getMajorType() == MajorType.TAG) {
                // reported by issuerAuth.untagged; the signature checks still run on the COSE_Sign1 inside
                issuerAuthTag = ((Tagged) issuerAuthItem).getTagNumber();
                issuerAuthItem = issuerAuthItem.getAsTagged();
            }
            CoseSign1 issuerAuth = CoseSign1.Companion.fromDataItem(issuerAuthItem);
            DataItem payload = Cbor.INSTANCE.decode(issuerAuth.getPayload());
            DataItem msoItem = payload.getMajorType() == MajorType.TAG ? payload.getAsTaggedEncodedCbor() : payload;
            DataItem nameSpacesItem = requirePresent(issuerSigned.getOrNull("nameSpaces"), "issuerSigned.nameSpaces");
            IssuerNamespaces namespaces = IssuerNamespaces.Companion.fromDataItem(nameSpacesItem);
            DataItem x5chain = issuerAuth.getUnprotectedHeaders().get(new CoseNumberLabel(LABEL_X5CHAIN));
            if (x5chain == null) {
                x5chain = issuerAuth.getProtectedHeaders().get(new CoseNumberLabel(LABEL_X5CHAIN));
            }
            X509CertChain chain = X509CertChain.Companion.fromDataItem(requirePresent(x5chain, "x5chain (COSE label 33)"));
            require(!chain.getCertificates().isEmpty(), "x5chain has no certificate");
            List<X509Certificate> certificates = X509CertChainJvmKt.getJavaX509Certificates(chain);
            List<WireIssuerSignedItems.Item> wireItems = WireIssuerSignedItems.scan(issuerSignedCbor);
            return new Doc(document, documentDocType, issuerSignedCbor, issuerAuthTag, issuerAuth, payload, msoItem,
                    nameSpacesItem, namespaces, wireItems, chain, certificates, options.strict());
        }

        private static DataItem requirePresent(DataItem item, String name) {
            require(item != null, name + " is missing");
            return item;
        }

        /** Multipaz's {@code MobileSecurityObject} of the MSO exactly as sent, or empty with {@link #parseFailure} set. */
        Optional<MobileSecurityObject> msoAsSent() {
            if (asSent == null) {
                try {
                    asSent = Optional.of(MobileSecurityObject.Companion.fromDataItem(msoItem));
                } catch (Throwable e) {
                    rethrowIfFatal(e);
                    parseFailure = e;
                    asSent = Optional.empty();
                }
            }
            return asSent;
        }

        /**
         * The MSO in Multipaz's model, for the few steps that need the model rather than the wire (the namespace
         * validator against the MSO, the instants Multipaz reads): as sent, or in baseline mode only, after the
         * {@code withTdateTags} repair that lets output predating M-02 (untagged dates, gap G1) be read at all. Strict
         * mode never repairs: the repair would hide exactly the gap strict mode exists to catch.
         */
        Optional<MobileSecurityObject> msoModel() {
            if (msoAsSent().isPresent() || strict) {
                return asSent;
            }
            if (repaired == null) {
                try {
                    repaired = Optional.of(MobileSecurityObject.Companion.fromDataItem(withTdateTags(msoItem)));
                } catch (Throwable e) {
                    rethrowIfFatal(e);
                    repaired = Optional.empty();
                }
            }
            return repaired;
        }

        /** The MSO {@code docType} as sent, or null when it is missing or not a tstr. */
        String wireDocType() {
            DataItem docType = msoItem.getOrNull("docType");
            return docType != null && docType.getMajorType() == MajorType.UNICODE_STRING ? docType.getAsTstr() : null;
        }

        /** The MSO {@code digestAlgorithm} as sent, or null with {@code badAlgorithm} reported. */
        Algorithm digestAlgorithm(Problems problems) {
            DataItem item = msoItem.getOrNull("digestAlgorithm");
            String name = item != null && item.getMajorType() == MajorType.UNICODE_STRING ? item.getAsTstr() : null;
            if ("SHA-256".equals(name)) {
                return Algorithm.SHA256;
            } else if ("SHA-384".equals(name)) {
                return Algorithm.SHA384;
            } else if ("SHA-512".equals(name)) {
                return Algorithm.SHA512;
            }
            problems.add("badAlgorithm", "MSO digestAlgorithm " + (item == null ? "is missing" : shortly(item)
                    + " is not SHA-256, SHA-384 or SHA-512") + " (ISO/IEC 18013-5 9.1.2.5)");
            return null;
        }

        /** The MSO {@code valueDigests} as sent: namespace to digestID to digest. */
        Map<String, Map<Long, byte[]>> wireValueDigests() {
            DataItem valueDigests = msoItem.getOrNull("valueDigests");
            Map<String, Map<Long, byte[]>> declared = new LinkedHashMap<>();
            if (valueDigests == null) {
                return declared;
            }
            for (Map.Entry<DataItem, DataItem> namespace : valueDigests.getAsMap().entrySet()) {
                Map<Long, byte[]> digests = new LinkedHashMap<>();
                for (Map.Entry<DataItem, DataItem> digest : namespace.getValue().getAsMap().entrySet()) {
                    require(digest.getKey().getMajorType() == MajorType.UNSIGNED_INTEGER, "valueDigests "
                            + namespace.getKey() + " carries a digestID that is not a uint: " + shortly(digest.getKey()));
                    require(digests.put(digest.getKey().getAsNumber(), digest.getValue().getAsBstr()) == null,
                            "valueDigests " + namespace.getKey() + " carries digestID " + digest.getKey() + " twice");
                }
                declared.put(namespace.getKey().getAsTstr(), digests);
            }
            return declared;
        }

        /** Rewrites untagged date strings into tag-0 tdate so an old MSO still parses; baseline mode only. */
        private static DataItem withTdateTags(DataItem msoItem) {
            DataItem validity = msoItem.getOrNull("validityInfo");
            if (validity == null) {
                return msoItem;
            }
            Map<DataItem, DataItem> dates = new LinkedHashMap<>(validity.getAsMap());
            boolean changed = false;
            for (Map.Entry<DataItem, DataItem> entry : dates.entrySet()) {
                if (entry.getValue().getMajorType() == MajorType.UNICODE_STRING) {
                    dates.put(entry.getKey(), new Tagged(Tagged.DATE_TIME_STRING, entry.getValue()));
                    changed = true;
                }
            }
            if (!changed) {
                return msoItem;
            }
            Map<DataItem, DataItem> mso = new LinkedHashMap<>(msoItem.getAsMap());
            mso.put(new Tstr("validityInfo"), new CborMap(dates, false));
            return new CborMap(mso, false);
        }

        /** Check 0: the credential is the bare IssuerSigned, not the draft-13 Document around it. */
        String shape(Problems problems) {
            if (document) {
                problems.add("documentWrapper", "the credential is a Document {docType, issuerSigned} (the draft-13 "
                        + "0.14.0 shape), not the bare IssuerSigned of ISO/IEC 18013-5 8.3.2.1.2.2 that OpenID4VCI "
                        + "Appendix A.2 returns as the mso_mdoc credential");
            }
            return "the credential is a bare IssuerSigned";
        }

        /** Check 0b: IssuerAuth is the untagged COSE_Sign1 (ISO/IEC 18013-5 9.1.2.4; RFC 9052 4.2 tags it only as #6.18). */
        String untagged(Problems problems) {
            if (issuerAuthTag != null) {
                problems.add("tagged", "IssuerAuth carries CBOR tag " + issuerAuthTag
                        + (issuerAuthTag == 18 ? " (COSE_Sign1_Tagged)" : "") + "; ISO/IEC 18013-5 9.1.2.4 defines "
                        + "IssuerAuth = COSE_Sign1, the untagged form (RFC 9052 4.2)");
            }
            return "IssuerAuth is an untagged COSE_Sign1";
        }

        /** Check 1a: Multipaz verifies the COSE_Sign1 against the x5chain leaf. */
        String signatureWithMultipaz(Problems problems) {
            DataItem alg = issuerAuth.getProtectedHeaders().get(new CoseNumberLabel(LABEL_ALG));
            if (alg == null) {
                problems.add("noAlg", "COSE protected header has no alg (label 1)");
                return null;
            }
            Algorithm algorithm;
            try {
                algorithm = Algorithm.Companion.fromCoseAlgorithmIdentifier((int) alg.getAsNumber());
            } catch (RuntimeException e) {
                algorithm = Algorithm.UNSET;
            }
            if (algorithm == Algorithm.UNSET) {
                problems.add("unsupportedAlg", "unsupported COSE alg " + shortly(alg));
                return null;
            }
            X509Cert leaf = chain.getCertificates().get(0);
            Algorithm checked = algorithm;
            try {
                await(continuation -> Cose.INSTANCE.coseSign1Check(leaf.getPublicKey(), null, issuerAuth, checked, continuation));
            } catch (Throwable e) {
                rethrowIfFatal(e);
                problems.add("invalid", "Multipaz coseSign1Check rejects the signature: " + describe(e));
                return null;
            }
            return "verified " + algorithm + " over Sig_structure with the x5chain leaf " + certificates.get(0).getSubjectX500Principal();
        }

        /**
         * Check 1b: Authlete's independent decode and COSEVerifier agree on the same IssuerAuth. Authlete gets the
         * CBOR item tree, so a tag-18 COSE_Sign1 (the draft-13 Document) is unwrapped here rather than re-encoded.
         */
        String signatureWithAuthlete(Problems problems) throws Exception {
            CBORItem parsed = new CBORDecoder(issuerSignedCbor).next();
            CBORPair pair = parsed instanceof CBORPairList map ? map.findByKey("issuerAuth") : null;
            if (pair == null) {
                problems.add("notCoseSign1", "Authlete finds no issuerAuth in the IssuerSigned map");
                return null;
            }
            CBORItem issuerAuthItem = pair.getValue();
            if (issuerAuthItem instanceof CBORTaggedItem tagged) {
                if (tagged.getTagNumber().longValue() != 18) {
                    problems.add("notCoseSign1", "issuerAuth carries tag " + tagged.getTagNumber() + ", not COSE_Sign1 (18)");
                    return null;
                }
                issuerAuthItem = tagged.getTagContent();
            }
            COSESign1 coseSign1;
            try {
                coseSign1 = COSESign1.build(issuerAuthItem);
            } catch (Exception e) {
                problems.add("notCoseSign1", "Authlete cannot read IssuerAuth as COSE_Sign1: " + describe(e));
                return null;
            }
            List<X509Certificate> authleteChain = coseSign1.getUnprotectedHeader() == null ? null
                    : coseSign1.getUnprotectedHeader().getX5Chain();
            if (authleteChain == null || authleteChain.isEmpty()) {
                authleteChain = coseSign1.getProtectedHeader().getX5Chain();
            }
            if (authleteChain == null || authleteChain.isEmpty()) {
                problems.add("noX5chain", "Authlete finds no x5chain in IssuerAuth");
                return null;
            }
            X509Certificate leaf = authleteChain.get(0);
            boolean valid;
            try {
                valid = new COSEVerifier(leaf.getPublicKey()).verify(coseSign1);
            } catch (Exception e) {
                problems.add("invalid", "Authlete COSEVerifier fails: " + describe(e));
                return null;
            }
            if (!valid) {
                problems.add("invalid", "Authlete COSEVerifier rejects the IssuerAuth signature");
            }
            return "verified with Authlete COSEVerifier against " + leaf.getSubjectX500Principal();
        }

        /** Check 2: the MSO payload is tag 24 over the encoded MSO (ISO/IEC 18013-5 9.1.2.4). */
        String msoPayloadIsTag24(Problems problems) {
            boolean tagged = payload.getMajorType() == MajorType.TAG
                    && ((Tagged) payload).getTagNumber() == Tagged.ENCODED_CBOR
                    && ((Tagged) payload).getTaggedItem().getMajorType() == MajorType.BYTE_STRING;
            if (!tagged) {
                if (!strict) {
                    skip("the MSO payload is not tag 24 today (fixed by M-02)");
                }
                problems.add("notTag24", "the MSO payload is not #6.24(bstr .cbor MobileSecurityObject) (ISO/IEC 18013-5 9.1.2.4)");
            }
            return "the MSO payload is tag 24 over the encoded MSO";
        }

        /**
         * Check 2b: Multipaz's {@code MobileSecurityObject} model accepts the MSO as sent. A Multipaz-based wallet
         * reads a credential through exactly this parser, so a refusal (for example its {@code signed <= validFrom}
         * requirement) means such a wallet cannot use the credential at all. Baseline mode reports an MSO that only
         * the untagged-date repair makes readable as skipped (gap G1); anything else is a failure.
         */
        String msoParses(Problems problems) {
            if (msoAsSent().isPresent()) {
                return "Multipaz MobileSecurityObject.fromDataItem accepts the MSO as sent";
            }
            String cause = describe(parseFailure);
            if (!strict && msoModel().isPresent()) {
                skip("Multipaz reads the MSO only after untagged dates are tagged (gap G1, fixed by M-02): " + cause);
            }
            problems.add("refused", "Multipaz MobileSecurityObject.fromDataItem refuses the MSO as sent (" + cause
                    + "): a Multipaz-based wallet cannot read this credential; mso.validityInfo and "
                    + "mso.validityInfo.tdateTags name the rule it breaks");
            return null;
        }

        /**
         * Check 3: the namespaces as received: not empty, no empty namespace, every namespace in valueDigests, no
         * elementIdentifier twice (the same rules as {@code verify_mdoc.py}); then Multipaz's own validator, on the
         * namespaces and against the MSO, as a second opinion with its own codes. Its warnings are reported.
         */
        String namespacesValidate(Problems problems) {
            Map<DataItem, DataItem> wire = nameSpacesItem.getAsMap();
            if (wire.isEmpty()) {
                problems.add("empty", "IssuerSigned.nameSpaces is empty: there is nothing to verify");
            }
            DataItem valueDigests = msoItem.getOrNull("valueDigests");
            Set<String> digested = new HashSet<>();
            if (valueDigests != null && valueDigests.getMajorType() == MajorType.MAP) {
                valueDigests.getAsMap().keySet().stream().filter(k -> k.getMajorType() == MajorType.UNICODE_STRING)
                        .forEach(k -> digested.add(k.getAsTstr()));
            }
            for (Map.Entry<DataItem, DataItem> namespace : wire.entrySet()) {
                String name = namespace.getKey().getAsTstr();
                if (namespace.getValue().getAsArray().isEmpty()) {
                    problems.add("emptyNamespace:" + parameter(name), "namespace " + name + " carries no IssuerSignedItem");
                }
                if (!digested.contains(name)) {
                    problems.add("noValueDigests:" + parameter(name), "namespace " + name
                            + " is in nameSpaces but has no valueDigests entry in the MSO");
                }
            }
            Map<String, Set<String>> identifiers = new LinkedHashMap<>();
            for (WireIssuerSignedItems.Item item : wireItems) {
                if (!identifiers.computeIfAbsent(item.namespace(), k -> new HashSet<>()).add(item.identifier())) {
                    problems.add("duplicateIdentifier:" + parameter(item.namespace() + "/" + item.identifier()),
                            "elementIdentifier " + item.identifier() + " repeats in " + item.namespace());
                }
            }
            ValidationResult structural = IssuerNamespaces.Companion.validate(nameSpacesItem);
            if (structural.getHasErrors()) {
                problems.add("multipazStructural", "Multipaz IssuerNamespaces.validate: " + findings(structural));
            }
            Optional<MobileSecurityObject> model = msoModel();
            if (model.isEmpty()) {
                // validateAgainstMso needs Multipaz's MSO model, which mso.parse reports as refused; what it would
                // compare (a digest table per namespace, a digest per item) is mso.valueDigests, read from the wire
                return "Multipaz validates " + namespaces.getData().size() + " namespace(s); validateAgainstMso not run "
                        + "(no MSO model, see mso.parse), its comparison is mso.valueDigests" + warnings(structural);
            }
            ValidationResult againstMso = await(c -> namespaces.validateAgainstMso(model.get(), c));
            if (againstMso.getHasErrors()) {
                problems.add("multipazAgainstMso", "Multipaz IssuerNamespaces.validateAgainstMso: " + findings(againstMso));
            }
            return "Multipaz validates " + namespaces.getData().size() + " namespace(s)" + warnings(structural) + warnings(againstMso);
        }

        /**
         * Check 4: every IssuerSignedItem digest equals its valueDigests entry under the declared algorithm. The hash
         * is taken over the bytes as received (9.1.2.5), not over a re-encoding of the parsed item, and every
         * {@code #6.24} head must be the preferred encoding, because a verifier that re-encodes would hash other bytes.
         */
        String digestsMatchValueDigests(Problems problems) {
            Algorithm digestAlgorithm = digestAlgorithm(problems);
            Map<String, Map<Long, byte[]>> declared = wireValueDigests();
            if (declared.isEmpty()) {
                problems.add("empty", "MSO valueDigests is missing or empty");
            }
            if (wireItems.isEmpty()) {
                problems.add("noItems", "IssuerSigned carries no IssuerSignedItem");
            }
            int verified = 0;
            for (WireIssuerSignedItems.Item item : wireItems) {
                String name = item.namespace() + "/" + item.identifier();
                if (!preferredTag24Head(item.raw())) {
                    problems.add("nonPreferredHead:" + parameter(name), name + " has a non-preferred #6.24 head: a "
                            + "verifier that re-encodes hashes other bytes than the issuer did");
                }
                Map<Long, byte[]> namespace = declared.get(item.namespace());
                if (namespace == null) {
                    problems.add("noNamespace:" + parameter(item.namespace()), "nameSpaces carries " + item.namespace()
                            + " but valueDigests has no such namespace");
                    continue;
                }
                byte[] expected = namespace.get(item.digestId());
                if (expected == null) {
                    problems.add("noEntry:" + parameter(name), "no valueDigests entry for " + name + " digestID " + item.digestId());
                    continue;
                }
                if (digestAlgorithm == null) {
                    continue;
                }
                byte[] actual = await(c -> Crypto.INSTANCE.digest(digestAlgorithm, item.raw(), c));
                if (Arrays.equals(expected, actual)) {
                    verified++;
                } else {
                    problems.add("mismatch:" + parameter(name), "digest mismatch for " + name + " digestID "
                            + item.digestId() + ": the received tag-24 bytes do not hash to the declared digest");
                }
            }
            int parsed = namespaces.getData().values().stream().mapToInt(Map::size).sum();
            if (wireItems.size() != parsed) {
                problems.add("duplicateHidden", "the wire carries " + wireItems.size() + " IssuerSignedItems but only "
                        + parsed + " distinct (namespace, elementIdentifier) pairs: a duplicate hides an item from every check");
            }
            return verified + " IssuerSignedItems match valueDigests under " + digestAlgorithm + " (hashed over the received bytes)";
        }

        /**
         * Check 5, second opinion: Multipaz's {@code IssuerSignedItem.calculateDigest} agrees with valueDigests. It
         * re-encodes, so a non-preferred encoding passes here and fails {@link #digestsMatchValueDigests} — which is
         * why it is not the primary oracle. It still catches a valueDigests table that is wrong for the parsed item.
         */
        String calculateDigestAgrees(Problems problems) {
            Algorithm digestAlgorithm = digestAlgorithm(problems);
            if (digestAlgorithm == null) {
                return null;
            }
            Map<String, Map<Long, byte[]>> declared = wireValueDigests();
            int verified = 0;
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    String name = namespace.getKey() + "/" + item.getDataElementIdentifier();
                    Map<Long, byte[]> namespaceDigests = declared.get(namespace.getKey());
                    byte[] expected = namespaceDigests == null ? null : namespaceDigests.get(item.getDigestId());
                    if (expected == null) {
                        problems.add("noEntry:" + parameter(name), "no valueDigests entry for " + name + " digestID " + item.getDigestId());
                        continue;
                    }
                    ByteString digest = await(c -> item.calculateDigest(digestAlgorithm, c));
                    if (Arrays.equals(expected, bytes(digest))) {
                        verified++;
                    } else {
                        problems.add("mismatch:" + parameter(name), "re-encoded digest mismatch for " + name
                                + " digestID " + item.getDigestId());
                    }
                }
            }
            return verified + " IssuerSignedItems match valueDigests when Multipaz re-encodes them";
        }

        /** Check 6: digestIDs are unique within each namespace (ISO/IEC 18013-5 9.1.2.5). */
        String digestIdsAreUnique(Problems problems) {
            // the wire, in order: two items sharing a digestID make the valueDigests entry ambiguous
            Map<String, Set<Long>> seen = new LinkedHashMap<>();
            for (WireIssuerSignedItems.Item item : wireItems) {
                if (!seen.computeIfAbsent(item.namespace(), k -> new HashSet<>()).add(item.digestId())) {
                    problems.add("duplicate:" + parameter(item.namespace() + "/" + item.digestId()), "duplicate digestID "
                            + item.digestId() + " in namespace " + item.namespace() + " (" + item.identifier() + ")");
                }
            }
            // second opinion: Multipaz collapses duplicates by identifier, so check what it did keep too
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                Set<Long> parsed = new HashSet<>();
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    if (!parsed.add(item.getDigestId())) {
                        problems.add("duplicate:" + parameter(namespace.getKey() + "/" + item.getDigestId()),
                                "duplicate digestID " + item.getDigestId() + " in namespace " + namespace.getKey());
                    }
                }
            }
            return "digestIDs unique per namespace";
        }

        /**
         * Check 7: the MSO deviceKey is the holder key the proof carried: EC2 P-256/384/521 by x and y, OKP Ed25519 by
         * x alone (kty 1, crv 6, no y). The COSE labels as sent and Multipaz's parse must both agree, and a COSE_Key
         * that carries the private key ({@code d}, label -4) fails whatever else it says.
         */
        String deviceKey(Problems problems, JWK expectedHolderKey) {
            if (expectedHolderKey == null) {
                problems.add("noHolder", "no expected holder key supplied");
                return null;
            }
            ExpectedKey expected;
            try {
                expected = ExpectedKey.of(expectedHolderKey);
            } catch (AssertionError e) {
                problems.add("unsupportedHolder", e.getMessage());
                return null;
            }
            DataItem deviceKeyInfo = msoItem.getOrNull("deviceKeyInfo");
            DataItem deviceKey = deviceKeyInfo == null || deviceKeyInfo.getMajorType() != MajorType.MAP ? null
                    : deviceKeyInfo.getOrNull("deviceKey");
            if (deviceKey == null || deviceKey.getMajorType() != MajorType.MAP || deviceKey.getAsMap().isEmpty()) {
                problems.add("missing", "MSO deviceKeyInfo.deviceKey is missing or not a COSE_Key map");
                return null;
            }
            Map<DataItem, DataItem> cose = deviceKey.getAsMap();
            if (numeric(cose, COSE_KEY_D) != null) {
                problems.add("privateKey", "the MSO deviceKey carries a private key (COSE_Key label -4, d)");
            }
            if (!Objects.equals((long) expected.kty, integer(numeric(cose, 1)))) {
                problems.add("kty", "deviceKey kty is not " + expected.ktyName + " (" + expected.kty + ")");
            }
            if (!Objects.equals(expected.crv, integer(numeric(cose, -1)))) {
                problems.add("crv", "deviceKey crv is not " + expected.crvName + " (" + expected.crv + ")");
            }
            if (!Arrays.equals(expected.x, bstr(numeric(cose, -2)))) {
                problems.add("x", "deviceKey x does not match the holder key");
            }
            if (expected.y != null && !Arrays.equals(expected.y, bstr(numeric(cose, -3)))) {
                problems.add("y", "deviceKey y does not match the holder key");
            }
            if (expected.y == null && numeric(cose, -3) != null) {
                problems.add("yOnOkp", "OKP deviceKey carries a y coordinate (label -3)");
            }
            // second opinion: Multipaz's own COSE_Key parse names the same key
            try {
                EcPublicKey parsed = CoseKey.Companion.fromDataItem(deviceKey).getEcPublicKey();
                if (!expected.matches(parsed)) {
                    problems.add("multipazMismatch", "Multipaz reads the deviceKey as " + parsed.getCurve() + " " + parsed
                            + ", expected " + expected.crvName + " x=" + Base64Url.of(expected.x));
                }
            } catch (Throwable e) {
                rethrowIfFatal(e);
                problems.add("multipazUnreadable", "Multipaz CoseKey cannot read the deviceKey: " + describe(e));
            }
            return "deviceKey equals the " + expected.crvName + " holder key (Multipaz CoseKey and the wire labels agree)";
        }

        /** Check 8: the MSO docType is the configured one, and a draft-13 Document says the same. */
        String docType(Problems problems, String expectedDocType) {
            String docType = wireDocType();
            if (docType == null) {
                problems.add("missing", "MSO docType is missing or not a tstr");
            } else if (!expectedDocType.equals(docType)) {
                problems.add("mismatch", "MSO docType is " + docType + ", expected " + expectedDocType);
            }
            if (document && !Objects.equals(documentDocType, docType)) {
                problems.add("documentMismatch", "the Document's docType " + documentDocType + " is not the MSO's " + docType);
            }
            return "docType " + expectedDocType;
        }

        /**
         * Check 9: the validity window, ordered from the dates <em>as sent</em> (tagged or not, any precision), so a
         * repaired parse in baseline mode cannot decide it: {@code signed <= validFrom < validUntil},
         * {@code validFrom <= expectedUpdate < validUntil} when present, and {@code at} inside
         * {@code validFrom..validUntil} (ISO/IEC 18013-5 9.1.2.4). Every rule is evaluated, so an accepted
         * {@code signedAfterValidFrom} cannot hide {@code expired}. Multipaz must read the same instants, and its own MSO
         * validator runs as a second opinion when it can read the MSO as sent; its findings map onto the same codes.
         */
        String validityInfo(Problems problems, Instant at) {
            DataItem validity = msoItem.getOrNull("validityInfo");
            if (validity == null || validity.getMajorType() != MajorType.MAP) {
                problems.add("missing:validityInfo", "MSO validityInfo is missing or not a map");
                return null;
            }
            Instant signed = wireInstant(validity, "signed", true, problems);
            Instant validFrom = wireInstant(validity, "validFrom", true, problems);
            Instant validUntil = wireInstant(validity, "validUntil", true, problems);
            Instant expectedUpdate = wireInstant(validity, "expectedUpdate", false, problems);
            if (signed != null && validFrom != null && signed.isAfter(validFrom)) {
                problems.add("signedAfterValidFrom", "signed " + signed + " is after validFrom " + validFrom + " (ISO/IEC 18013-5 9.1.2.4)");
            }
            if (validFrom != null && validUntil != null && !validFrom.isBefore(validUntil)) {
                problems.add("validFromNotBeforeValidUntil", "validFrom " + validFrom + " is not before validUntil " + validUntil);
            }
            if (expectedUpdate != null && validFrom != null && expectedUpdate.isBefore(validFrom)) {
                problems.add("expectedUpdateBeforeValidFrom", "expectedUpdate " + expectedUpdate + " is before validFrom "
                        + validFrom + " (ISO/IEC 18013-5 9.1.2.4)");
            }
            if (expectedUpdate != null && validUntil != null && !expectedUpdate.isBefore(validUntil)) {
                problems.add("expectedUpdateNotBeforeValidUntil", "expectedUpdate " + expectedUpdate
                        + " is not before validUntil " + validUntil);
            }
            if (validFrom != null && validFrom.isAfter(at)) {
                problems.add("notYetValid", "validFrom " + validFrom + " is in the future (at " + at + ")");
            }
            if (validUntil != null && at.isAfter(validUntil)) {
                problems.add("expired", "validUntil " + validUntil + " has passed (at " + at + ")");
            }

            Optional<MobileSecurityObject> model = msoModel();
            if (model.isPresent()) {
                sameInstant(problems, "signed", signed, model.get().getSignedAt());
                sameInstant(problems, "validFrom", validFrom, model.get().getValidFrom());
                sameInstant(problems, "validUntil", validUntil, model.get().getValidUntil());
                sameInstant(problems, "expectedUpdate", expectedUpdate, model.get().getExpectedUpdate());
            }
            String window = "signed " + signed + " within " + validFrom + ".." + validUntil
                    + (expectedUpdate == null ? "" : ", expectedUpdate " + expectedUpdate);
            if (msoAsSent().isEmpty()) {
                // Multipaz cannot read the MSO as sent: mso.parse reports that, and the window decision falls to the
                // wire rules above
                return window + "; Multipaz's own MSO validation not run: it cannot read the MSO as sent (mso.parse)";
            }
            ValidationResult multipaz = MobileSecurityObject.Companion.validate(msoItem, kotlinInstant(at));
            for (ValidationFinding finding : multipaz.getErrors()) {
                String code = multipazValidityCode(finding.getMessage());
                if (code != null) {
                    problems.add(code, "Multipaz MobileSecurityObject.validate: " + finding.getMessage());
                }
            }
            return window + warnings(multipaz);
        }

        /**
         * Check 10: the wire dates. Each of {@code signed}, {@code validFrom}, {@code validUntil} and
         * {@code expectedUpdate} (when present) must be CBOR tag 0 over an RFC 3339 tstr with whole seconds and
         * {@code Z} (ISO/IEC 18013-5 9.1.2.4, gap G1); every field and every way it misses is its own code. Multipaz's
         * fractional-seconds findings are the second opinion on the precision half. Baseline mode reports the gap as
         * skipped, never as a pass.
         */
        String tdateTags(Problems problems, boolean strictTdate) {
            DataItem validity = msoItem.getOrNull("validityInfo");
            if (validity == null || validity.getMajorType() != MajorType.MAP) {
                problems.add("missing:validityInfo", "MSO validityInfo is missing or not a map");
                return null;
            }
            List<VerificationReport.Problem> found = new ArrayList<>();
            for (String field : VALIDITY_FIELDS) {
                DataItem item = validity.getOrNull(field);
                if (item == null) {
                    if (!"expectedUpdate".equals(field)) { // optional in ISO/IEC 18013-5 9.1.2.4
                        found.add(new VerificationReport.Problem("missing:" + field, "validityInfo." + field + " is missing"));
                    }
                    continue;
                }
                tdateProblems(item).forEach(problem -> found.add(new VerificationReport.Problem(
                        problem.code() + ":" + field, field + " " + problem.message() + " (ISO/IEC 18013-5 9.1.2.4)")));
            }
            if (msoAsSent().isPresent()) {
                for (ValidationFinding finding : MobileSecurityObject.Companion.validate(msoItem, kotlinInstant(Instant.now())).getErrors()) {
                    Matcher fractional = MULTIPAZ_FRACTIONAL.matcher(finding.getMessage());
                    if (fractional.matches()) {
                        found.add(new VerificationReport.Problem("fractionalSeconds:" + fractional.group(1),
                                "Multipaz MobileSecurityObject.validate: " + finding.getMessage()));
                    }
                }
            }
            if (!found.isEmpty() && !strictTdate) {
                skip("tdate gap: " + found + " (fixed by M-02)");
            }
            found.forEach(problem -> problems.add(problem.code(), problem.message()));
            return "validityInfo dates are tag-0 whole-second tdate";
        }

        /**
         * Check 11: the x5chain validates to the supplied IACA. The rules both verifiers apply (each certificate
         * issued by the next, the last by the IACA, all valid at {@code at}) come first; the JDK PKIX validator and
         * Multipaz's chain validation follow as second opinions with their own codes. Strict mode without an IACA
         * cannot make the decision and fails rather than skipping.
         */
        String chainToIaca(Problems problems, Optional<X509Certificate> iaca, Instant at, boolean strict) {
            if (iaca.isEmpty()) {
                if (!strict) {
                    skip("no IACA supplied: chain-to-anchor not verified");
                }
                problems.add("noAnchorSupplied", "no IACA supplied: the chain-to-anchor decision cannot be made");
                return null;
            }
            X509Certificate anchor = iaca.get();
            List<X509Certificate> path = new ArrayList<>(certificates);
            if (path.get(path.size() - 1).equals(anchor)) {
                path.remove(path.size() - 1);
            }
            if (path.isEmpty()) {
                problems.add("onlyAnchor", "x5chain carries only the IACA");
                return null;
            }
            for (int i = 0; i + 1 < path.size(); i++) {
                if (!issuedBy(path.get(i), path.get(i + 1))) {
                    problems.add("notIssuedBy:" + i, "x5chain certificate " + i + " is not issued by certificate " + (i + 1));
                }
            }
            if (!issuedBy(path.get(path.size() - 1), anchor)) {
                problems.add("notAnchored", path.get(path.size() - 1).getSubjectX500Principal() + " is not issued by the IACA "
                        + anchor.getSubjectX500Principal());
            }
            for (int i = 0; i < path.size(); i++) {
                if (!validAt(path.get(i), at)) {
                    problems.add("notValidAt:" + i, path.get(i).getSubjectX500Principal() + " is not valid at " + at);
                }
            }
            if (!validAt(anchor, at)) {
                problems.add("notValidAt:anchor", "the IACA " + anchor.getSubjectX500Principal() + " is not valid at " + at);
            }
            try {
                PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
                parameters.setRevocationEnabled(false);
                parameters.setDate(Date.from(at));
                CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509")
                        .generateCertPath(new ArrayList<java.security.cert.Certificate>(path)), parameters);
            } catch (CertPathValidatorException e) {
                problems.add("pkix:" + e.getReason(), "JDK PKIX: " + describe(e));
            } catch (GeneralSecurityException e) {
                problems.add("pkix:UNSPECIFIED", "JDK PKIX: " + describe(e));
            }
            try {
                await(continuation -> chain.validate(kotlinInstant(at), true, true, true, continuation));
            } catch (Throwable e) {
                rethrowIfFatal(e);
                problems.add("multipaz", "Multipaz X509CertChain.validate: " + describe(e));
            }
            return "x5chain validates to " + anchor.getSubjectX500Principal() + " at " + at;
        }

        /** Check 12: no certificate in the x5chain is self-signed (HAIP: the trust anchor stays out of the chain). */
        String noSelfSignedInChain(Problems problems, boolean required) {
            if (!required) {
                skip("x5chain may carry a self-signed certificate today (gap G9, HAIP; fixed by M-02)");
            }
            for (int i = 0; i < certificates.size(); i++) {
                X509Certificate certificate = certificates.get(i);
                if (issuedBy(certificate, certificate)) {
                    problems.add("selfSigned:" + i, "x5chain certificate " + i + " (" + certificate.getSubjectX500Principal()
                            + ") is self-signed (HAIP: the IACA must not be in x5chain)");
                }
            }
            return "no self-signed certificate in x5chain";
        }

        /** Check 13: every x5chain certificate serial is a positive integer of at most 20 octets (RFC 5280 4.1.2.2). */
        String serialNumbers(Problems problems) {
            serialNumberProblems(certificates).forEach(problem -> problems.add(problem.code(), problem.message()));
            return certificates.size() + " x5chain certificate serial(s) positive and at most " + MAX_SERIAL_OCTETS + " octets";
        }

        /** Check 14: element types and mandatory elements of the mDL namespace (ISO/IEC 18013-5 7.2.1 Table 5). */
        String mdlElementTypes(Problems problems, boolean required) {
            if (!required) {
                skip("element types are not enforced today (gap G2; enabled by M-03)");
            }
            if (!MDL_DOCTYPE.equals(wireDocType())) {
                skip("docType " + wireDocType() + " is not an mDL: there are no mDL element types to check");
            }
            Map<String, IssuerSignedItem> items = namespaces.getData().get(MDL_NAMESPACE);
            if (items == null) {
                problems.add("noNamespace", "IssuerSigned has no namespace " + MDL_NAMESPACE);
                return null;
            }
            Map<String, DataItem> elements = new LinkedHashMap<>();
            items.forEach((identifier, item) -> elements.put(identifier, item.getDataElementValue()));
            mdlElementProblems(elements).forEach(problem -> problems.add(problem.code(), problem.message()));
            return elements.size() + " elements typed against ISO/IEC 18013-5 Table 5 (Multipaz DrivingLicense)";
        }
    }

    /** Maps a Multipaz MSO validation error onto the window codes; null for the tdate precision findings. */
    static String multipazValidityCode(String message) {
        if (MULTIPAZ_FRACTIONAL.matcher(message).matches()) {
            return null; // mso.validityInfo.tdateTags owns precision
        } else if (message.contains("must be equal to or later than signed")) {
            return "signedAfterValidFrom";
        } else if (message.startsWith("MSO expectedUpdate") && message.contains("cannot be earlier than validFrom")) {
            return "expectedUpdateBeforeValidFrom";
        } else if (message.startsWith("MSO expectedUpdate") && message.contains("is later than validUntil")) {
            return "expectedUpdateNotBeforeValidUntil";
        } else if (message.startsWith("MSO validUntil") && message.contains("must be later than validFrom")) {
            return "validFromNotBeforeValidUntil";
        } else if (message.startsWith("MSO is not yet valid")) {
            return "notYetValid";
        } else if (message.startsWith("MSO is expired")) {
            return "expired";
        }
        return "multipazRejects";
    }

    /** True when {@code certificate} names {@code issuer} as its issuer and verifies under its key. */
    private static boolean issuedBy(X509Certificate certificate, X509Certificate issuer) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean validAt(X509Certificate certificate, Instant at) {
        Date date = Date.from(at);
        return !date.before(certificate.getNotBefore()) && !date.after(certificate.getNotAfter());
    }

    /**
     * Problems with the x5chain serial numbers (RFC 5280 4.1.2.2): {@code nonPositive} for a serial that is not
     * positive, {@code zero} in addition for 0, {@code tooLong} for more than 20 DER content octets. A gap that
     * accepts keymanager's negative serials ({@code nonPositive}, G27) therefore cannot cover a zero or an overlong one.
     */
    static List<VerificationReport.Problem> serialNumberProblems(List<X509Certificate> certificates) {
        List<VerificationReport.Problem> problems = new ArrayList<>();
        for (int i = 0; i < certificates.size(); i++) {
            BigInteger serial = certificates.get(i).getSerialNumber();
            String subject = "x5chain certificate " + i + " (" + certificates.get(i).getSubjectX500Principal() + ")";
            if (serial.signum() <= 0) {
                problems.add(new VerificationReport.Problem("nonPositive", subject + " has the non-positive serial " + serial));
            }
            if (serial.signum() == 0) {
                problems.add(new VerificationReport.Problem("zero", subject + " has the serial 0"));
            }
            int octets = serial.toByteArray().length; // minimal two's complement: the DER INTEGER content octets
            if (octets > MAX_SERIAL_OCTETS) {
                problems.add(new VerificationReport.Problem("tooLong", subject + " has a serial of " + octets
                        + " octets, more than " + MAX_SERIAL_OCTETS));
            }
        }
        return problems;
    }

    /**
     * Problems with the elements of namespace {@code org.iso.18013.5.1}, each under its own code: {@code missing:<id>}
     * for a Table 5 mandatory element that is absent, {@code untyped:<id>} for a value of the wrong CBOR type,
     * {@code notInDocType:<id>} for an element outside the mDL document type, {@code unmodelled:<id>} for a type this
     * harness does not model. Every problem is reported, not the first. Types come from Multipaz's
     * {@code DrivingLicense}, except where Table 5 says otherwise (see {@link #TDATE_OR_FULL_DATE}).
     */
    static List<VerificationReport.Problem> mdlElementProblems(Map<String, DataItem> elements) {
        MdocNamespace namespace = DrivingLicense.INSTANCE.getDocumentType("en-US").getMdocDocumentType()
                .getNamespaces().get(MDL_NAMESPACE);
        require(namespace != null, "Multipaz DrivingLicense has no namespace " + MDL_NAMESPACE);
        List<VerificationReport.Problem> problems = new ArrayList<>();
        for (Map.Entry<String, MdocDataElement> expected : namespace.getDataElements().entrySet()) {
            String identifier = expected.getKey();
            DataItem value = elements.get(identifier);
            if (value == null) {
                if (expected.getValue().getMandatory()) {
                    problems.add(new VerificationReport.Problem("missing:" + parameter(identifier), "mandatory mDL element "
                            + identifier + " is missing (ISO/IEC 18013-5 7.2.1 Table 5)"));
                }
                continue;
            }
            problems.addAll(typeProblems(identifier, expected.getValue().getAttribute(), value));
        }
        for (String identifier : elements.keySet()) {
            if (!namespace.getDataElements().containsKey(identifier)) {
                problems.add(new VerificationReport.Problem("notInDocType:" + parameter(identifier), "element "
                        + identifier + " is not in the " + MDL_DOCTYPE + " document type"));
            }
        }
        return problems;
    }

    private static List<VerificationReport.Problem> typeProblems(String identifier, DocumentAttribute attribute, DataItem value) {
        String untyped = "untyped:" + parameter(identifier);
        String actual = shortly(value);
        String problem;
        if (TDATE_OR_FULL_DATE.contains(identifier)) {
            String asDate = fullDateProblem(value);
            String asTdate = tdateProblem(value);
            problem = asDate == null || asTdate == null ? null : identifier + " must be full-date or tdate (Table 5): as "
                    + "full-date it " + asDate + ", as tdate it " + asTdate;
        } else if (TDATE_ONLY.contains(identifier)) {
            String tdate = tdateProblem(value);
            problem = tdate == null ? null : identifier + " must be tdate (Table 5): it " + tdate;
        } else if (DRIVING_PRIVILEGES.equals(identifier)) {
            return drivingPrivilegesProblems(value).stream().map(p -> new VerificationReport.Problem(untyped, p)).toList();
        } else {
            DocumentAttributeType type = attribute.getType();
            if (type instanceof DocumentAttributeType.String || type instanceof DocumentAttributeType.StringOptions) {
                problem = value.getMajorType() == MajorType.UNICODE_STRING ? null : identifier + " must be a tstr, is " + actual;
            } else if (type instanceof DocumentAttributeType.Number || type instanceof DocumentAttributeType.IntegerOptions) {
                problem = value.getMajorType() == MajorType.UNSIGNED_INTEGER ? null
                        : identifier + " must be a non-negative uint, is " + actual;
            } else if (type instanceof DocumentAttributeType.Boolean) {
                boolean bool = value.getMajorType() == MajorType.SPECIAL && isBoolean(value);
                problem = bool ? null : identifier + " must be true or false, is " + actual;
            } else if (type instanceof DocumentAttributeType.Date) {
                String date = fullDateProblem(value);
                problem = date == null ? null : identifier + " must be full-date: it " + date;
            } else if (type instanceof DocumentAttributeType.DateTime) {
                String tdate = tdateProblem(value);
                problem = tdate == null ? null : identifier + " must be tdate: it " + tdate;
            } else if (type instanceof DocumentAttributeType.Picture || type instanceof DocumentAttributeType.Blob) {
                problem = value.getMajorType() == MajorType.BYTE_STRING ? null : identifier + " must be a bstr, is " + actual;
            } else {
                return List.of(new VerificationReport.Problem("unmodelled:" + parameter(identifier), identifier + " is typed "
                        + type.getClass().getSimpleName() + ", which this harness does not model: an unknown element "
                        + "type fails rather than guesses"));
            }
        }
        return problem == null ? List.of() : List.of(new VerificationReport.Problem(untyped, problem));
    }

    /**
     * ISO/IEC 18013-5 7.2.4: {@code [+ {vehicle_category_code: tstr, ? issue_date: full-date,
     * ? expiry_date: full-date, ? codes: [+ {code: tstr, ? sign: tstr, ? value: tstr}]}]}.
     */
    private static List<String> drivingPrivilegesProblems(DataItem value) {
        List<String> problems = new ArrayList<>();
        if (value.getMajorType() != MajorType.ARRAY || value.getAsArray().isEmpty()) {
            problems.add(DRIVING_PRIVILEGES + " must be a non-empty array of maps (7.2.4), is " + shortly(value));
            return problems;
        }
        int index = 0;
        for (DataItem privilege : value.getAsArray()) {
            String at = DRIVING_PRIVILEGES + "[" + index++ + "]";
            if (privilege.getMajorType() != MajorType.MAP) {
                problems.add(at + " must be a map, is " + shortly(privilege));
                continue;
            }
            requireTstr(privilege, "vehicle_category_code", true, at, problems);
            for (String date : List.of("issue_date", "expiry_date")) {
                DataItem item = privilege.getOrNull(date);
                String problem = item == null ? null : fullDateProblem(item);
                if (problem != null) {
                    problems.add(at + "." + date + " must be full-date (7.2.4): it " + problem);
                }
            }
            DataItem codes = privilege.getOrNull("codes");
            if (codes == null) {
                continue;
            }
            if (codes.getMajorType() != MajorType.ARRAY || codes.getAsArray().isEmpty()) {
                problems.add(at + ".codes must be a non-empty array of maps, is " + shortly(codes));
                continue;
            }
            int codeIndex = 0;
            for (DataItem code : codes.getAsArray()) {
                String codeAt = at + ".codes[" + codeIndex++ + "]";
                if (code.getMajorType() != MajorType.MAP) {
                    problems.add(codeAt + " must be a map, is " + shortly(code));
                    continue;
                }
                requireTstr(code, "code", true, codeAt, problems);
                requireTstr(code, "sign", false, codeAt, problems);
                requireTstr(code, "value", false, codeAt, problems);
            }
        }
        return problems;
    }

    private static void requireTstr(DataItem map, String key, boolean mandatory, String at, List<String> problems) {
        DataItem item = map.getOrNull(key);
        if (item == null) {
            if (mandatory) {
                problems.add(at + "." + key + " is missing");
            }
        } else if (item.getMajorType() != MajorType.UNICODE_STRING) {
            problems.add(at + "." + key + " must be a tstr, is " + shortly(item));
        }
    }

    /**
     * Every way {@code value} misses {@code tdate}, by code: {@code untagged} (a tstr without tag 0), {@code notTdate}
     * (any other item or tag), {@code notRfc3339}, {@code fractionalSeconds}, {@code notZulu} (an offset other than
     * {@code Z}), {@code notCalendar} ({@code 2026-02-30T00:00:00Z}). Empty when it is a tag-0 RFC 3339 instant with
     * whole seconds and {@code Z}.
     */
    static List<VerificationReport.Problem> tdateProblems(DataItem value) {
        List<VerificationReport.Problem> problems = new ArrayList<>();
        DataItem text = value;
        if (value instanceof Tagged tagged) {
            if (tagged.getTagNumber() != Tagged.DATE_TIME_STRING) {
                problems.add(new VerificationReport.Problem("notTdate", "is not #6.0(tstr): " + shortly(value)));
            }
            text = tagged.getTaggedItem();
        } else if (value.getMajorType() == MajorType.UNICODE_STRING) {
            problems.add(new VerificationReport.Problem("untagged", "is a tstr without tag 0: " + shortly(value)));
        }
        if (text.getMajorType() != MajorType.UNICODE_STRING) {
            if (problems.isEmpty()) {
                problems.add(new VerificationReport.Problem("notTdate", "is not #6.0(tstr): " + shortly(value)));
            }
            return problems;
        }
        String string = text.getAsTstr();
        Matcher rfc3339 = RFC3339.matcher(string);
        if (!rfc3339.matches()) {
            problems.add(new VerificationReport.Problem("notRfc3339", "is not an RFC 3339 date-time: " + string));
            return problems;
        }
        if (rfc3339.group(1) != null) {
            problems.add(new VerificationReport.Problem("fractionalSeconds", "carries fractional seconds: " + string));
        }
        if (!"Z".equals(rfc3339.group(2))) {
            problems.add(new VerificationReport.Problem("notZulu", "has the offset " + rfc3339.group(2) + ", not Z: " + string));
        }
        try {
            OffsetDateTime.parse(string); // ResolverStyle.STRICT: 30 February and hour 25 fail
        } catch (DateTimeParseException e) {
            problems.add(new VerificationReport.Problem("notCalendar", "is not a calendar instant: " + string));
        }
        return problems;
    }

    /**
     * Null when {@code value} is {@code tdate}: tag 0 over a tstr that is RFC 3339 {@code date-time} with whole seconds
     * and {@code Z}, and a real calendar instant ({@code 2026-02-30T00:00:00Z} fails). Otherwise what is wrong.
     */
    static String tdateProblem(DataItem value) {
        List<VerificationReport.Problem> problems = tdateProblems(value);
        return problems.isEmpty() ? null : problems.stream().map(VerificationReport.Problem::message)
                .collect(java.util.stream.Collectors.joining(", "));
    }

    /** Null when {@code value} is {@code full-date}: tag 1004 over a strict {@code YYYY-MM-DD} calendar date. */
    static String fullDateProblem(DataItem value) {
        if (!(value instanceof Tagged tagged) || tagged.getTagNumber() != Tagged.FULL_DATE_STRING
                || tagged.getTaggedItem().getMajorType() != MajorType.UNICODE_STRING) {
            return "is not #6.1004(tstr): " + shortly(value);
        }
        String text = tagged.getTaggedItem().getAsTstr();
        if (!FULL_DATE.matcher(text).matches()) {
            return "is not YYYY-MM-DD: " + text;
        }
        try {
            LocalDate.parse(text, DateTimeFormatter.ISO_LOCAL_DATE); // ResolverStyle.STRICT: 2026-99-99 fails
            return null;
        } catch (DateTimeParseException e) {
            return "is not a calendar date: " + text;
        }
    }

    /** True when the first six bytes are the shortest encodings of tag 24 and of its bstr length. */
    static boolean preferredTag24Head(byte[] raw) {
        if (raw.length < 3 || (raw[0] & 0xff) != 0xd8 || raw[1] != 0x18 || (raw[2] & 0xe0) != 0x40) {
            return false;
        }
        int additional = raw[2] & 0x1f;
        if (additional < 24) {
            return true;
        }
        int size = additional == 24 ? 1 : additional == 25 ? 2 : additional == 26 ? 4 : additional == 27 ? 8 : -1;
        if (size < 0 || raw.length < 3 + size) {
            return false;
        }
        long length = 0;
        for (int i = 0; i < size; i++) {
            length = (length << 8) | (raw[3 + i] & 0xff);
        }
        int shortest = length < 24 ? 0 : length < 0x100 ? 1 : length < 0x10000 ? 2 : length < 0x100000000L ? 4 : 8;
        return size == shortest;
    }

    private static boolean isBoolean(DataItem value) {
        try {
            value.getAsBoolean(); // a null or undefined simple value throws here
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String shortly(DataItem value) {
        String text = value.getMajorType() + " " + value;
        return text.length() > 120 ? text.substring(0, 117) + "..." : text;
    }

    /**
     * The instant a validityInfo date names, read from the wire whether or not it is tagged and at any precision: the
     * window's ordering must not depend on the baseline repair. Whether the encoding is right is the tdate check's
     * business. A missing or unreadable date is reported and read as null, so the other rules still run.
     */
    private static Instant wireInstant(DataItem validity, String field, boolean required, Problems problems) {
        DataItem item = validity.getOrNull(field);
        if (item == null) {
            if (required) {
                problems.add("missing:" + field, "validityInfo." + field + " is missing");
            }
            return null;
        }
        DataItem text = item instanceof Tagged tagged ? tagged.getTaggedItem() : item;
        if (text.getMajorType() != MajorType.UNICODE_STRING || !RFC3339.matcher(text.getAsTstr()).matches()) {
            problems.add("notDate:" + field, "validityInfo." + field + " is not an RFC 3339 date-time: " + shortly(item));
            return null;
        }
        try {
            return OffsetDateTime.parse(text.getAsTstr()).toInstant();
        } catch (DateTimeParseException e) {
            problems.add("notDate:" + field, "validityInfo." + field + " is not a calendar instant: " + text.getAsTstr());
            return null;
        }
    }

    private static void sameInstant(Problems problems, String field, Instant wire, kotlin.time.Instant multipaz) {
        Instant parsed = multipaz == null ? null
                : Instant.ofEpochSecond(multipaz.getEpochSeconds(), multipaz.getNanosecondsOfSecond());
        if (!Objects.equals(wire, parsed)) {
            problems.add("multipazDisagrees:" + field, "Multipaz reads validityInfo." + field + " as " + parsed
                    + " but the wire says " + wire);
        }
    }

    /** The COSE_Key a holder proof is expected to have produced, normalised from the JWK. */
    private record ExpectedKey(int kty, String ktyName, Long crv, String crvName, byte[] x, byte[] y) {

        static ExpectedKey of(JWK jwk) {
            if (jwk instanceof ECKey ec) {
                String curve = ec.getCurve().getName();
                return new ExpectedKey(2, "EC2", switch (curve) {
                    case "P-256" -> 1L;
                    case "P-384" -> 2L;
                    case "P-521" -> 3L;
                    default -> throw new AssertionError("unsupported EC curve " + curve);
                }, curve, ec.getX().decode(), ec.getY().decode());
            }
            if (jwk instanceof OctetKeyPair okp && "Ed25519".equals(okp.getCurve().getName())) {
                // compared by x: Nimbus cannot turn an OKP JWK into a JCA key, and nothing else identifies it
                return new ExpectedKey(1, "OKP", 6L, "Ed25519", okp.getX().decode(), null);
            }
            throw new AssertionError("unsupported holder key type: " + jwk.getKeyType()
                    + (jwk instanceof OctetKeyPair okp ? " " + okp.getCurve() : ""));
        }

        /** Multipaz's parse of the deviceKey is this key: same COSE curve, same coordinates. */
        boolean matches(EcPublicKey actual) {
            if (actual == null || actual.getCurve().getCoseCurveIdentifier() != crv) {
                return false;
            }
            if (y == null) {
                return actual instanceof EcPublicKeyOkp okp && Arrays.equals(okp.getX(), x);
            }
            return actual instanceof EcPublicKeyDoubleCoordinate ec
                    && Arrays.equals(ec.getX(), x) && Arrays.equals(ec.getY(), y);
        }
    }

    private static final class Base64Url {
        static String of(byte[] bytes) {
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }
    }

    private static Long integer(DataItem value) {
        if (value == null || (value.getMajorType() != MajorType.UNSIGNED_INTEGER
                && value.getMajorType() != MajorType.NEGATIVE_INTEGER)) {
            return null;
        }
        return value.getAsNumber();
    }

    private static byte[] bstr(DataItem value) {
        return value == null || value.getMajorType() != MajorType.BYTE_STRING ? null : value.getAsBstr();
    }

    private static DataItem numeric(Map<DataItem, DataItem> labels, long label) {
        for (Map.Entry<DataItem, DataItem> entry : labels.entrySet()) {
            MajorType keyType = entry.getKey().getMajorType();
            if ((keyType == MajorType.UNSIGNED_INTEGER || keyType == MajorType.NEGATIVE_INTEGER)
                    && entry.getKey().getAsNumber() == label) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static byte[] bytes(ByteString byteString) {
        return byteString.toByteArray(0, byteString.getSize());
    }

    private static kotlin.time.Instant kotlinInstant(Instant instant) {
        return kotlin.time.Instant.Companion.fromEpochMilliseconds(instant.toEpochMilli());
    }

    private static String findings(ValidationResult result) {
        return result.getFindings().stream().map(ValidationFinding::getMessage).toList().toString();
    }

    private static String warnings(ValidationResult result) {
        List<String> warnings = result.getWarnings().stream().map(ValidationFinding::getMessage).toList();
        return warnings.isEmpty() ? "" : "; Multipaz warnings " + warnings;
    }

    /**
     * Multipaz's cryptographic entry points are suspending for multiplatform reasons but complete synchronously on
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
