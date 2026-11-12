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
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * An ISO/IEC 18013-5 IssuerSigned verifier built on libraries Certify does not maintain, so a formatter change cannot
 * make its own tests pass by agreeing with itself: OpenWallet Foundation <b>Multipaz</b> parses the CBOR, the MSO,
 * the namespaces and the x5chain and checks the COSE_Sign1 signature and digests; <b>Authlete CBOR</b> parses and
 * verifies the same IssuerAuth independently as a second COSE oracle; the JDK PKIX validator anchors the chain at an
 * IACA. Every rule becomes a named check in a {@link VerificationReport}, and a check that did not run is
 * {@link VerificationReport.State#SKIPPED} rather than a pass.
 *
 * <p>Digests are computed over the bytes the credential actually carried ({@link WireIssuerSignedItems});
 * {@code IssuerSignedItem.calculateDigest} is kept as a second opinion precisely because it re-encodes. The MSO fields
 * (docType, digestAlgorithm, valueDigests, deviceKey, validityInfo) are read from the MSO as sent with Multipaz's CBOR
 * and COSE_Key decoders, so whether Multipaz's {@code MobileSecurityObject} model accepts the MSO is one check
 * ({@code mso.parse}) instead of a cascade through every other one, and a repaired parse cannot decide the validity
 * window.
 *
 * <p>See {@code docs/design/20-mdl-issuer.md} (M-01, decision D9). Multipaz is pinned in the parent POM; its Kotlin
 * dependencies stay inside {@code certify-testkit-mdoc}.
 */
public final class IndependentMdocVerifier {

    public static final String CHECK_PARSE = "issuerSigned.parse";
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
    public static final List<String> CHECKS = List.of(CHECK_PARSE, CHECK_SIGNATURE_MULTIPAZ, CHECK_SIGNATURE_AUTHLETE,
            CHECK_MSO_PAYLOAD_TAG, CHECK_MSO_PARSE, CHECK_NAMESPACES, CHECK_VALUE_DIGESTS, CHECK_CALCULATED_DIGESTS, CHECK_DIGEST_IDS_UNIQUE,
            CHECK_DEVICE_KEY, CHECK_DOC_TYPE, CHECK_VALIDITY_INFO, CHECK_TDATE_TAGS, CHECK_CHAIN_TO_IACA,
            CHECK_NO_SELF_SIGNED, CHECK_SERIAL_NUMBER, CHECK_ELEMENT_TYPES);

    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    private static final int LABEL_ALG = 1;
    private static final int LABEL_X5CHAIN = 33;
    private static final long COSE_KEY_D = -4;
    private static final int MAX_SERIAL_OCTETS = 20;
    private static final Pattern WHOLE_SECOND_TDATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");
    private static final Pattern FULL_DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
    /**
     * ISO/IEC 18013-5 Table 5 where Multipaz 0.102.0's {@code DrivingLicense} disagrees: {@code issue_date} and
     * {@code expiry_date} are "tdate or full-date" (Multipaz: full-date only) and {@code portrait_capture_date} is a
     * tdate (Multipaz: full-date). {@code driving_privileges} is modelled from 7.2.4, because Multipaz carries no
     * embedded attributes for it.
     */
    private static final Set<String> TDATE_OR_FULL_DATE = Set.of("issue_date", "expiry_date");
    private static final Set<String> TDATE_ONLY = Set.of("portrait_capture_date");
    private static final String DRIVING_PRIVILEGES = "driving_privileges";

    public VerificationReport verify(byte[] issuerSignedCbor, JWK expectedHolderKey, Optional<X509Certificate> iaca,
                                     Instant at, Options options) {
        Doc doc;
        try {
            doc = Doc.parse(issuerSignedCbor, options);
        } catch (Throwable e) {
            rethrowIfFatal(e);
            // a missing x5chain or issuerAuth is a failed check, not an exception out of the harness
            String reason = "not run: issuerSigned did not parse (" + describe(e) + ")";
            List<VerificationReport.Check> unparsed = new ArrayList<>();
            for (String name : CHECKS) {
                unparsed.add(VerificationReport.Check.fail(name, name.equals(CHECK_PARSE) ? describe(e) : reason));
            }
            return new VerificationReport(unparsed);
        }
        List<VerificationReport.Check> checks = new ArrayList<>();
        checks.add(VerificationReport.Check.pass(CHECK_PARSE, "Multipaz reads issuerAuth, nameSpaces and x5chain; "
                + doc.wireItems.size() + " IssuerSignedItems on the wire"));
        checks.add(run(CHECK_SIGNATURE_MULTIPAZ, doc::signatureWithMultipaz));
        checks.add(run(CHECK_SIGNATURE_AUTHLETE, () -> doc.signatureWithAuthlete(issuerSignedCbor)));
        checks.add(run(CHECK_MSO_PAYLOAD_TAG, doc::msoPayloadIsTag24));
        checks.add(run(CHECK_MSO_PARSE, doc::msoParses));
        checks.add(run(CHECK_NAMESPACES, doc::namespacesValidate));
        checks.add(run(CHECK_VALUE_DIGESTS, doc::digestsMatchValueDigests));
        checks.add(run(CHECK_CALCULATED_DIGESTS, doc::calculateDigestAgrees));
        checks.add(run(CHECK_DIGEST_IDS_UNIQUE, doc::digestIdsAreUnique));
        checks.add(run(CHECK_DEVICE_KEY, () -> doc.deviceKey(expectedHolderKey)));
        checks.add(run(CHECK_DOC_TYPE, () -> doc.docType(options.expectedDocType())));
        checks.add(run(CHECK_VALIDITY_INFO, () -> doc.validityInfo(at)));
        checks.add(run(CHECK_TDATE_TAGS, () -> doc.tdateTags(options.strict())));
        checks.add(run(CHECK_CHAIN_TO_IACA, () -> doc.chainToIaca(iaca, at, options.strict())));
        checks.add(run(CHECK_NO_SELF_SIGNED, () -> doc.noSelfSignedInChain(options.strict())));
        checks.add(run(CHECK_SERIAL_NUMBER, doc::serialNumbers));
        checks.add(run(CHECK_ELEMENT_TYPES, () -> doc.mdlElementTypes(options.strict())));
        return new VerificationReport(checks);
    }

    @FunctionalInterface
    interface Probe {
        String run() throws Exception;
    }

    /** A check that was not run because the gap it covers is still open; never a pass. */
    private static final class Skipped extends RuntimeException {
        Skipped(String message) {
            super(message, null, false, false);
        }
    }

    private static String skip(String message) {
        throw new Skipped(message);
    }

    /**
     * Runs one check. Anything a check throws is that check's failure, Errors included (a Kotlin
     * {@code NotImplementedError}, a {@code StackOverflowError} on deeply nested CBOR), so one bad credential cannot
     * take the report down; only a VM failure that leaves nothing to report on propagates.
     */
    static VerificationReport.Check run(String name, Probe probe) {
        try {
            return VerificationReport.Check.pass(name, probe.run());
        } catch (Skipped e) {
            return VerificationReport.Check.skipped(name, e.getMessage());
        } catch (Throwable e) {
            rethrowIfFatal(e);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return VerificationReport.Check.fail(name, describe(e));
        }
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

        private Doc(CoseSign1 issuerAuth, DataItem payload, DataItem msoItem, DataItem nameSpacesItem,
                    IssuerNamespaces namespaces, List<WireIssuerSignedItems.Item> wireItems, X509CertChain chain,
                    List<X509Certificate> certificates, boolean strict) {
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

        static Doc parse(byte[] issuerSignedCbor, Options options) {
            DataItem issuerSigned = Cbor.INSTANCE.decode(issuerSignedCbor);
            DataItem issuerAuthItem = requirePresent(issuerSigned.getOrNull("issuerAuth"), "issuerSigned.issuerAuth");
            if (issuerAuthItem.getMajorType() == MajorType.TAG) {
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
            return new Doc(issuerAuth, payload, msoItem, nameSpacesItem, namespaces, wireItems, chain, certificates,
                    options.strict());
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

        /** The MSO {@code docType} as sent. */
        String wireDocType() {
            DataItem docType = requirePresent(msoItem.getOrNull("docType"), "MSO docType");
            require(docType.getMajorType() == MajorType.UNICODE_STRING, "MSO docType is not a tstr: " + shortly(docType));
            return docType.getAsTstr();
        }

        /** The MSO {@code digestAlgorithm} as sent: one of the three ISO/IEC 18013-5 9.1.2.5 names. */
        Algorithm wireDigestAlgorithm() {
            String name = requirePresent(msoItem.getOrNull("digestAlgorithm"), "MSO digestAlgorithm").getAsTstr();
            return switch (name) {
                case "SHA-256" -> Algorithm.SHA256;
                case "SHA-384" -> Algorithm.SHA384;
                case "SHA-512" -> Algorithm.SHA512;
                default -> throw new AssertionError("MSO digestAlgorithm " + name
                        + " is not SHA-256, SHA-384 or SHA-512 (ISO/IEC 18013-5 9.1.2.5)");
            };
        }

        /** The MSO {@code valueDigests} as sent: namespace to digestID to digest. */
        Map<String, Map<Long, byte[]>> wireValueDigests() {
            DataItem valueDigests = requirePresent(msoItem.getOrNull("valueDigests"), "MSO valueDigests");
            Map<String, Map<Long, byte[]>> declared = new LinkedHashMap<>();
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

        private Algorithm protectedAlgorithm() {
            DataItem alg = issuerAuth.getProtectedHeaders().get(new CoseNumberLabel(LABEL_ALG));
            require(alg != null, "COSE protected header has no alg (label 1)");
            Algorithm algorithm = Algorithm.Companion.fromCoseAlgorithmIdentifier((int) alg.getAsNumber());
            require(algorithm != Algorithm.UNSET, "unsupported COSE alg " + alg.getAsNumber());
            return algorithm;
        }

        /** Check 1a: Multipaz verifies the COSE_Sign1 against the x5chain leaf. */
        String signatureWithMultipaz() {
            Algorithm algorithm = protectedAlgorithm();
            X509Cert leaf = chain.getCertificates().get(0);
            await(continuation -> Cose.INSTANCE.coseSign1Check(leaf.getPublicKey(), null, issuerAuth, algorithm, continuation));
            return "verified " + algorithm + " over Sig_structure with the x5chain leaf " + certificates.get(0).getSubjectX500Principal();
        }

        /**
         * Check 1b: Authlete's independent decode and COSEVerifier agree on the same IssuerAuth. Authlete gets the
         * CBOR item tree, so a tag-18 COSE_Sign1 (the draft-13 Document) is unwrapped here rather than re-encoded.
         */
        String signatureWithAuthlete(byte[] issuerSignedCbor) throws Exception {
            CBORItem parsed = new CBORDecoder(issuerSignedCbor).next();
            require(parsed instanceof CBORPairList, "Authlete did not decode IssuerSigned as a CBOR map");
            CBORPair pair = ((CBORPairList) parsed).findByKey("issuerAuth");
            require(pair != null, "Authlete found no issuerAuth in IssuerSigned");
            CBORItem issuerAuthItem = pair.getValue();
            if (issuerAuthItem instanceof CBORTaggedItem tagged) {
                require(tagged.getTagNumber().longValue() == 18, "issuerAuth carries tag " + tagged.getTagNumber()
                        + ", not COSE_Sign1 (18)");
                issuerAuthItem = tagged.getTagContent();
            }
            COSESign1 coseSign1 = COSESign1.build(issuerAuthItem);
            List<X509Certificate> authleteChain = coseSign1.getUnprotectedHeader() == null ? null
                    : coseSign1.getUnprotectedHeader().getX5Chain();
            if (authleteChain == null || authleteChain.isEmpty()) {
                authleteChain = coseSign1.getProtectedHeader().getX5Chain();
            }
            require(authleteChain != null && !authleteChain.isEmpty(), "Authlete found no x5chain in IssuerAuth");
            X509Certificate leaf = authleteChain.get(0);
            boolean valid = new COSEVerifier(leaf.getPublicKey()).verify(coseSign1);
            require(valid, "Authlete COSEVerifier rejected the IssuerAuth signature");
            return "verified with Authlete COSEVerifier against " + leaf.getSubjectX500Principal();
        }

        /** Check 2: the MSO payload is tag 24 over the encoded MSO (ISO/IEC 18013-5 9.1.2.4). */
        String msoPayloadIsTag24() {
            boolean tagged = payload.getMajorType() == MajorType.TAG
                    && ((Tagged) payload).getTagNumber() == Tagged.ENCODED_CBOR
                    && ((Tagged) payload).getTaggedItem().getMajorType() == MajorType.BYTE_STRING;
            if (!tagged) {
                require(!strict, "the MSO payload is not #6.24(bstr .cbor MobileSecurityObject) (ISO/IEC 18013-5 9.1.2.4)");
                skip("the MSO payload is not tag 24 today (fixed by M-02)");
            }
            return "the MSO payload is tag 24 over the encoded MSO";
        }

        /**
         * Check 2b: Multipaz's {@code MobileSecurityObject} model accepts the MSO as sent. A Multipaz-based wallet
         * reads a credential through exactly this parser, so a refusal (for example its {@code signed <= validFrom}
         * requirement) means such a wallet cannot use the credential at all. Baseline mode reports an MSO that only
         * the untagged-date repair makes readable as skipped (gap G1); anything else is a failure.
         */
        String msoParses() {
            if (msoAsSent().isPresent()) {
                return "Multipaz MobileSecurityObject.fromDataItem accepts the MSO as sent";
            }
            String cause = describe(parseFailure);
            if (!strict && msoModel().isPresent()) {
                skip("Multipaz reads the MSO only after untagged dates are tagged (gap G1, fixed by M-02): " + cause);
            }
            throw new AssertionError("Multipaz MobileSecurityObject.fromDataItem refuses the MSO as sent (" + cause
                    + "): a Multipaz-based wallet cannot read this credential; mso.validityInfo and "
                    + "mso.validityInfo.tdateTags name the rule it breaks");
        }

        /**
         * Check 3: Multipaz's own namespace validator, on the namespaces as received and against the MSO. Its errors
         * fail the check (duplicate elementIdentifier, duplicate digestID, missing fields, salt length,
         * {@code validateAgainstMso}'); its warnings are reported.
         */
        String namespacesValidate() {
            ValidationResult structural = IssuerNamespaces.Companion.validate(nameSpacesItem);
            require(!structural.getHasErrors(), "Multipaz IssuerNamespaces.validate: " + findings(structural));
            Optional<MobileSecurityObject> model = msoModel();
            if (model.isEmpty()) {
                // validateAgainstMso needs Multipaz's MSO model, which mso.parse reports as refused; what it would
                // compare (a digest table per namespace, a digest per item) is mso.valueDigests, read from the wire
                return "Multipaz validates " + namespaces.getData().size() + " namespace(s); validateAgainstMso not run "
                        + "(no MSO model, see mso.parse), its comparison is mso.valueDigests" + warnings(structural);
            }
            ValidationResult againstMso = await(c -> namespaces.validateAgainstMso(model.get(), c));
            require(!againstMso.getHasErrors(), "Multipaz IssuerNamespaces.validateAgainstMso: " + findings(againstMso));
            String warnings = warnings(structural) + warnings(againstMso);
            return "Multipaz validates " + namespaces.getData().size() + " namespace(s)" + warnings;
        }

        /**
         * Check 4: every IssuerSignedItem digest equals its valueDigests entry under the declared algorithm. The hash
         * is taken over the bytes as received (9.1.2.5), not over a re-encoding of the parsed item.
         */
        String digestsMatchValueDigests() {
            Algorithm digestAlgorithm = wireDigestAlgorithm();
            Map<String, Map<Long, byte[]>> declared = wireValueDigests();
            require(!declared.isEmpty(), "MSO valueDigests is empty");
            require(!wireItems.isEmpty(), "IssuerSigned carries no IssuerSignedItem");
            int verified = 0;
            for (WireIssuerSignedItems.Item item : wireItems) {
                Map<Long, byte[]> namespace = declared.get(item.namespace());
                require(namespace != null, "nameSpaces carries " + item.namespace() + " but valueDigests has no such namespace");
                byte[] expected = namespace.get(item.digestId());
                require(expected != null, "no valueDigests entry for " + item.namespace() + " digestID "
                        + item.digestId() + " (" + item.identifier() + ")");
                byte[] actual = await(c -> Crypto.INSTANCE.digest(digestAlgorithm, item.raw(), c));
                require(Arrays.equals(expected, actual),
                        "digest mismatch for " + item.namespace() + "/" + item.identifier() + " digestID " + item.digestId()
                                + ": the received tag-24 bytes do not hash to the declared digest");
                verified++;
            }
            int parsed = namespaces.getData().values().stream().mapToInt(Map::size).sum();
            require(verified == parsed, "the wire carries " + verified + " IssuerSignedItems but only " + parsed
                    + " distinct (namespace, elementIdentifier) pairs: a duplicate hides an item from every check");
            return verified + " IssuerSignedItems match valueDigests under " + digestAlgorithm
                    + " (hashed over the received bytes)";
        }

        /**
         * Check 5, second opinion: Multipaz's {@code IssuerSignedItem.calculateDigest} agrees with valueDigests. It
         * re-encodes, so a non-preferred encoding passes here and fails {@link #digestsMatchValueDigests} — which is
         * why it is not the primary oracle. It still catches a valueDigests table that is wrong for the parsed item.
         */
        String calculateDigestAgrees() {
            Algorithm digestAlgorithm = wireDigestAlgorithm();
            Map<String, Map<Long, byte[]>> declared = wireValueDigests();
            int verified = 0;
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    ByteString digest = await(c -> item.calculateDigest(digestAlgorithm, c));
                    Map<Long, byte[]> namespaceDigests = declared.get(namespace.getKey());
                    byte[] expected = namespaceDigests == null ? null : namespaceDigests.get(item.getDigestId());
                    require(expected != null, "no valueDigests entry for " + namespace.getKey() + " digestID "
                            + item.getDigestId() + " (" + item.getDataElementIdentifier() + ")");
                    require(Arrays.equals(expected, bytes(digest)),
                            "re-encoded digest mismatch for " + namespace.getKey() + "/" + item.getDataElementIdentifier()
                                    + " digestID " + item.getDigestId());
                    verified++;
                }
            }
            return verified + " IssuerSignedItems match valueDigests when Multipaz re-encodes them";
        }

        /** Check 6: digestIDs are unique within each namespace (ISO/IEC 18013-5 9.1.2.5). */
        String digestIdsAreUnique() {
            // the wire, in order: two items sharing a digestID make the valueDigests entry ambiguous
            Map<String, Set<Long>> seen = new LinkedHashMap<>();
            for (WireIssuerSignedItems.Item item : wireItems) {
                require(seen.computeIfAbsent(item.namespace(), k -> new HashSet<>()).add(item.digestId()),
                        "duplicate digestID " + item.digestId() + " in namespace " + item.namespace()
                                + " (" + item.identifier() + ")");
            }
            // second opinion: Multipaz collapses duplicates by identifier, so check what it did keep too
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                Set<Long> parsed = new HashSet<>();
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    require(parsed.add(item.getDigestId()), "duplicate digestID " + item.getDigestId()
                            + " in namespace " + namespace.getKey());
                }
            }
            return "digestIDs unique per namespace";
        }

        /**
         * Check 7: the MSO deviceKey is the holder key the proof carried: EC2 P-256/384/521 by x and y, OKP Ed25519 by
         * x alone (kty 1, crv 6, no y). Multipaz's parse and the COSE labels as sent must both agree, and a COSE_Key
         * that carries the private key ({@code d}, label -4) fails whatever else it says.
         */
        String deviceKey(JWK expectedHolderKey) {
            require(expectedHolderKey != null, "no expected holder key supplied");
            ExpectedKey expected = ExpectedKey.of(expectedHolderKey);
            DataItem deviceKeyInfo = requirePresent(msoItem.getOrNull("deviceKeyInfo"), "MSO deviceKeyInfo");
            DataItem deviceKey = requirePresent(deviceKeyInfo.getOrNull("deviceKey"), "MSO deviceKeyInfo.deviceKey");
            Map<DataItem, DataItem> cose = deviceKey.getAsMap();
            require(numeric(cose, COSE_KEY_D) == null, "the MSO deviceKey carries a private key (COSE_Key label -4, d)");
            EcPublicKey parsed = CoseKey.Companion.fromDataItem(deviceKey).getEcPublicKey();
            require(expected.matches(parsed), "MSO deviceKey is not the holder key: expected " + expected.crvName
                    + " x=" + Base64Url.of(expected.x) + ", Multipaz reads " + parsed.getCurve() + " " + parsed);
            // second opinion on the bytes as sent: the labels, not Multipaz's parse
            require((long) expected.kty == number(cose, 1), "deviceKey kty is not " + expected.ktyName + " (" + expected.kty + ")");
            require(expected.crv == number(cose, -1), "deviceKey crv is not " + expected.crvName + " (" + expected.crv + ")");
            require(Arrays.equals(expected.x, bstr(cose, -2)), "deviceKey x does not match the holder key");
            if (expected.y != null) {
                require(Arrays.equals(expected.y, bstr(cose, -3)), "deviceKey y does not match the holder key");
            } else {
                require(numeric(cose, -3) == null, "OKP deviceKey carries a y coordinate (label -3)");
            }
            return "deviceKey equals the " + expected.crvName + " holder key (Multipaz CoseKey and the wire labels agree)";
        }

        /** Check 8: the MSO docType is the doctype the credential configuration asked for. */
        String docType(String expectedDocType) {
            String docType = wireDocType();
            require(expectedDocType.equals(docType), "MSO docType is " + docType + ", expected " + expectedDocType);
            return "docType " + expectedDocType;
        }

        /**
         * Check 9: the validity window, ordered from the dates <em>as sent</em> (tagged or not, any precision), so a
         * repaired parse in baseline mode cannot decide it: {@code signed <= validFrom < validUntil},
         * {@code expectedUpdate} (when present) in {@code validFrom..validUntil}, and {@code at} inside
         * {@code validFrom..validUntil} (ISO/IEC 18013-5 9.1.2.4). Multipaz must read the same instants, and its own
         * MSO validator runs as a second opinion when it can read the MSO as sent.
         */
        String validityInfo(Instant at) {
            DataItem validity = requirePresent(msoItem.getOrNull("validityInfo"), "MSO validityInfo");
            Instant signed = wireInstant(validity, "signed", true);
            Instant validFrom = wireInstant(validity, "validFrom", true);
            Instant validUntil = wireInstant(validity, "validUntil", true);
            Instant expectedUpdate = wireInstant(validity, "expectedUpdate", false);
            require(!signed.isAfter(validFrom), "signed " + signed + " is after validFrom " + validFrom
                    + " (ISO/IEC 18013-5 9.1.2.4)");
            require(validFrom.isBefore(validUntil), "validFrom " + validFrom + " is not before validUntil " + validUntil);
            if (expectedUpdate != null) {
                require(!expectedUpdate.isBefore(validFrom), "expectedUpdate " + expectedUpdate + " is before validFrom "
                        + validFrom + " (ISO/IEC 18013-5 9.1.2.4)");
                require(expectedUpdate.isBefore(validUntil), "expectedUpdate " + expectedUpdate
                        + " is not before validUntil " + validUntil);
            }
            require(!validFrom.isAfter(at), "validFrom " + validFrom + " is in the future (at " + at + ")");
            require(!at.isAfter(validUntil), "validUntil " + validUntil + " has passed (at " + at + ")");

            Optional<MobileSecurityObject> model = msoModel();
            if (model.isPresent()) {
                requireSameInstant("signed", signed, model.get().getSignedAt());
                requireSameInstant("validFrom", validFrom, model.get().getValidFrom());
                requireSameInstant("validUntil", validUntil, model.get().getValidUntil());
                requireSameInstant("expectedUpdate", expectedUpdate, model.get().getExpectedUpdate());
            }
            String window = "signed " + signed + " within " + validFrom + ".." + validUntil
                    + (expectedUpdate == null ? "" : ", expectedUpdate " + expectedUpdate);
            if (msoAsSent().isEmpty()) {
                // Multipaz cannot read the MSO as sent: mso.parse reports that, and in baseline mode for untagged
                // dates (gap G1) skips it, so the window decision falls to the wire checks above
                return window + "; Multipaz's own MSO validation not run: it cannot read the MSO as sent (mso.parse)";
            }
            ValidationResult multipaz = MobileSecurityObject.Companion.validate(msoItem, kotlinInstant(at));
            // Multipaz also reports tdate precision here; that finding belongs to the tdate check, which owns the gap
            // and reports it as skipped in baseline mode instead of failing the window.
            List<String> errors = multipaz.getErrors().stream()
                    .map(ValidationFinding::getMessage)
                    .filter(message -> !message.contains("fractional seconds"))
                    .toList();
            require(errors.isEmpty(), "Multipaz MobileSecurityObject.validate: " + errors);
            return window + warnings(multipaz);
        }

        /**
         * Check 10: the wire dates. Strict mode requires CBOR tag 0 over an RFC 3339 tstr with whole seconds and
         * {@code Z} on {@code signed}, {@code validFrom}, {@code validUntil} and {@code expectedUpdate} when present
         * (ISO/IEC 18013-5 9.1.2.4, gap G1). Baseline mode reports the gap as skipped, never as a pass.
         */
        String tdateTags(boolean strictTdate) {
            DataItem validity = requirePresent(msoItem.getOrNull("validityInfo"), "MSO validityInfo");
            List<String> problems = new ArrayList<>();
            for (String field : List.of("signed", "validFrom", "validUntil", "expectedUpdate")) {
                DataItem item = validity.getOrNull(field);
                if (item == null) {
                    if ("expectedUpdate".equals(field)) {
                        continue; // optional in ISO/IEC 18013-5 9.1.2.4
                    }
                    throw new AssertionError("validityInfo." + field + " is missing");
                }
                String problem = tdateProblem(item);
                if (problem != null) {
                    problems.add(field + " " + problem);
                }
            }
            // Multipaz's own MSO validator is the second opinion on the precision half of this rule (the wire is the
            // first); it cannot contribute when it cannot read the MSO as sent at all, which problems already says.
            if (msoAsSent().isPresent()) {
                MobileSecurityObject.Companion.validate(msoItem, kotlinInstant(Instant.now())).getErrors().stream()
                        .map(ValidationFinding::getMessage)
                        .filter(message -> message.contains("fractional seconds"))
                        .forEach(problems::add);
            }
            if (!problems.isEmpty()) {
                if (strictTdate) {
                    throw new AssertionError(String.join("; ", problems) + " (ISO/IEC 18013-5 9.1.2.4, gap G1)");
                }
                skip("tdate gap: " + String.join("; ", problems) + " (fixed by M-02)");
            }
            // the rest of Multipaz's MSO findings belong to their own checks (mso.validityInfo owns expiry)
            return "validityInfo dates are tag-0 whole-second tdate";
        }

        /**
         * Check 11: the x5chain validates to the supplied IACA. The JDK PKIX validator is the trust decision;
         * Multipaz validates the chain's signatures, CA constraints and certificate validity as a second opinion.
         * Strict mode without an IACA cannot make that decision and fails rather than skipping.
         */
        String chainToIaca(Optional<X509Certificate> iaca, Instant at, boolean strict) throws Exception {
            if (iaca.isEmpty()) {
                require(!strict, "strict mode needs the IACA: the chain-to-anchor check cannot run without one");
                skip("no IACA supplied: chain-to-anchor not verified");
            }
            X509Certificate anchor = iaca.get();
            List<java.security.cert.Certificate> path = new ArrayList<>(certificates);
            if (path.get(path.size() - 1).equals(anchor)) {
                path.remove(path.size() - 1);
            }
            require(!path.isEmpty(), "x5chain carries only the IACA");
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(at));
            java.security.cert.CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
            CertPathValidator.getInstance("PKIX").validate(certPath, parameters);
            await(continuation -> chain.validate(kotlinInstant(at), true, true, true, continuation));
            return "x5chain validates to " + anchor.getSubjectX500Principal() + " at " + at;
        }

        /** Check 12: no certificate in the x5chain is self-signed (HAIP: the trust anchor stays out of the chain). */
        String noSelfSignedInChain(boolean required) throws Exception {
            if (!required) {
                skip("x5chain may carry a self-signed certificate today (gap G9, HAIP; fixed by M-02)");
            }
            for (X509Certificate certificate : certificates) {
                boolean selfIssued = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
                if (!selfIssued) {
                    continue;
                }
                boolean selfSigned = true;
                try {
                    certificate.verify(certificate.getPublicKey());
                } catch (Exception e) {
                    selfSigned = false;
                }
                require(!selfSigned, "x5chain carries the self-signed certificate " + certificate.getSubjectX500Principal()
                        + " (HAIP: the IACA must not be in x5chain)");
            }
            return "no self-signed certificate in x5chain";
        }

        /** Check 13: every x5chain certificate serial is a positive integer of at most 20 octets (RFC 5280 4.1.2.2). */
        String serialNumbers() {
            List<String> problems = serialNumberProblems(certificates);
            require(problems.isEmpty(), String.join("; ", problems) + " (RFC 5280 4.1.2.2)");
            return certificates.size() + " x5chain certificate serial(s) positive and at most " + MAX_SERIAL_OCTETS + " octets";
        }

        /** Check 14: element types and mandatory elements of the mDL namespace (ISO/IEC 18013-5 7.2.1 Table 5). */
        String mdlElementTypes(boolean required) {
            if (!required) {
                skip("element types are not enforced today (gap G2; enabled by M-03)");
            }
            if (!MDL_DOCTYPE.equals(wireDocType())) {
                skip("docType " + wireDocType() + " is not an mDL: there are no mDL element types to check");
            }
            Map<String, IssuerSignedItem> items = namespaces.getData().get(MDL_NAMESPACE);
            require(items != null, "IssuerSigned has no namespace " + MDL_NAMESPACE);
            Map<String, DataItem> elements = new LinkedHashMap<>();
            items.forEach((identifier, item) -> elements.put(identifier, item.getDataElementValue()));
            List<String> problems = mdlElementProblems(elements);
            require(problems.isEmpty(), String.join("; ", problems));
            return elements.size() + " elements typed against ISO/IEC 18013-5 Table 5 (Multipaz DrivingLicense)";
        }
    }

    /** Problems with the x5chain serial numbers: non-positive, or more than 20 DER content octets. */
    static List<String> serialNumberProblems(List<X509Certificate> certificates) {
        List<String> problems = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            BigInteger serial = certificate.getSerialNumber();
            String subject = String.valueOf(certificate.getSubjectX500Principal());
            if (serial.signum() <= 0) {
                problems.add(subject + " has the non-positive serial " + serial);
            }
            int octets = serial.toByteArray().length; // minimal two's complement: the DER INTEGER content octets
            if (octets > MAX_SERIAL_OCTETS) {
                problems.add(subject + " has a serial of " + octets + " octets, more than " + MAX_SERIAL_OCTETS);
            }
        }
        return problems;
    }

    /**
     * Problems with the elements of namespace {@code org.iso.18013.5.1}: a missing Table 5 mandatory element, an
     * element outside the mDL document type, or a value of the wrong CBOR type. Every problem is reported, not the
     * first. Types come from Multipaz's {@code DrivingLicense}, except where Table 5 says otherwise (see
     * {@link #TDATE_OR_FULL_DATE}).
     */
    static List<String> mdlElementProblems(Map<String, DataItem> elements) {
        MdocNamespace namespace = DrivingLicense.INSTANCE.getDocumentType("en-US").getMdocDocumentType()
                .getNamespaces().get(MDL_NAMESPACE);
        require(namespace != null, "Multipaz DrivingLicense has no namespace " + MDL_NAMESPACE);
        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, MdocDataElement> expected : namespace.getDataElements().entrySet()) {
            DataItem value = elements.get(expected.getKey());
            if (value == null) {
                if (expected.getValue().getMandatory()) {
                    problems.add("mandatory mDL element " + expected.getKey() + " is missing (ISO/IEC 18013-5 7.2.1 Table 5)");
                }
                continue;
            }
            String problem = typeProblem(expected.getKey(), expected.getValue().getAttribute(), value);
            if (problem != null) {
                problems.add(problem);
            }
        }
        for (String identifier : elements.keySet()) {
            if (!namespace.getDataElements().containsKey(identifier)) {
                problems.add("element " + identifier + " is not in the " + MDL_DOCTYPE + " document type");
            }
        }
        return problems;
    }

    private static String typeProblem(String identifier, DocumentAttribute attribute, DataItem value) {
        String actual = shortly(value);
        if (TDATE_OR_FULL_DATE.contains(identifier)) {
            String asDate = fullDateProblem(value);
            String asTdate = tdateProblem(value);
            return asDate == null || asTdate == null ? null : identifier + " must be full-date or tdate (Table 5): as "
                    + "full-date it " + asDate + ", as tdate it " + asTdate;
        }
        if (TDATE_ONLY.contains(identifier)) {
            String problem = tdateProblem(value);
            return problem == null ? null : identifier + " must be tdate (Table 5): it " + problem;
        }
        if (DRIVING_PRIVILEGES.equals(identifier)) {
            List<String> problems = drivingPrivilegesProblems(value);
            return problems.isEmpty() ? null : String.join("; ", problems);
        }
        DocumentAttributeType type = attribute.getType();
        if (type instanceof DocumentAttributeType.String || type instanceof DocumentAttributeType.StringOptions) {
            return value.getMajorType() == MajorType.UNICODE_STRING ? null : identifier + " must be a tstr, is " + actual;
        } else if (type instanceof DocumentAttributeType.Number || type instanceof DocumentAttributeType.IntegerOptions) {
            return value.getMajorType() == MajorType.UNSIGNED_INTEGER ? null
                    : identifier + " must be a non-negative uint, is " + actual;
        } else if (type instanceof DocumentAttributeType.Boolean) {
            boolean bool = value.getMajorType() == MajorType.SPECIAL && isBoolean(value);
            return bool ? null : identifier + " must be true or false, is " + actual;
        } else if (type instanceof DocumentAttributeType.Date) {
            String problem = fullDateProblem(value);
            return problem == null ? null : identifier + " must be full-date: it " + problem;
        } else if (type instanceof DocumentAttributeType.DateTime) {
            String problem = tdateProblem(value);
            return problem == null ? null : identifier + " must be tdate: it " + problem;
        } else if (type instanceof DocumentAttributeType.Picture || type instanceof DocumentAttributeType.Blob) {
            return value.getMajorType() == MajorType.BYTE_STRING ? null : identifier + " must be a bstr, is " + actual;
        }
        return identifier + " is typed " + type.getClass().getSimpleName()
                + ", which this harness does not model: an unknown element type fails rather than guesses";
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
     * Null when {@code value} is {@code tdate}: tag 0 over a tstr that is RFC 3339 {@code date-time} with whole seconds
     * and {@code Z}, and a real calendar instant ({@code 2026-02-30T00:00:00Z} fails). Otherwise what is wrong.
     */
    static String tdateProblem(DataItem value) {
        if (!(value instanceof Tagged tagged) || tagged.getTagNumber() != Tagged.DATE_TIME_STRING
                || tagged.getTaggedItem().getMajorType() != MajorType.UNICODE_STRING) {
            return "is not #6.0(tstr): " + shortly(value);
        }
        String text = tagged.getTaggedItem().getAsTstr();
        if (!WHOLE_SECOND_TDATE.matcher(text).matches()) {
            return "is not an RFC 3339 date-time with whole seconds and Z: " + text;
        }
        try {
            LocalDateTime.parse(text.substring(0, text.length() - 1), DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            return null;
        } catch (DateTimeParseException e) {
            return "is not a calendar instant: " + text;
        }
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
     * business.
     */
    private static Instant wireInstant(DataItem validity, String field, boolean required) {
        DataItem item = validity.getOrNull(field);
        if (item == null) {
            require(!required, "validityInfo." + field + " is missing");
            return null;
        }
        DataItem text = item instanceof Tagged tagged ? tagged.getTaggedItem() : item;
        require(text.getMajorType() == MajorType.UNICODE_STRING, "validityInfo." + field + " is not a date string: " + shortly(item));
        try {
            return OffsetDateTime.parse(text.getAsTstr()).toInstant();
        } catch (DateTimeParseException e) {
            throw new AssertionError("validityInfo." + field + " is not an RFC 3339 date-time: " + text.getAsTstr());
        }
    }

    private static void requireSameInstant(String field, Instant wire, kotlin.time.Instant multipaz) {
        Instant parsed = multipaz == null ? null
                : Instant.ofEpochSecond(multipaz.getEpochSeconds(), multipaz.getNanosecondsOfSecond());
        require(java.util.Objects.equals(wire, parsed), "Multipaz reads validityInfo." + field + " as " + parsed
                + " but the wire says " + wire);
    }

    /** The COSE_Key a holder proof is expected to have produced, normalised from the JWK. */
    private record ExpectedKey(int kty, String ktyName, long crv, String crvName, byte[] x, byte[] y) {

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

    private static long number(Map<DataItem, DataItem> labels, long label) {
        DataItem value = numeric(labels, label);
        require(value != null, "COSE key has no label " + label);
        return value.getAsNumber();
    }

    private static byte[] bstr(Map<DataItem, DataItem> labels, long label) {
        DataItem value = numeric(labels, label);
        require(value != null, "COSE key has no label " + label);
        return value.getAsBstr();
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
