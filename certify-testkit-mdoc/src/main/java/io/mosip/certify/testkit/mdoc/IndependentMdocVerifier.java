/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import com.authlete.cbor.CBORParser;
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
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.cose.CoseSign1;
import org.multipaz.crypto.Algorithm;
import org.multipaz.crypto.Crypto;
import org.multipaz.crypto.EcPublicKey;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;
import org.multipaz.crypto.X509CertChainJvmKt;
import org.multipaz.documenttype.DocumentAttribute;
import org.multipaz.documenttype.DocumentAttributeType;
import org.multipaz.documenttype.DocumentType;
import org.multipaz.documenttype.MdocDataElement;
import org.multipaz.documenttype.MdocNamespace;
import org.multipaz.documenttype.knowntypes.DrivingLicense;
import org.multipaz.mdoc.issuersigned.IssuerNamespaces;
import org.multipaz.mdoc.issuersigned.IssuerSignedItem;
import org.multipaz.mdoc.mso.MobileSecurityObject;
import org.multipaz.validation.ValidationFinding;
import org.multipaz.validation.ValidationResult;

import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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
 * {@code IssuerSignedItem.calculateDigest} is kept as a second opinion precisely because it re-encodes.
 *
 * <p>See {@code docs/design/20-mdl-issuer.md} (M-01, decision D9). Multipaz is pinned in the parent POM; its Kotlin
 * dependencies stay inside {@code certify-testkit-mdoc}.
 */
public final class IndependentMdocVerifier {

    public static final String CHECK_PARSE = "issuerSigned.parse";
    public static final String CHECK_SIGNATURE_MULTIPAZ = "issuerAuth.signature.multipaz";
    public static final String CHECK_SIGNATURE_AUTHLETE = "issuerAuth.signature.authlete";
    public static final String CHECK_MSO_PAYLOAD_TAG = "mso.payloadTag24";
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
    public static final String CHECK_ELEMENT_TYPES = "mdl.elementTypes";

    /** Every check, in report order; also what a credential that does not parse reports as not run. */
    private static final List<String> ALL_CHECKS = List.of(CHECK_PARSE, CHECK_SIGNATURE_MULTIPAZ, CHECK_SIGNATURE_AUTHLETE,
            CHECK_MSO_PAYLOAD_TAG, CHECK_NAMESPACES, CHECK_VALUE_DIGESTS, CHECK_CALCULATED_DIGESTS, CHECK_DIGEST_IDS_UNIQUE,
            CHECK_DEVICE_KEY, CHECK_DOC_TYPE, CHECK_VALIDITY_INFO, CHECK_TDATE_TAGS, CHECK_CHAIN_TO_IACA,
            CHECK_NO_SELF_SIGNED, CHECK_ELEMENT_TYPES);

    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    private static final int LABEL_ALG = 1;
    private static final int LABEL_X5CHAIN = 33;
    private static final Pattern SECONDS_ONLY_TDATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");
    private static final Pattern FULL_DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");

    public VerificationReport verify(byte[] issuerSignedCbor, JWK expectedHolderKey, Optional<X509Certificate> iaca,
                                     Instant at, Options options) {
        Doc doc;
        try {
            doc = Doc.parse(issuerSignedCbor, options);
        } catch (AssertionError | RuntimeException e) {
            // a missing x5chain or issuerAuth is a failed check, not an exception out of the harness
            String reason = "not run: issuerSigned did not parse (" + describe(e) + ")";
            List<VerificationReport.Check> unparsed = new ArrayList<>();
            for (String name : ALL_CHECKS) {
                unparsed.add(name.equals(CHECK_PARSE)
                        ? VerificationReport.Check.fail(name, describe(e))
                        : VerificationReport.Check.fail(name, reason));
            }
            return new VerificationReport(unparsed);
        }
        List<VerificationReport.Check> checks = new ArrayList<>();
        checks.add(run(CHECK_SIGNATURE_MULTIPAZ, doc::signatureWithMultipaz));
        checks.add(run(CHECK_SIGNATURE_AUTHLETE, () -> doc.signatureWithAuthlete(issuerSignedCbor)));
        checks.add(run(CHECK_MSO_PAYLOAD_TAG, doc::msoPayloadIsTag24));
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
        checks.add(run(CHECK_ELEMENT_TYPES, () -> doc.mdlElementTypes(options.strict())));
        return new VerificationReport(checks);
    }

    @FunctionalInterface
    private interface Probe {
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

    private static VerificationReport.Check run(String name, Probe probe) {
        try {
            return VerificationReport.Check.pass(name, probe.run());
        } catch (Skipped e) {
            return VerificationReport.Check.skipped(name, e.getMessage());
        } catch (AssertionError e) {
            return VerificationReport.Check.fail(name, describe(e));
        } catch (Exception e) {
            return VerificationReport.Check.fail(name, describe(e));
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
        private MobileSecurityObject mso;
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

        /**
         * The MSO as Multipaz reads it. In strict mode the reader gets the bytes as sent: the {@code withTdateTags}
         * repair below would hide exactly the untagged-date gap (G1) the strict mode exists to catch. In baseline
         * mode it is a fallback for output that predates M-02, and {@link #msoParsesAsSent()} says the repaired
         * parse happened so the checks that depend on Multipaz's own reading can say so instead of guessing.
         */
        MobileSecurityObject mso() {
            if (mso != null) {
                return mso;
            }
            if (parseFailure == null) {
                try {
                    mso = MobileSecurityObject.Companion.fromDataItem(msoItem);
                    return mso;
                } catch (AssertionError | RuntimeException e) {
                    parseFailure = e;
                }
            }
            require(!strict, "Multipaz cannot parse the MSO as sent, and strict mode does not repair it: "
                    + describe(parseFailure) + " (ISO/IEC 18013-5 9.1.2.4 tdate, gap G1)");
            mso = MobileSecurityObject.Companion.fromDataItem(withTdateTags(msoItem));
            return mso;
        }

        /** True when Multipaz reads the MSO exactly as it arrived; false is the untagged/fractional tdate gap G1. */
        boolean msoParsesAsSent() {
            mso();
            return parseFailure == null;
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

        /** Check 1b: Authlete's independent parse and COSEVerifier agree on the same IssuerAuth. */
        @SuppressWarnings("unchecked")
        String signatureWithAuthlete(byte[] issuerSignedCbor) throws Exception {
            Object parsed = new CBORParser(issuerSignedCbor).next();
            require(parsed instanceof Map<?, ?>, "Authlete did not parse IssuerSigned as a CBOR map");
            Object issuerAuthValue = ((Map<Object, Object>) parsed).get("issuerAuth");
            require(issuerAuthValue instanceof List<?>, "Authlete did not parse issuerAuth as a COSE_Sign1 array");
            COSESign1 coseSign1 = COSESign1.build((List<Object>) issuerAuthValue);
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
         * Check 3: Multipaz's own namespace validator, on the namespaces as received and against the MSO. Its errors
         * fail the check (duplicate elementIdentifier, duplicate digestID, missing fields, salt length,
         * {@code validateAgainstMso}'); its warnings are reported.
         */
        String namespacesValidate() {
            ValidationResult structural = IssuerNamespaces.Companion.validate(nameSpacesItem);
            require(!structural.getHasErrors(), "Multipaz IssuerNamespaces.validate: " + findings(structural));
            ValidationResult againstMso = await(c -> namespaces.validateAgainstMso(mso(), c));
            require(!againstMso.getHasErrors(), "Multipaz IssuerNamespaces.validateAgainstMso: " + findings(againstMso));
            String warnings = warnings(structural) + warnings(againstMso);
            return "Multipaz validates " + namespaces.getData().size() + " namespace(s)" + warnings;
        }

        /**
         * Check 4: every IssuerSignedItem digest equals its valueDigests entry under the declared algorithm. The hash
         * is taken over the bytes as received (9.1.2.5), not over a re-encoding of the parsed item.
         */
        String digestsMatchValueDigests() {
            Algorithm digestAlgorithm = mso().getDigestAlgorithm();
            require(digestAlgorithm != Algorithm.UNSET, "MSO digestAlgorithm is not set");
            Map<String, Map<Long, ByteString>> declared = mso().getValueDigests();
            require(declared != null && !declared.isEmpty(), "MSO valueDigests is empty");
            require(!wireItems.isEmpty(), "IssuerSigned carries no IssuerSignedItem");
            int verified = 0;
            for (WireIssuerSignedItems.Item item : wireItems) {
                Map<Long, ByteString> namespace = declared.get(item.namespace());
                require(namespace != null, "nameSpaces carries " + item.namespace() + " but valueDigests has no such namespace");
                ByteString expected = namespace.get(item.digestId());
                require(expected != null, "no valueDigests entry for " + item.namespace() + " digestID "
                        + item.digestId() + " (" + item.identifier() + ")");
                byte[] actual = await(c -> Crypto.INSTANCE.digest(digestAlgorithm, item.raw(), c));
                require(Arrays.equals(bytes(expected), actual),
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
            Algorithm digestAlgorithm = mso().getDigestAlgorithm();
            Map<String, Map<Long, ByteString>> declared = mso().getValueDigests();
            int verified = 0;
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    ByteString digest = await(c -> item.calculateDigest(digestAlgorithm, c));
                    Map<Long, ByteString> namespaceDigests = declared.get(namespace.getKey());
                    ByteString expected = namespaceDigests == null ? null : namespaceDigests.get(item.getDigestId());
                    require(expected != null, "no valueDigests entry for " + namespace.getKey() + " digestID "
                            + item.getDigestId() + " (" + item.getDataElementIdentifier() + ")");
                    require(Arrays.equals(bytes(expected), bytes(digest)),
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

        /** Check 7: the MSO deviceKey is the holder key the proof carried (EC2 P-256/384/521 or OKP Ed25519). */
        String deviceKey(JWK expectedHolderKey) {
            require(expectedHolderKey != null, "no expected holder key supplied");
            EcPublicKey expected = ecPublicKey(expectedHolderKey);
            EcPublicKey actual = mso().getDeviceKey();
            require(expected.equals(actual), "MSO deviceKey is not the holder key: expected " + expected.getCurve()
                    + " " + expected + ", MSO carries " + actual.getCurve() + " " + actual);
            // second opinion on the bytes as sent: the labels, not Multipaz's parse
            DataItem deviceKey = msoItem.get("deviceKeyInfo").get("deviceKey");
            require(deviceKey != null, "MSO deviceKeyInfo.deviceKey is missing");
            ExpectedKey labels = ExpectedKey.of(expectedHolderKey);
            Map<DataItem, DataItem> cose = deviceKey.getAsMap();
            require((long) labels.kty == number(cose, 1), "deviceKey kty is not " + labels.ktyName);
            require(labels.crv == number(cose, -1), "deviceKey crv is not " + labels.crvName);
            require(Arrays.equals(labels.x, bstr(cose, -2)), "deviceKey x does not match the holder key");
            if (labels.y != null) {
                require(Arrays.equals(labels.y, bstr(cose, -3)), "deviceKey y does not match the holder key");
            } else {
                require(numeric(cose, -3) == null, "OKP deviceKey carries a y coordinate (label -3)");
            }
            return "deviceKey equals the " + labels.crvName + " holder key (Multipaz parse and wire labels agree)";
        }

        /** Check 8: the MSO docType is the doctype the credential configuration asked for. */
        String docType(String expectedDocType) {
            require(expectedDocType.equals(mso().getDocType()),
                    "MSO docType is " + mso().getDocType() + ", expected " + expectedDocType);
            return "docType " + expectedDocType;
        }

        /**
         * Check 9: the validity window. {@code signed <= validFrom < validUntil}, {@code expectedUpdate} (when
         * present) after {@code signed} and before {@code validUntil}, and {@code at} inside
         * {@code validFrom..validUntil}; Multipaz's own MSO validator runs as a second opinion.
         */
        String validityInfo(Instant at) {
            DataItem validity = msoItem.getOrNull("validityInfo");
            require(validity != null, "MSO validityInfo is missing");
            MobileSecurityObject parsed = mso();
            long signed = parsed.getSignedAt().toEpochMilliseconds();
            long validFrom = parsed.getValidFrom().toEpochMilliseconds();
            long validUntil = parsed.getValidUntil().toEpochMilliseconds();
            long now = at.toEpochMilli();
            require(signed <= validFrom, "signed " + parsed.getSignedAt() + " is after validFrom " + parsed.getValidFrom());
            require(validFrom < validUntil, "validFrom " + parsed.getValidFrom() + " is not before validUntil "
                    + parsed.getValidUntil());
            kotlin.time.Instant expectedUpdate = parsed.getExpectedUpdate();
            if (expectedUpdate != null) {
                long update = expectedUpdate.toEpochMilliseconds();
                require(update > signed, "expectedUpdate " + expectedUpdate + " is not after signed " + parsed.getSignedAt());
                require(update < validUntil, "expectedUpdate " + expectedUpdate + " is not before validUntil "
                        + parsed.getValidUntil());
            }
            require(validFrom <= now, "validFrom " + parsed.getValidFrom() + " is in the future (at " + at + ")");
            require(now <= validUntil, "validUntil " + parsed.getValidUntil() + " has passed (at " + at + ")");
            if (!msoParsesAsSent()) {
                // the MSO carries a date Multipaz cannot read as sent (gap G1). The tdate check owns that gap and
                // reports it as skipped in baseline mode, so the window decision falls to the checks above.
                return "signed " + parsed.getSignedAt() + " within " + parsed.getValidFrom() + ".." + parsed.getValidUntil()
                        + "; Multipaz's own MSO validation skipped: it cannot read the MSO as sent (gap G1)";
            }
            ValidationResult multipaz = MobileSecurityObject.Companion.validate(msoItem, kotlinInstant(at));
            // Multipaz also reports tdate precision here; that finding belongs to the tdate check, which owns the gap
            // and reports it as skipped in baseline mode instead of failing the window.
            List<String> errors = multipaz.getErrors().stream()
                    .map(ValidationFinding::getMessage)
                    .filter(message -> !message.contains("fractional seconds"))
                    .toList();
            require(errors.isEmpty(), "Multipaz MobileSecurityObject.validate: " + errors);
            return "signed " + parsed.getSignedAt() + " within " + parsed.getValidFrom() + ".." + parsed.getValidUntil()
                    + (expectedUpdate == null ? "" : ", expectedUpdate " + expectedUpdate) + warnings(multipaz);
        }

        /**
         * Check 10: the wire dates. Strict mode requires CBOR tag 0 over an RFC 3339 tstr with whole seconds on
         * {@code signed}, {@code validFrom}, {@code validUntil} and {@code expectedUpdate} when present
         * (ISO/IEC 18013-5 9.1.2.4, gap G1). Baseline mode reports the gap as skipped, never as a pass.
         */
        String tdateTags(boolean strictTdate) {
            DataItem validity = msoItem.getOrNull("validityInfo");
            require(validity != null, "MSO validityInfo is missing");
            List<String> problems = new ArrayList<>();
            for (String field : List.of("signed", "validFrom", "validUntil", "expectedUpdate")) {
                DataItem item = validity.getOrNull(field);
                if (item == null) {
                    if ("expectedUpdate".equals(field)) {
                        continue; // optional in ISO/IEC 18013-5 9.1.2.4
                    }
                    throw new AssertionError("validityInfo." + field + " is missing");
                }
                if (item.getMajorType() != MajorType.TAG
                        || ((Tagged) item).getTagNumber() != Tagged.DATE_TIME_STRING
                        || ((Tagged) item).getTaggedItem().getMajorType() != MajorType.UNICODE_STRING) {
                    problems.add(field + " is not #6.0(tstr): " + item);
                    continue;
                }
                String text = ((Tagged) item).getTaggedItem().getAsTstr();
                if (!SECONDS_ONLY_TDATE.matcher(text).matches()) {
                    problems.add(field + " is not a whole-second tdate: " + text);
                }
            }
            // Multipaz's own MSO validator is the second opinion on the precision half of this rule (the wire is the
            // first); it cannot contribute when it cannot read the MSO as sent at all, which problems already says.
            if (msoParsesAsSent()) {
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
            return "signed, validFrom, validUntil are tag-0 whole-second tdate";
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

        /** Check 13: element types and mandatory elements against Multipaz's DrivingLicense document type. */
        String mdlElementTypes(boolean required) {
            if (!required) {
                skip("element types are not enforced today (gap G2; enabled by M-03)");
            }
            if (!MDL_DOCTYPE.equals(mso().getDocType())) {
                skip("docType " + mso().getDocType() + " is not an mDL: there are no mDL element types to check");
            }
            DocumentType mdl = DrivingLicense.INSTANCE.getDocumentType("en-US");
            MdocNamespace namespace = mdl.getMdocDocumentType().getNamespaces().get(MDL_NAMESPACE);
            require(namespace != null, "Multipaz DrivingLicense has no namespace " + MDL_NAMESPACE);
            Map<String, IssuerSignedItem> elements = namespaces.getData().get(MDL_NAMESPACE);
            require(elements != null, "IssuerSigned has no namespace " + MDL_NAMESPACE);
            for (Map.Entry<String, MdocDataElement> expected : namespace.getDataElements().entrySet()) {
                IssuerSignedItem item = elements.get(expected.getKey());
                if (item == null) {
                    require(!expected.getValue().getMandatory(),
                            "mandatory mDL element " + expected.getKey() + " is missing (ISO/IEC 18013-5 7.2.1 Table 5)");
                    continue;
                }
                requireType(expected.getKey(), expected.getValue().getAttribute(), item.getDataElementValue());
            }
            for (String identifier : elements.keySet()) {
                require(namespace.getDataElements().containsKey(identifier),
                        "element " + identifier + " is not in Multipaz's org.iso.18013.5.1.mDL document type");
            }
            return elements.size() + " elements typed against Multipaz DrivingLicense";
        }

        private static void requireType(String identifier, DocumentAttribute attribute, DataItem value) {
            DocumentAttributeType type = attribute.getType();
            String actual = value.getMajorType() + " " + value;
            if (type instanceof DocumentAttributeType.String || type instanceof DocumentAttributeType.StringOptions) {
                require(value.getMajorType() == MajorType.UNICODE_STRING, identifier + " must be a tstr, is " + actual);
            } else if (type instanceof DocumentAttributeType.Number || type instanceof DocumentAttributeType.IntegerOptions) {
                require(value.getMajorType() == MajorType.UNSIGNED_INTEGER, identifier + " must be a non-negative uint, is " + actual);
            } else if (type instanceof DocumentAttributeType.Boolean) {
                require(value.getMajorType() == MajorType.SPECIAL, identifier + " must be true or false, is " + actual);
                value.getAsBoolean(); // a null or undefined simple value throws here
            } else if (type instanceof DocumentAttributeType.Date) {
                require(isFullDate(value), identifier + " must be full-date (#6.1004(tstr) YYYY-MM-DD), is " + actual);
            } else if (type instanceof DocumentAttributeType.DateTime) {
                require(value.getMajorType() == MajorType.TAG
                                && ((Tagged) value).getTagNumber() == Tagged.DATE_TIME_STRING,
                        identifier + " must be tdate (#6.0(tstr)), is " + actual);
            } else if (type instanceof DocumentAttributeType.Picture || type instanceof DocumentAttributeType.Blob) {
                require(value.getMajorType() == MajorType.BYTE_STRING, identifier + " must be a bstr, is " + actual);
            } else if (type instanceof DocumentAttributeType.ComplexType) {
                require(value.getMajorType() == MajorType.ARRAY, identifier + " must be an array of maps, is " + actual);
                for (DataItem element : value.getAsArray()) {
                    require(element.getMajorType() == MajorType.MAP, identifier + " entries must be maps, is "
                            + element.getMajorType());
                    require(element.getOrNull("vehicle_category_code") != null || attribute.getEmbeddedAttributes().isEmpty(),
                            identifier + " entry has no vehicle_category_code");
                    for (DocumentAttribute embedded : attribute.getEmbeddedAttributes()) {
                        DataItem sub = element.getOrNull(embedded.getIdentifier());
                        if (sub != null) {
                            requireType(identifier + "." + embedded.getIdentifier(), embedded, sub);
                        }
                    }
                }
            } else {
                throw new AssertionError(identifier + " is typed " + type.getClass().getSimpleName()
                        + ", which this harness does not model: an unknown element type fails rather than guesses");
            }
        }

        private static boolean isFullDate(DataItem value) {
            return value.getMajorType() == MajorType.TAG
                    && ((Tagged) value).getTagNumber() == Tagged.FULL_DATE_STRING
                    && ((Tagged) value).getTaggedItem().getMajorType() == MajorType.UNICODE_STRING
                    && FULL_DATE.matcher(((Tagged) value).getTaggedItem().getAsTstr()).matches();
        }
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
                return new ExpectedKey(1, "OKP", 6L, "Ed25519", okp.getX().decode(), null);
            }
            throw new AssertionError("unsupported holder key type: " + jwk.getKeyType());
        }
    }

    /** The holder JWK as Multipaz reads it, so the comparison is against Multipaz's parse of the MSO deviceKey. */
    private static EcPublicKey ecPublicKey(JWK jwk) {
        try {
            java.security.PublicKey key = jwk instanceof ECKey ec ? ec.toPublicKey()
                    : jwk instanceof OctetKeyPair okp ? okp.toPublicKey()
                    : null;
            require(key != null, "unsupported holder key type: " + jwk.getKeyType());
            String pem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";
            return EcPublicKey.Companion.fromPem(pem);
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new AssertionError("cannot read the holder key: " + describe(e));
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
