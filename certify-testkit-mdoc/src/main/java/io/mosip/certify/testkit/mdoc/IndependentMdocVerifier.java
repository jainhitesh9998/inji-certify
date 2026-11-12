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

import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
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
 * IACA. Every rule becomes a named check in a {@link VerificationReport}.
 *
 * <p>See {@code docs/design/20-mdl-issuer.md} (M-01, decision D9). Multipaz is pinned in the parent POM; its Kotlin
 * dependencies stay inside {@code certify-testkit-mdoc}.
 */
public final class IndependentMdocVerifier {

    public static final String CHECK_SIGNATURE_MULTIPAZ = "issuerAuth.signature.multipaz";
    public static final String CHECK_SIGNATURE_AUTHLETE = "issuerAuth.signature.authlete";
    public static final String CHECK_VALUE_DIGESTS = "mso.valueDigests";
    public static final String CHECK_DIGEST_IDS_UNIQUE = "mso.valueDigests.digestIdsUnique";
    public static final String CHECK_DEVICE_KEY = "mso.deviceKey";
    public static final String CHECK_DOC_TYPE = "mso.docType";
    public static final String CHECK_VALIDITY_INFO = "mso.validityInfo";
    public static final String CHECK_CHAIN_TO_IACA = "x5chain.iaca";
    public static final String CHECK_NO_SELF_SIGNED = "x5chain.noSelfSigned";
    public static final String CHECK_ELEMENT_TYPES = "mdl.elementTypes";

    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    private static final int LABEL_ALG = 1;
    private static final int LABEL_X5CHAIN = 33;
    private static final Pattern SECONDS_ONLY_TDATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");

    public VerificationReport verify(byte[] issuerSignedCbor, JWK expectedHolderKey, Optional<X509Certificate> iaca,
                                     Instant at, Options options) {
        List<VerificationReport.Check> checks = new ArrayList<>();
        Doc doc;
        try {
            doc = Doc.parse(issuerSignedCbor);
        } catch (RuntimeException e) {
            checks.add(new VerificationReport.Check("issuerSigned.parse", false, describe(e)));
            return new VerificationReport(checks);
        }
        checks.add(run(CHECK_SIGNATURE_MULTIPAZ, () -> doc.signatureWithMultipaz()));
        checks.add(run(CHECK_SIGNATURE_AUTHLETE, () -> doc.signatureWithAuthlete(issuerSignedCbor)));
        checks.add(run(CHECK_VALUE_DIGESTS, doc::digestsMatchValueDigests));
        checks.add(run(CHECK_DIGEST_IDS_UNIQUE, doc::digestIdsAreUnique));
        checks.add(run(CHECK_DEVICE_KEY, () -> doc.deviceKey(expectedHolderKey)));
        checks.add(run(CHECK_DOC_TYPE, () -> doc.docType(options.expectedDocType())));
        checks.add(run(CHECK_VALIDITY_INFO, () -> doc.validityInfo(at, options.strictTdate())));
        checks.add(run(CHECK_CHAIN_TO_IACA, () -> doc.chainToIaca(iaca, at)));
        checks.add(run(CHECK_NO_SELF_SIGNED, () -> doc.noSelfSignedInChain(options.requireNoSelfSignedInChain())));
        checks.add(run(CHECK_ELEMENT_TYPES, () -> doc.mdlElementTypes(options.checkMdlElementTypes())));
        return new VerificationReport(checks);
    }

    private interface Probe {
        String run() throws Exception;
    }

    private static VerificationReport.Check run(String name, Probe probe) {
        try {
            return new VerificationReport.Check(name, true, probe.run());
        } catch (AssertionError e) {
            return new VerificationReport.Check(name, false, e.getMessage());
        } catch (Exception e) {
            return new VerificationReport.Check(name, false, describe(e));
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
    private record Doc(CoseSign1 issuerAuth, DataItem msoItem, MobileSecurityObject mso, IssuerNamespaces namespaces,
                       X509CertChain chain, List<X509Certificate> certificates) {

        static Doc parse(byte[] issuerSignedCbor) {
            DataItem issuerSigned = Cbor.INSTANCE.decode(issuerSignedCbor);
            DataItem issuerAuthItem = requirePresent(issuerSigned.getOrNull("issuerAuth"), "issuerSigned.issuerAuth");
            if (issuerAuthItem.getMajorType() == MajorType.TAG) {
                issuerAuthItem = issuerAuthItem.getAsTagged();
            }
            CoseSign1 issuerAuth = CoseSign1.Companion.fromDataItem(issuerAuthItem);
            DataItem payload = Cbor.INSTANCE.decode(issuerAuth.getPayload());
            DataItem msoItem = payload.getMajorType() == MajorType.TAG ? payload.getAsTaggedEncodedCbor() : payload;
            MobileSecurityObject mso = MobileSecurityObject.Companion.fromDataItem(withTdateTags(msoItem));
            IssuerNamespaces namespaces = IssuerNamespaces.Companion.fromDataItem(
                    requirePresent(issuerSigned.getOrNull("nameSpaces"), "issuerSigned.nameSpaces"));
            DataItem x5chain = issuerAuth.getUnprotectedHeaders().get(new CoseNumberLabel(LABEL_X5CHAIN));
            if (x5chain == null) {
                x5chain = issuerAuth.getProtectedHeaders().get(new CoseNumberLabel(LABEL_X5CHAIN));
            }
            X509CertChain chain = X509CertChain.Companion.fromDataItem(requirePresent(x5chain, "x5chain (COSE label 33)"));
            require(!chain.getCertificates().isEmpty(), "x5chain has no certificate");
            List<X509Certificate> certificates = X509CertChainJvmKt.getJavaX509Certificates(chain);
            return new Doc(issuerAuth, msoItem, mso, namespaces, chain, certificates);
        }

        /**
         * Multipaz's MSO reader requires the validityInfo dates to be tag-0 tdate. Today's Velocity path can emit
         * them as plain tstr (gap G1, fixed by M-02), so the strict reader is fed a tag-0 view of the same wire
         * values while {@link #validityInfo} still checks the bytes as they were sent.
         */
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

        private static DataItem requirePresent(DataItem item, String name) {
            require(item != null, name + " is missing");
            return item;
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

        /** Check 2: every IssuerSignedItem digest equals its valueDigests entry under the declared algorithm. */
        String digestsMatchValueDigests() {
            Algorithm digestAlgorithm = mso.getDigestAlgorithm();
            require(digestAlgorithm != Algorithm.UNSET, "MSO digestAlgorithm is not set");
            Map<String, Map<Long, ByteString>> expected = mso.getValueDigests();
            require(expected != null && !expected.isEmpty(), "MSO valueDigests is empty");
            int verified = 0;
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                Map<Long, ByteString> namespaceDigests = expected.get(namespace.getKey());
                require(namespaceDigests != null, "no valueDigests for namespace " + namespace.getKey());
                for (IssuerSignedItem issuerSignedItem : namespace.getValue().values()) {
                    ByteString digest = await(c -> issuerSignedItem.calculateDigest(digestAlgorithm, c));
                    ByteString declared = namespaceDigests.get(issuerSignedItem.getDigestId());
                    require(declared != null, "no valueDigests entry for " + namespace.getKey() + " digestID "
                            + issuerSignedItem.getDigestId() + " (" + issuerSignedItem.getDataElementIdentifier() + ")");
                    require(java.util.Arrays.equals(bytes(declared), bytes(digest)),
                            "digest mismatch for " + namespace.getKey() + "/" + issuerSignedItem.getDataElementIdentifier()
                                    + " digestID " + issuerSignedItem.getDigestId());
                    verified++;
                }
            }
            require(verified > 0, "IssuerSigned carries no IssuerSignedItem");
            return verified + " IssuerSignedItems match valueDigests under " + digestAlgorithm;
        }

        /** Check 9: digestIDs are unique within each namespace (ISO/IEC 18013-5 9.1.2.5). */
        String digestIdsAreUnique() {
            for (Map.Entry<String, Map<String, IssuerSignedItem>> namespace : namespaces.getData().entrySet()) {
                Set<Long> seen = new HashSet<>();
                for (IssuerSignedItem item : namespace.getValue().values()) {
                    require(seen.add(item.getDigestId()), "duplicate digestID " + item.getDigestId()
                            + " in namespace " + namespace.getKey());
                }
            }
            return "digestIDs unique per namespace";
        }

        /** Check 3: the MSO deviceKey is the holder key the proof carried (EC2 P-256 or OKP Ed25519). */
        String deviceKey(JWK expectedHolderKey) {
            require(expectedHolderKey != null, "no expected holder key supplied");
            ExpectedKey expected = ExpectedKey.of(expectedHolderKey);
            DataItem deviceKey = msoItem.get("deviceKeyInfo").get("deviceKey");
            require(deviceKey != null, "MSO deviceKeyInfo.deviceKey is missing");
            Map<DataItem, DataItem> labels = deviceKey.getAsMap();
            require((long) expected.kty == number(labels, 1), "deviceKey kty is not " + expected.ktyName);
            require(expected.crv == number(labels, -1), "deviceKey crv is not " + expected.crvName);
            require(java.util.Arrays.equals(expected.x, bstr(labels, -2)), "deviceKey x does not match the holder key");
            if (expected.y != null) {
                require(java.util.Arrays.equals(expected.y, bstr(labels, -3)), "deviceKey y does not match the holder key");
            }
            return "deviceKey equals the " + expected.crvName + " holder key";
        }

        /** Check 4: the MSO docType is the doctype the credential configuration asked for. */
        String docType(String expectedDocType) {
            require(expectedDocType.equals(mso.getDocType()),
                    "MSO docType is " + mso.getDocType() + ", expected " + expectedDocType);
            return "docType " + expectedDocType;
        }

        /** Check 5: validityInfo parses; signed <= at within validFrom..validUntil; strict rejects fractional seconds. */
        String validityInfo(Instant at, boolean strictTdate) {
            DataItem validity = msoItem.get("validityInfo");
            require(validity != null, "MSO validityInfo is missing");
            long signed = mso.getSignedAt().toEpochMilliseconds();
            long validFrom = mso.getValidFrom().toEpochMilliseconds();
            long validUntil = mso.getValidUntil().toEpochMilliseconds();
            long now = at.toEpochMilli();
            require(validFrom <= validUntil, "validFrom is after validUntil");
            require(signed <= now, "signed " + mso.getSignedAt() + " is in the future (at " + at + ")");
            require(validFrom <= now, "validFrom " + mso.getValidFrom() + " is in the future (at " + at + ")");
            require(now <= validUntil, "validUntil " + mso.getValidUntil() + " has passed (at " + at + ")");
            boolean untagged = false;
            for (String field : List.of("signed", "validFrom", "validUntil")) {
                DataItem item = validity.get(field);
                untagged |= item != null && item.getMajorType() == MajorType.UNICODE_STRING;
                String text = tdateText(item, field);
                if (strictTdate) {
                    require(SECONDS_ONLY_TDATE.matcher(text).matches(),
                            field + " is not a tag-0 seconds-only tdate: " + text + " (ISO/IEC 18013-5 9.1.2.4, gap G1)");
                }
            }
            return "signed " + mso.getSignedAt() + " within " + mso.getValidFrom() + ".." + mso.getValidUntil()
                    + (untagged ? ", tdate tags missing (gap G1)" : "");
        }

        private static String tdateText(DataItem item, String field) {
            require(item != null, "validityInfo." + field + " is missing");
            if (item.getMajorType() == MajorType.TAG) {
                require(((Tagged) item).getTagNumber() == Tagged.DATE_TIME_STRING,
                        "validityInfo." + field + " is not tagged as a tdate (tag 0)");
                return ((Tagged) item).getTaggedItem().getAsTstr();
            }
            return item.getAsTstr();
        }

        /**
         * Check 6: the x5chain validates to the supplied IACA. The JDK PKIX validator is the trust decision;
         * Multipaz validates the chain's signatures, CA constraints and certificate validity as a second opinion.
         */
        String chainToIaca(Optional<X509Certificate> iaca, Instant at) throws Exception {
            if (iaca.isEmpty()) {
                return "no IACA supplied: chain-to-anchor check skipped";
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
            kotlin.time.Instant instant = kotlin.time.Instant.Companion.fromEpochMilliseconds(at.toEpochMilli());
            await(continuation -> chain.validate(instant, true, true, true, continuation));
            return "x5chain validates to " + anchor.getSubjectX500Principal() + " at " + at;
        }

        /** Check 7: no certificate in the x5chain is self-signed (HAIP: the trust anchor stays out of the chain). */
        String noSelfSignedInChain(boolean required) throws Exception {
            if (!required) {
                return "not checked yet (gap G9, enabled by M-02)";
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

        /** Check 8: element types match Multipaz's DrivingLicense document type for org.iso.18013.5.1. */
        String mdlElementTypes(boolean required) {
            if (!required) {
                return "not checked yet (gap G2, enabled by M-03)";
            }
            if (!MDL_DOCTYPE.equals(mso.getDocType())) {
                return "docType " + mso.getDocType() + " is not an mDL: element types not checked";
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
                DocumentAttribute attribute = expected.getValue().getAttribute();
                require(typeMatches(attribute.getType(), item.getDataElementValue()),
                        "element " + expected.getKey() + " is " + item.getDataElementValue().getMajorType()
                                + ", Multipaz expects " + attribute.getType().getClass().getSimpleName());
            }
            for (String identifier : elements.keySet()) {
                require(namespace.getDataElements().containsKey(identifier),
                        "element " + identifier + " is not in Multipaz's org.iso.18013.5.1.mDL document type");
            }
            return elements.size() + " elements typed against Multipaz DrivingLicense";
        }

        private static boolean typeMatches(DocumentAttributeType type, DataItem value) {
            MajorType majorType = value.getMajorType();
            if (type instanceof DocumentAttributeType.String || type instanceof DocumentAttributeType.StringOptions) {
                return majorType == MajorType.UNICODE_STRING;
            }
            if (type instanceof DocumentAttributeType.Number || type instanceof DocumentAttributeType.IntegerOptions) {
                return majorType == MajorType.UNSIGNED_INTEGER || majorType == MajorType.NEGATIVE_INTEGER;
            }
            if (type instanceof DocumentAttributeType.Boolean) {
                return majorType == MajorType.SPECIAL;
            }
            if (type instanceof DocumentAttributeType.Date) {
                return majorType == MajorType.TAG || majorType == MajorType.UNICODE_STRING;
            }
            if (type instanceof DocumentAttributeType.DateTime) {
                return majorType == MajorType.TAG;
            }
            if (type instanceof DocumentAttributeType.Picture || type instanceof DocumentAttributeType.Blob) {
                return majorType == MajorType.BYTE_STRING;
            }
            if (type instanceof DocumentAttributeType.ComplexType) {
                return majorType == MajorType.MAP || majorType == MajorType.ARRAY;
            }
            return true; // a Multipaz attribute type this harness does not model: do not guess
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
