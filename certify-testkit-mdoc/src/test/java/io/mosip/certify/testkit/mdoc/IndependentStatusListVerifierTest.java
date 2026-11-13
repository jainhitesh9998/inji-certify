/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;
import kotlinx.io.bytestring.ByteString;
import org.junit.jupiter.api.Test;
import org.multipaz.asn1.ASN1;
import org.multipaz.asn1.ASN1Integer;
import org.multipaz.asn1.ASN1ObjectIdentifier;
import org.multipaz.asn1.ASN1Sequence;
import org.multipaz.asn1.OID;
import org.multipaz.cbor.Bstr;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.CborMap;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.DataItemExtensionsKt;
import org.multipaz.cbor.Tagged;
import org.multipaz.cbor.Tstr;
import org.multipaz.cose.Cose;
import org.multipaz.cose.CoseLabel;
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.cose.CoseSign1;
import org.multipaz.crypto.Algorithm;
import org.multipaz.crypto.AsymmetricKey;
import org.multipaz.crypto.EcCurve;
import org.multipaz.crypto.EcPrivateKey;
import org.multipaz.crypto.X500Name;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;
import org.multipaz.crypto.X509CertChainJvmKt;
import org.multipaz.crypto.X509KeyUsage;
import org.multipaz.mdoc.util.MdocUtil;
import org.multipaz.revocation.CompressedStatusList;
import org.multipaz.util.CompressionKt;

import com.nimbusds.jose.jwk.JWK;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The M-11b mutation matrix: every problem code of {@link IndependentStatusListVerifier#PROBLEM_CODES} is triggered by
 * one dedicated mutation of a token Multipaz itself built, and the mutation fires that code and no other. The positive
 * fixture is a real {@code CompressedStatusList.serializeAsCwt} token — protected {@code typ} and {@code x5chain}
 * without the root, tag 18 — signed by a Document Signer issued by a Multipaz-built IACA, so what passes here is what
 * Multipaz's own issuer writes (docs/design/wp/M-11-status-list-under-iaca.md 4.9, M-11b).
 */
class IndependentStatusListVerifierTest {

    static final String URI = "https://issuer.example/v1/certify/credentials/token-status-list/list-1";
    static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    static final long TTL = 3600;
    /** 32 octets = 256 one-bit statuses, all VALID in the positive fixture. */
    static final byte[] STATUSES = new byte[32];

    // ---- the sample sidecars (MdocSamples) ------------------------------------------------------------------------

    /**
     * A sample whose MSO carries {@code status.status_list} records the list beside the credential, and the reader hands
     * the conformance run the uri, the idx, the IssuerAuth x5chain and the list's own media type — the four inputs the
     * verifier needs and nothing Certify-specific. Both sidecars are required together: a body without its
     * Content-Type cannot be held to TSL 8.2.
     */
    @Test
    void aSampleRecordsTheListAndTheMsoStatusThatPointsAtIt(@org.junit.jupiter.api.io.TempDir Path directory) throws Exception {
        Fixture fixture = new Fixture();
        byte[] token = fixture.token();
        Path mdoc = MdocSamples.write(directory, getClass(), "synthetic", fixture.issuerSignedWithStatus(URI, 3),
                JWK.parse(HOLDER_JWK), "org.iso.18013.5.1.mDL", AcceptedGaps.none(), fixture.iacaJava);
        MdocSamples.writeStatusList(mdoc, token, IndependentStatusListVerifier.MEDIA_TYPE);

        MdocSamples.Sample sample = MdocSamples.read(mdoc);
        assertEquals(new MdocSamples.StatusListInfo(URI, 3), sample.statusListInfo().orElseThrow());
        assertEquals(IndependentStatusListVerifier.MEDIA_TYPE, sample.statusList().orElseThrow().contentType());
        assertEquals(token.length, sample.statusList().orElseThrow().body().length);
        assertEquals(1, sample.issuerAuthX5chain().size(), "the IssuerAuth x5chain the list has to equal");

        VerificationReport report = IndependentStatusListVerifier.verify(sample.statusList().orElseThrow().body(),
                sample.statusList().orElseThrow().contentType(), sample.statusListInfo().orElseThrow().uri(),
                sample.statusListInfo().orElseThrow().idx(), sample.issuerAuthX5chain(), sample.iaca().orElseThrow(),
                NOW, IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of(), report.failures(), () -> "the recorded sample verifies: " + report);

        Files.delete(directory.resolve(sample.name() + MdocSamples.STATUSLIST_CONTENT_TYPE));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> MdocSamples.read(mdoc),
                "a body without its Content-Type is refused, not silently verified as something else");
    }

    private static final String HOLDER_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";

    // ---- the positive fixture ------------------------------------------------------------------------------------

    @Test
    void aMultipazBuiltTokenPassesEveryCheckAgainstItsIaca() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.token(), IndependentStatusListVerifier.StatusListOptions.strictMode());

        assertEquals(IndependentStatusListVerifier.TOKEN_CHECKS,
                report.checks().stream().map(VerificationReport.Check::name).toList(),
                "every token check runs, in report order");
        assertEquals(List.of(), report.failures(), () -> "the Multipaz-built token must pass: " + report);
        assertTrue(report.passed(), () -> report.toString());
        assertEquals("served as application/statuslist+cwt", report.check(IndependentStatusListVerifier.CHECK_HTTP).message());
    }

    @Test
    void theSameTokenReportsARevokedIndexAsTheRevokedStatusTheCallerExpects() {
        Fixture fixture = new Fixture();
        byte[] statuses = new byte[32];
        statuses[3] = (byte) (1 << 5); // idx 29, LSB first (TSL 4.1)
        byte[] token = fixture.token(statuses, TTL, URI, NOW, fixture.dsc);

        VerificationReport valid = verify(fixture, token, new IndependentStatusListVerifier.StatusListOptions(true, 0, true),
                fixture.dsc, 29);
        assertEquals(List.of("statusMismatch:1"), valid.check(IndependentStatusListVerifier.CHECK_LIST).codes(),
                "the caller expected VALID, the list says INVALID");
        assertEquals(List.of(IndependentStatusListVerifier.CHECK_LIST),
                valid.failures().stream().map(VerificationReport.Check::name).toList(),
                "the one set bit is the only problem: the token is otherwise valid");

        VerificationReport revoked = verify(fixture, token, new IndependentStatusListVerifier.StatusListOptions(true, 1, true),
                fixture.dsc, 29);
        assertEquals(List.of(), revoked.failures(), () -> "idx 29 is INVALID, which is what the caller expects: " + revoked);
    }

    @Test
    void aTokenWithoutAnAnchorFailsOnlyWhenTheCallerIsStrict() {
        Fixture fixture = new Fixture();
        byte[] token = fixture.token();
        VerificationReport strict = verifyWithoutAnchor(fixture, token, IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of("noAnchorSupplied"), strict.check(IndependentStatusListVerifier.CHECK_CHAIN).codes());
        assertEquals(1, strict.failures().size(), () -> "the anchor is the only problem: " + strict);

        VerificationReport baseline = verifyWithoutAnchor(fixture, token,
                new IndependentStatusListVerifier.StatusListOptions(false, 0, true));
        assertEquals(IndependentStatusListVerifier.CHECK_CHAIN, baseline.skippedNames().iterator().next());
        assertEquals(List.of(), baseline.failures(), () -> "a baseline run skips, it does not fail: " + baseline);
    }

    @Test
    void theOptionsAcceptOnlyTheTwoMdocStatuses() {
        new IndependentStatusListVerifier.StatusListOptions(true, 0, true);
        new IndependentStatusListVerifier.StatusListOptions(true, 1, false);
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, 2, true)),
                "ISO/IEC 18013-5 second edition 12.3.6.1: an mdoc status is revoked or valid, and bits=1 has no 2");
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, 3, true)));
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, -1, false)));
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, 4, false)));
    }

    // ---- statusList.http -------------------------------------------------------------------------------------------

    @Test
    void aJwtBodyServedAsAJwtIsBothTheWrongMediaTypeAndNotACwt() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                "application/statuslist+jwt", IndependentStatusListVerifier.StatusListOptions.strictMode());

        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_HTTP, List.of("contentType"),
                IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18"),
                IndependentStatusListVerifier.CHECK_TYP, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_X5CHAIN, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_SIGNATURE, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_ISSUANCE_CHAIN, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_CLAIMS, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_LIST, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE, List.of("notRun")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message().contains("not CBOR"),
                "the envelope check says the body is not CBOR: " + report.check(IndependentStatusListVerifier.CHECK_ENVELOPE));
    }

    @Test
    void aMediaTypeParameterIsIgnoredAndACaseDifferenceIsAccepted() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.token(), "Application/StatusList+CWT; charset=binary",
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of(), report.failures(), () -> "TSL 8.2 compares the media type, not its parameters: " + report);
    }

    @Test
    void aMissingContentTypeIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = IndependentStatusListVerifier.verify(fixture.token(), null, URI, 3,
                javaCerts(List.of(fixture.dsc)), fixture.iacaJava, NOW,
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_HTTP, List.of("contentType")));
    }

    // ---- statusList.envelope ---------------------------------------------------------------------------------------

    @Test
    void anUntaggedCoseSign1IsNotAStatusListToken() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().tag(null).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18")));
    }

    @Test
    void aTag61WrappedCwtIsRefusedEvenAroundAValidTag18() {
        Fixture fixture = new Fixture();
        byte[] nested = wrap(61, fixture.token()); // 61(18(COSE_Sign1)) — the CWT tag TSL 5.2 forbids
        VerificationReport report = verify(fixture, nested, IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("cwtTag61")));
    }

    @Test
    void aSecondTagAroundTheTag18IsRefusedIncludingTheSelfDescribeTag() {
        Fixture fixture = new Fixture();
        VerificationReport doubled = verify(fixture, wrap(18, fixture.token()),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(doubled, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18")));
        assertTrue(doubled.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message().contains("[18, 18]"),
                "the report names the whole tag stack: " + doubled);

        VerificationReport selfDescribed = verify(fixture, wrap(55799, fixture.token()),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(selfDescribed, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18")));
        assertTrue(selfDescribed.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message().contains("[55799, 18]"),
                "55799 (RFC 8949 3.4.6) is refused, as @owf/cose 0.6.0 refuses it: "
                        + selfDescribed.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message());
    }

    @Test
    void aTagOtherThan17And18And61IsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().tag(99L).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18")));
    }

    @Test
    void aCoseMac0TagIsNotASignedList() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().tag(17L).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("mac0")));
    }

    @Test
    void aDetachedPayloadLeavesNothingToRead() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().detached().build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("detachedPayload"),
                IndependentStatusListVerifier.CHECK_CLAIMS, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_LIST, List.of("notRun")));
        assertEquals(Set.of(IndependentStatusListVerifier.CHECK_SIGNATURE), report.skippedNames(),
                "the signature cannot be checked without the detached payload");
    }

    /**
     * Review round 4, 1: a correctly signed payload whose claims map carries {@code sub} twice is invalid CBOR (RFC
     * 8949 5.3.1) and a malformed CWT (RFC 8392 7.2 steps 1 and 7). Multipaz keeps the last value and Authlete
     * verifies bytes only, so with the expected uri second the token used to pass every check; in both orders it is now
     * {@code duplicateKey} and nothing is read from its maps.
     */
    @Test
    void aClaimsMapWithSubTwiceIsMalformedInBothOrders() {
        Fixture fixture = new Fixture();
        for (List<String> subs : List.of(List.of("https://issuer.example/other", URI), List.of(URI, "https://issuer.example/other"))) {
            byte[] payload = rawMap(
                    enc(claim(2)), enc(new Tstr(subs.get(0))),
                    enc(claim(2)), enc(new Tstr(subs.get(1))),
                    enc(claim(4)), enc(DataItemExtensionsKt.toDataItem(NOW.plusSeconds(TTL).getEpochSecond())),
                    enc(claim(6)), enc(DataItemExtensionsKt.toDataItem(NOW.getEpochSecond())),
                    enc(claim(65533)), enc(statusListClaim(1, fixture.zlib(STATUSES))),
                    enc(claim(65534)), enc(DataItemExtensionsKt.toDataItem(TTL)));
            assertMalformedByDuplicateKey(verify(fixture, fixture.builder().rawPayload(payload).build(),
                    IndependentStatusListVerifier.StatusListOptions.strictMode()), "the CWT claims carries the key 2 twice");
        }
    }

    /** The nested {@code status_list} map, both orders: bits 2 then 1 (Multipaz reads 1) and 1 then 2. */
    @Test
    void aStatusListMapWithBitsTwiceIsMalformedInBothOrders() {
        Fixture fixture = new Fixture();
        for (long[] bits : new long[][] {{2, 1}, {1, 2}}) {
            byte[] statusList = rawMap(
                    enc(new Tstr("bits")), enc(DataItemExtensionsKt.toDataItem(bits[0])),
                    enc(new Tstr("bits")), enc(DataItemExtensionsKt.toDataItem(bits[1])),
                    enc(new Tstr("lst")), enc(new Bstr(fixture.zlib(STATUSES))));
            byte[] payload = rawMap(
                    enc(claim(2)), enc(new Tstr(URI)),
                    enc(claim(4)), enc(DataItemExtensionsKt.toDataItem(NOW.plusSeconds(TTL).getEpochSecond())),
                    enc(claim(6)), enc(DataItemExtensionsKt.toDataItem(NOW.getEpochSecond())),
                    enc(claim(65533)), statusList,
                    enc(claim(65534)), enc(DataItemExtensionsKt.toDataItem(TTL)));
            assertMalformedByDuplicateKey(verify(fixture, fixture.builder().rawPayload(payload).build(),
                    IndependentStatusListVerifier.StatusListOptions.strictMode()),
                    "the CWT claims → 65533 carries the key \"bits\" twice");
        }
    }

    /** The protected header, both orders: a wrong typ then the media type (Multipaz reads the media type), and back. */
    @Test
    void aProtectedHeaderWithTypTwiceIsMalformedInBothOrders() {
        Fixture fixture = new Fixture();
        for (List<String> typs : List.of(List.of("statuslist+cwt", IndependentStatusListVerifier.MEDIA_TYPE),
                List.of(IndependentStatusListVerifier.MEDIA_TYPE, "statuslist+cwt"))) {
            byte[] protectedHeader = rawMap(
                    enc(claim(1)), enc(DataItemExtensionsKt.toDataItem(-7L)),
                    enc(claim(16)), enc(new Tstr(typs.get(0))),
                    enc(claim(16)), enc(new Tstr(typs.get(1))),
                    enc(claim(33)), enc(new X509CertChain(List.of(fixture.dsc)).toCoseX5Chain(false)));
            byte[] token = fixture.signRaw(protectedHeader, rawMap(), fixture.canonicalPayload(), fixture.dscKey);
            assertMalformedByDuplicateKey(verify(fixture, token, IndependentStatusListVerifier.StatusListOptions.strictMode()),
                    "the protected header carries the key 16 twice");
        }
    }

    /** The unprotected header, both orders of two different kid values (RFC 9052 3 covers both buckets). */
    @Test
    void anUnprotectedHeaderWithALabelTwiceIsMalformedInBothOrders() {
        Fixture fixture = new Fixture();
        for (List<byte[]> kids : List.of(List.of(new byte[] {1}, new byte[] {2}), List.of(new byte[] {2}, new byte[] {1}))) {
            byte[] unprotectedHeader = rawMap(enc(claim(4)), enc(new Bstr(kids.get(0))), enc(claim(4)), enc(new Bstr(kids.get(1))));
            byte[] token = fixture.signRaw(fixture.canonicalProtectedHeader(), unprotectedHeader, fixture.canonicalPayload(),
                    fixture.dscKey);
            assertMalformedByDuplicateKey(verify(fixture, token, IndependentStatusListVerifier.StatusListOptions.strictMode()),
                    "the unprotected header carries the key 4 twice");
        }
    }

    /**
     * RFC 8949 5.6.1 compares keys at the data-model level, not as bytes: {@code 02} and the non-preferred
     * {@code 18 02} are the same integer 2 and so the same claim, which Multipaz's decoder also collapses into one.
     */
    @Test
    void aKeyRepeatedInANonPreferredEncodingIsStillADuplicate() {
        Fixture fixture = new Fixture();
        byte[] payload = rawMap(
                enc(claim(2)), enc(new Tstr("https://issuer.example/other")),
                new byte[] {0x18, 0x02}, enc(new Tstr(URI)),
                enc(claim(4)), enc(DataItemExtensionsKt.toDataItem(NOW.plusSeconds(TTL).getEpochSecond())),
                enc(claim(6)), enc(DataItemExtensionsKt.toDataItem(NOW.getEpochSecond())),
                enc(claim(65533)), enc(statusListClaim(1, fixture.zlib(STATUSES))),
                enc(claim(65534)), enc(DataItemExtensionsKt.toDataItem(TTL)));
        assertEquals(1, Cbor.INSTANCE.decode(payload).getAsMap().keySet().stream()
                .filter(key -> key.equals(claim(2))).count(), "Multipaz keeps one claim 2 out of the two encodings");
        assertMalformedByDuplicateKey(verify(fixture, fixture.builder().rawPayload(payload).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode()), "the CWT claims carries the key 2 twice");
    }

    /**
     * Review round 5, 1: keys are compared as RFC 8949 5.6.1 data items, recursively, not as bytes. Claim 999 holds
     * {@code { {1: 1, 2: 2}: 1, {2: 2, 1: 1}: 2 }}: two encodings of one map key ("Two maps are equal if they have the
     * same set of pairs regardless of their order"), which byte comparison let through with every check passing,
     * Multipaz's {@code fromCwt} included.
     */
    @Test
    void aMapKeyRepeatedWithItsPairsInAnotherOrderIsADuplicate() {
        Fixture fixture = new Fixture();
        assertMalformedByDuplicateKey(verify(fixture, tokenWithExtraClaim(fixture, hex("a2a20101020201a20202010102")),
                IndependentStatusListVerifier.StatusListOptions.strictMode()), "the CWT claims → 999 carries the key");
    }

    /**
     * Floats compare by numeric value whatever their width, -0.0 equals 0.0 (RFC 8949 5.6.1), and every NaN is one key
     * (stricter than 5.6.1's significand rule, documented on {@code DuplicateKeys.dataItem}).
     */
    @Test
    void floatKeysOfOneNumericValueAreDuplicatesWhateverTheirWidth() {
        Fixture fixture = new Fixture();
        Map<String, String> maps = new LinkedHashMap<>();
        maps.put("1.0 as f16 and f64", "a2f93c0001fb3ff000000000000002");
        maps.put("1.0 as f32 and f16", "a2fa3f80000001f93c0002");
        maps.put("0.0 and -0.0", "a2f9000001f9800002");
        maps.put("NaN as f16 and f64", "a2f97e0001fb7ff800000000000002");
        maps.forEach((name, map) -> assertMalformedByDuplicateKey(verify(fixture, tokenWithExtraClaim(fixture, hex(map)),
                IndependentStatusListVerifier.StatusListOptions.strictMode()), "the CWT claims → 999 carries the key"));
    }

    /** Arrays compare element by element: {@code [1, 2]} and {@code [18 01, 19 0002]} are one key. */
    @Test
    void arrayKeysWithTheSameElementsInOtherIntegerWidthsAreDuplicates() {
        Fixture fixture = new Fixture();
        assertMalformedByDuplicateKey(verify(fixture, tokenWithExtraClaim(fixture, hex("a28201020182180119000202")),
                IndependentStatusListVerifier.StatusListOptions.strictMode()), "the CWT claims → 999 carries the key");
    }

    /**
     * What RFC 8949 5.6.1 keeps apart stays apart: an integer, the same integer tagged, a bignum, a float and a simple
     * value of the same number; a text string and a byte string of the same bytes; an array and a map; 0 and 0.0.
     * Such a claim is not a duplicate, and the token passes every check.
     */
    @Test
    void distinctDataItemsStayDistinctKeys() {
        Fixture fixture = new Fixture();
        String map = "ab"
                + "01" + "00"            // 1
                + "c101" + "00"          // 1(1): tagged
                + "c24101" + "00"        // 2(h'01'): bignum 1
                + "f93c00" + "00"        // 1.0
                + "e1" + "00"            // simple(1)
                + "6161" + "00"          // "a"
                + "4161" + "00"          // h'61'
                + "820101" + "00"        // [1, 1]
                + "a10101" + "00"        // {1: 1}
                + "00" + "00"            // 0
                + "f90000" + "00";       // 0.0
        VerificationReport report = verify(fixture, tokenWithExtraClaim(fixture, hex(map)),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of(), report.failures(), () -> "eleven distinct keys are not a duplicate: " + report);
    }

    /**
     * Review round 5, 3: the branch where Authlete cannot decode what Multipaz decoded. A text string that is not
     * UTF-8 — RFC 8949 5.3.1's other basic validity error — is decoded by Multipaz to U+FFFD (so two different
     * malformed keys would be one key there) and refused by Authlete, so the token is unreadable.
     */
    @Test
    void aTextStringThatIsNotUtf8MakesTheTokenUnreadable() {
        Fixture fixture = new Fixture();
        assertEquals("\uFFFD", Cbor.INSTANCE.decode(hex("61ff")).getAsTstr(), "Multipaz reads 61 ff as U+FFFD");
        VerificationReport report = verify(fixture, tokenWithExtraClaim(fixture, hex("61ff")),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertOnlyEnvelopeFails(report, "notTagged18", "Authlete cannot decode the CWT claims");
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message().contains("UTF-8"),
                () -> "the reason is the malformed text: " + report.check(IndependentStatusListVerifier.CHECK_ENVELOPE));
    }

    /** The canonical claims, encoded byte for byte, with claim 999 = {@code value} appended; signed by the DSC. */
    private static byte[] tokenWithExtraClaim(Fixture fixture, byte[] value) {
        List<byte[]> entries = new ArrayList<>();
        fixture.canonicalClaims().forEach((key, claimValue) -> {
            entries.add(enc(key));
            entries.add(enc(claimValue));
        });
        entries.add(enc(claim(999)));
        entries.add(value);
        return fixture.builder().rawPayload(rawMap(entries.toArray(byte[][]::new))).build();
    }

    private static byte[] hex(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    /**
     * The control for the hand-built tokens above: the same raw encoding and hand signing, without a repeated key,
     * passes every check — so the duplicate is the only defect those tokens carry.
     */
    @Test
    void aHandSignedTokenWithoutARepeatedKeyPassesEveryCheck() {
        Fixture fixture = new Fixture();
        byte[] protectedHeader = rawMap(
                enc(claim(1)), enc(DataItemExtensionsKt.toDataItem(-7L)),
                enc(claim(16)), enc(new Tstr(IndependentStatusListVerifier.MEDIA_TYPE)),
                enc(claim(33)), enc(new X509CertChain(List.of(fixture.dsc)).toCoseX5Chain(false)));
        byte[] unprotectedHeader = rawMap(enc(claim(4)), enc(new Bstr(new byte[] {1})));
        byte[] payload = rawMap(
                enc(claim(2)), enc(new Tstr(URI)),
                enc(claim(4)), enc(DataItemExtensionsKt.toDataItem(NOW.plusSeconds(TTL).getEpochSecond())),
                enc(claim(6)), enc(DataItemExtensionsKt.toDataItem(NOW.getEpochSecond())),
                enc(claim(65533)), rawMap(enc(new Tstr("bits")), enc(DataItemExtensionsKt.toDataItem(1L)),
                        enc(new Tstr("lst")), enc(new Bstr(fixture.zlib(STATUSES)))),
                enc(claim(65534)), enc(DataItemExtensionsKt.toDataItem(TTL)));
        VerificationReport report = verify(fixture, fixture.signRaw(protectedHeader, unprotectedHeader, payload, fixture.dscKey),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of(), report.failures(), () -> "the hand-signed token is valid: " + report);
        VerificationReport viaBuilder = verify(fixture, fixture.builder().rawPayload(payload).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of(), viaBuilder.failures(), () -> "the raw payload signed by Multipaz is valid: " + viaBuilder);
    }

    /** {@code duplicateKey} and nothing else but notRun: no check reads a map one decoder or another has chosen from. */
    private static void assertMalformedByDuplicateKey(VerificationReport report, String where) {
        assertOnlyEnvelopeFails(report, "duplicateKey", where);
    }

    /** The envelope fails with {@code code} naming {@code where}, and every other token check is notRun. */
    private static void assertOnlyEnvelopeFails(VerificationReport report, String code, String where) {
        Map<String, List<String>> expected = new LinkedHashMap<>();
        expected.put(IndependentStatusListVerifier.CHECK_ENVELOPE, List.of(code));
        for (String check : List.of(IndependentStatusListVerifier.CHECK_TYP, IndependentStatusListVerifier.CHECK_X5CHAIN,
                IndependentStatusListVerifier.CHECK_SIGNATURE, IndependentStatusListVerifier.CHECK_CHAIN,
                IndependentStatusListVerifier.CHECK_ISSUANCE_CHAIN, IndependentStatusListVerifier.CHECK_CLAIMS,
                IndependentStatusListVerifier.CHECK_LIST, IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE)) {
            expected.put(check, List.of("notRun"));
        }
        assertProblems(report, expected);
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message().contains(where),
                () -> "the report names the map and the key (" + where + "): "
                        + report.check(IndependentStatusListVerifier.CHECK_ENVELOPE).message());
    }

    // ---- statusList.typ --------------------------------------------------------------------------------------------

    @Test
    void aMissingTypIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().protectedTyp(null).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_TYP, List.of("missing")));
    }

    @Test
    void aTypOnlyInTheUnprotectedHeaderIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().typInUnprotected().build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_TYP, List.of("unprotected")));
    }

    @Test
    void aTypThatIsNotATextStringIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().protectedTyp(DataItemExtensionsKt.toDataItem(42L)).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_TYP, List.of("notText")));
    }

    @Test
    void theWrongTypIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().protectedTyp(new Tstr("statuslist+cwt")).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_TYP, List.of("wrong")));
    }

    // ---- statusList.x5chain ----------------------------------------------------------------------------------------

    @Test
    void aTokenWithoutX5chainCannotBeVerified() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().noChain().build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_X5CHAIN, List.of("missing"),
                IndependentStatusListVerifier.CHECK_SIGNATURE, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("notRun"),
                IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE, List.of("notRun")));
    }

    @Test
    void anX5chainOnlyInTheUnprotectedHeaderIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().chainInUnprotected().build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_X5CHAIN, List.of("unprotectedOnly")));
    }

    @Test
    void aChainThatCarriesItsOwnAnchorIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.builder().protectedChain(List.of(fixture.dsc, fixture.iaca)).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_X5CHAIN, List.of("carriesAnchor")));
    }

    @Test
    void aSerialThatIsNotPositiveOrIsTooLongIsRefused() {
        Fixture fixture = new Fixture();
        X509Cert zeroSerial = fixture.issued(fixture.statusKey, "Zero Serial Signer", 0L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true);
        VerificationReport report = verify(fixture, fixture.builder().signer(zeroSerial, fixture.statusKey).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_X5CHAIN, List.of("serialNumber")));
    }

    // ---- statusList.signature --------------------------------------------------------------------------------------

    @Test
    void aTamperedSignatureIsRejectedByBothOracles() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tamperedSignature(), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_SIGNATURE,
                List.of("invalid:multipaz", "invalid:authlete")));
    }

    // ---- statusList.chain ------------------------------------------------------------------------------------------

    @Test
    void aTokenThatChainsToADifferentIacaIsUntrusted() {
        Fixture fixture = new Fixture();
        X509Cert foreignSigner = fixture.issuedUnder(fixture.otherIaca, fixture.otherIacaKey, "Foreign DSC", 7L, null, true,
                fixture.foreignKey);
        VerificationReport report = verify(fixture, fixture.builder().signer(foreignSigner, fixture.foreignKey).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), foreignSigner);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    /**
     * The review-round-1 major: {@code fromCwt} caps {@code exp} at {@code maxValidity} (365 days, the Multipaz wallet
     * default {@code CachingRevocationChecker} uses), so a Document Signer valid for the Annex B 457 days cannot carry a
     * list four hundred days out even though every field passes the individual checks. Only the chain check can report
     * it: {@code statusList.chain:untrusted} is "fromCwt refuses".
     */
    @Test
    void anExpFourHundredDaysOutIsRefusedByMultipazsMaxValidity() {
        Fixture fixture = new Fixture();
        X509Cert longLived = fixture.issuedValid(fixture.statusKey, "Long-Lived Status Signer", 21L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true, NOW.minusSeconds(86_400),
                NOW.plusSeconds(457L * 24 * 3600));
        Map<DataItem, DataItem> claims = fixture.canonicalClaims();
        claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(400L * 24 * 3600).getEpochSecond()));
        VerificationReport report = verify(fixture, fixture.builder().signer(longLived, fixture.statusKey).claims(claims).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), longLived);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("maxValidity"),
                "the refusal names maxValidity: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
    }

    /**
     * Review round 2, 1(a): only a failure fromCwt itself makes may explain its refusal. ttl, exp-vs-notAfter, iat-vs-exp,
     * idx and the status are outside its rules, so a maxValidity refusal next to a ttl problem is still the chain's.
     */
    @Test
    void aMaxValidityRefusalIsNotHiddenByACodeFromCwtNeverChecks() {
        Fixture fixture = new Fixture();
        X509Cert longLived = fixture.issuedValid(fixture.statusKey, "Long-Lived Status Signer", 23L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true, NOW.minusSeconds(86_400),
                NOW.plusSeconds(457L * 24 * 3600));
        Map<DataItem, DataItem> claims = fixture.canonicalClaims();
        claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(400L * 24 * 3600).getEpochSecond()));
        claims.put(claim(65534), DataItemExtensionsKt.toDataItem(0L));
        VerificationReport report = verify(fixture, fixture.builder().signer(longLived, fixture.statusKey).claims(claims).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), longLived);
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_CLAIMS, List.of("ttlInvalid"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    @Test
    void theFromCwtAdapterResolvesAgainstThePinnedMultipazJar() {
        java.lang.reflect.Method bridge = IndependentStatusListVerifier.multipazFromCwtBridge();
        assertEquals("fromCwt-myKFqkg$default", bridge.getName(), "the mangled Kotlin bridge this adapter knows");
        assertEquals("org.multipaz.revocation.CompressedStatusList$Companion", bridge.getDeclaringClass().getName());
        assertEquals(9, bridge.getParameterCount(), "receiver, cwt, trustedRootCert, checks, atTime, maxValidity, "
                + "Continuation, mask, marker");
    }

    /**
     * Review round 2, 2: a broken adapter or a changed Multipaz must be the non-declarable {@code error} code with the
     * descriptive message, never {@code statusList.chain:untrusted} (which would blame the credential for a harness
     * defect).
     */
    @Test
    void aBrokenFromCwtAdapterIsAnErrorNotAnUntrustedChain() {
        Fixture fixture = new Fixture();
        String message = "Multipaz 0.102.0 CompressedStatusList$Companion.fromCwt-myKFqkg$default is gone: a Multipaz "
                + "upgrade changed fromCwt";
        try {
            IndependentStatusListVerifier.failMultipazFromCwtAdapterForTest(message);
            VerificationReport report = verify(fixture, fixture.token(), IndependentStatusListVerifier.StatusListOptions.strictMode());
            assertEquals(List.of("error"), report.check(IndependentStatusListVerifier.CHECK_CHAIN).codes(),
                    () -> "a harness defect is an error: " + report);
            assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("changed fromCwt"),
                    () -> "the descriptive message survives: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
            assertEquals(1, report.failures().size(), () -> "nothing else fails: " + report);
        } finally {
            IndependentStatusListVerifier.resetMultipazFromCwtAdapterForTest();
        }
    }

    /** Review round 2, 4: Authlete is handed the wire bytes, so tag 18 around the Multipaz-built token verifies. */
    @Test
    void authleteVerifiesTheWireBytesOfAMultipazBuiltToken() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.token(), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(VerificationReport.State.PASS, report.check(IndependentStatusListVerifier.CHECK_SIGNATURE).state());
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_SIGNATURE).message().contains("Authlete"),
                "both oracles verified: " + report.check(IndependentStatusListVerifier.CHECK_SIGNATURE));
    }

    /**
     * Review round 3, 1: the suppression is decided from the token's state, not from check names, because several
     * check codes also cover shapes Multipaz accepts. Each probe keeps exp = now + 400 days on the Annex B 457-day
     * signer, so {@code fromCwt} refuses on maxValidity; only a defect {@code fromCwt} itself refuses on may explain
     * that, and none of these does.
     */
    @Test
    void aBitsValueMultipazAcceptsDoesNotHideItsMaxValidityRefusal() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 25L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        assertProblems(multipazRefusal(fixture, longLived, exp, claims -> claims.put(claim(65533),
                        statusListClaim(2, fixture.zlib(STATUSES)))),
                Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("bitsNotOne"),
                        IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    @Test
    void anUntaggedCoseSign1DoesNotHideMultipazsMaxValidityRefusal() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 26L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        VerificationReport report = verify(fixture, fixture.builder().signer(longLived, fixture.statusKey)
                        .claims(claimsOf(fixture, exp)).tag(null).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), longLived);
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_ENVELOPE, List.of("notTagged18"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    @Test
    void aFutureIatNextToAnExpDoesNotHideMultipazsMaxValidityRefusal() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 27L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        assertProblems(multipazRefusal(fixture, longLived, exp, claims -> claims.put(claim(6),
                        DataItemExtensionsKt.toDataItem(NOW.plusSeconds(3600).getEpochSecond()))),
                Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("iatFuture"),
                        IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    @Test
    void aGarbageLstBstrDoesNotHideMultipazsMaxValidityRefusal() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 28L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        assertProblems(multipazRefusal(fixture, longLived, exp, claims -> claims.put(claim(65533),
                        statusListClaim(1, new byte[] {(byte) 0xb9, (byte) 0xa3}))),
                Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("lstNotZlib"),
                        IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    private static X509Cert longLived(Fixture fixture, long serial) {
        return fixture.issuedValid(fixture.statusKey, "Long-Lived Status Signer", serial,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true, NOW.minusSeconds(86_400),
                NOW.plusSeconds(457L * 24 * 3600));
    }

    /**
     * Review round 3, 1 (renamed in round 4): with {@code exp} present {@code fromCborMap} never reads {@code ttl}, so
     * {@code fromCwt} accepts a text ttl and only the claims check refuses it — there is no refusal to explain.
     */
    @Test
    void aTextTtlNextToAnExpIsOnlyTtlInvalid() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(65534), new Tstr("3600"))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("ttlInvalid")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().startsWith(
                "CompressedStatusList.fromCwt accepts"), () -> "fromCwt reads no ttl next to an exp: " + report);
    }

    /**
     * Review round 4, nit: the exp-absent branch. {@code fromCborMap} reads {@code ttl.asNumber} only without
     * {@code exp}, so there a text ttl is {@code fromCwt}'s own refusal and is explained by {@code ttlInvalid}: no
     * chain code.
     */
    @Test
    void withoutAnExpATextTtlIsFromCwtsOwnRefusalAndExplainsIt() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> {
                    claims.remove(claim(4));
                    claims.put(claim(65534), new Tstr("3600"));
                }), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expMissing", "ttlInvalid")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("fromCwt refused"),
                () -> "fromCwt refuses, for the reason ttlInvalid reports: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
    }

    /** The same branch for {@code iat}: without {@code exp}, validateCwt refuses an iat more than 5 s ahead itself. */
    @Test
    void withoutAnExpAFutureIatIsFromCwtsOwnRefusalAndExplainsIt() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> {
                    claims.remove(claim(4));
                    claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(3600).getEpochSecond()));
                }), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("iatFuture", "expMissing")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("fromCwt refused"),
                () -> "fromCwt refuses, for the reason iatFuture reports: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
    }

    /**
     * Review round 5, 2: without {@code exp}, validateCwt derives it as {@code iat + maxValidity} and refuses it as
     * expired when that is before now. An iat 366 days old is that refusal, caused by the missing exp, so
     * {@code expMissing} explains it and the chain passes.
     */
    @Test
    void withoutAnExpAnIatOlderThanMaxValidityIsFromCwtsExpiryAndExpMissingExplainsIt() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> {
                    claims.remove(claim(4));
                    claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(366L * 24 * 3600).getEpochSecond()));
                }), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expMissing")));
        VerificationReport.Check chain = report.check(IndependentStatusListVerifier.CHECK_CHAIN);
        assertTrue(chain.message().contains("fromCwt refused") && chain.message().contains("expired"),
                () -> "fromCwt refuses the derived exp as expired, which expMissing explains: " + chain);
    }

    /**
     * Review round 4, 3: validateCwt decides maxValidity right after reading exp, before typ, sub, the signature and
     * the list, so a token past it is refused for maxValidity whatever else is wrong with it, and the chain says so
     * next to the other check's code.
     */
    @Test
    void aWrongTypDoesNotHideAMaxValidityRefusalThatComesFirst() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 29L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        VerificationReport report = verify(fixture, fixture.builder().signer(longLived, fixture.statusKey)
                        .claims(claimsOf(fixture, exp)).protectedTyp(new Tstr("statuslist+cwt")).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), longLived);
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_TYP, List.of("wrong"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("maxValidity"),
                () -> "the chain names the refusal fromCwt actually made: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
    }

    @Test
    void aWrongSubDoesNotHideAMaxValidityRefusalThatComesFirst() {
        Fixture fixture = new Fixture();
        X509Cert longLived = longLived(fixture, 30L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        VerificationReport report = multipazRefusal(fixture, longLived, exp,
                claims -> claims.put(claim(2), new Tstr("https://issuer.example/other")));
        assertProblems(report, Map.of(
                IndependentStatusListVerifier.CHECK_CLAIMS, List.of("subMismatch"),
                IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).message().contains("maxValidity"),
                () -> "the chain names the refusal fromCwt actually made: " + report.check(IndependentStatusListVerifier.CHECK_CHAIN));
    }

    /**
     * Review round 4, 4: {@code fromStatusListClaim} narrows the {@code Uint} bits to an int ({@code l2i}), so
     * {@code 4294967297} is 1 to Multipaz. ISO2 12.3.6.5 still refuses it ({@code bitsNotOne}); next to an exp past
     * maxValidity the chain reports that refusal too.
     */
    @Test
    void aBitsValueMultipazNarrowsToOneIsBitsNotOneAndDoesNotHideMaxValidity() {
        Fixture fixture = new Fixture();
        VerificationReport accepted = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(65533),
                        statusListClaim(4_294_967_297L, fixture.zlib(STATUSES)))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(accepted, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("bitsNotOne")));
        assertTrue(accepted.check(IndependentStatusListVerifier.CHECK_CHAIN).message().startsWith(
                "CompressedStatusList.fromCwt accepts"), () -> "Multipaz reads bits 2^32 + 1 as 1: " + accepted);

        X509Cert longLived = longLived(fixture, 31L);
        long exp = NOW.plusSeconds(400L * 24 * 3600).getEpochSecond();
        assertProblems(multipazRefusal(fixture, longLived, exp, claims -> claims.put(claim(65533),
                        statusListClaim(4_294_967_297L, fixture.zlib(STATUSES)))),
                Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("bitsNotOne"),
                        IndependentStatusListVerifier.CHECK_CHAIN, List.of("untrusted")));
    }

    /**
     * Review round 4: the mirror of {@code fromCwt}'s rules held to {@code fromCwt} itself, token by token. Every
     * token here is within maxValidity and signed by the trusted Document Signer, so {@code fromCwt} refuses exactly
     * when the mirror says a reported defect makes it refuse — including the int narrowing of {@code bits} and the
     * millisecond {@code at} it is handed, which no report shows unless {@code fromCwt} also refuses for a reason no
     * check names.
     */
    @Test
    void theFromCwtMirrorAgreesWithFromCwtTokenByToken() {
        Fixture fixture = new Fixture();
        Map<String, java.util.function.Consumer<Map<DataItem, DataItem>>> mutations = new LinkedHashMap<>();
        for (long bits : new long[] {1, 2, 3, 4, 8, 0, 16, 4_294_967_297L, 4_294_967_298L, 4_294_967_299L, -1}) {
            mutations.put("bits " + bits, claims -> claims.put(claim(65533), statusListClaim(bits, fixture.zlib(STATUSES))));
        }
        mutations.put("bits as text", claims -> {
            Map<DataItem, DataItem> list = new LinkedHashMap<>();
            list.put(new Tstr("bits"), new Tstr("1"));
            list.put(new Tstr("lst"), new Bstr(fixture.zlib(STATUSES)));
            claims.put(claim(65533), new CborMap(list, false));
        });
        mutations.put("garbage lst", claims -> claims.put(claim(65533), statusListClaim(1, new byte[] {(byte) 0xb9})));
        mutations.put("exp at the evaluation instant", claims -> {
            claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.getEpochSecond()));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(60).getEpochSecond()));
        });
        mutations.put("exp a second before", claims -> {
            claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(1).getEpochSecond()));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(60).getEpochSecond()));
        });
        mutations.put("no exp, iat 5 s ahead", claims -> {
            claims.remove(claim(4));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(5).getEpochSecond()));
        });
        mutations.put("no exp, iat 6 s ahead", claims -> {
            claims.remove(claim(4));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(6).getEpochSecond()));
        });
        for (long days : new long[] {364, 365, 366}) {
            mutations.put("no exp, iat " + days + " days ago", claims -> {
                claims.remove(claim(4));
                claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(days * 24 * 3600).getEpochSecond()));
            });
        }
        mutations.put("no exp, text ttl", claims -> {
            claims.remove(claim(4));
            claims.put(claim(65534), new Tstr("3600"));
        });
        mutations.put("text ttl next to exp", claims -> claims.put(claim(65534), new Tstr("3600")));
        mutations.put("wrong sub", claims -> claims.put(claim(2), new Tstr("https://issuer.example/other")));

        Map<String, Instant> instants = new LinkedHashMap<>();
        instants.put("at", NOW);
        instants.put("at + 500 ms", NOW.plusMillis(500));
        instants.put("at + 100 ns", NOW.plusNanos(100));
        List<String> disagreements = new ArrayList<>();
        mutations.forEach((name, mutation) -> instants.forEach((when, at) -> {
            byte[] token = fixture.tokenWithClaims(mutation);
            VerificationReport report = IndependentStatusListVerifier.verify(token, IndependentStatusListVerifier.MEDIA_TYPE,
                    URI, 3, javaCerts(List.of(fixture.dsc)), fixture.iacaJava, at,
                    IndependentStatusListVerifier.StatusListOptions.strictMode());
            VerificationReport.Check chain = report.check(IndependentStatusListVerifier.CHECK_CHAIN);
            assertEquals(VerificationReport.State.PASS, chain.state(), () -> name + " " + when + ": no refusal is "
                    + "unexplained within maxValidity: " + chain);
            boolean refused = !chain.message().startsWith("CompressedStatusList.fromCwt accepts");
            boolean mirror = IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(token, URI, at);
            if (refused != mirror) {
                disagreements.add(name + " " + when + ": fromCwt " + (refused ? "refuses" : "accepts") + ", the mirror says "
                        + (mirror ? "it refuses" : "it accepts"));
            }
        }));
        assertEquals(List.of(), disagreements);
        // the expectations the mirror encodes, spelled out
        assertTrue(!IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(fixture.tokenWithClaims(
                mutations.get("bits 4294967297")), URI, NOW), "Multipaz narrows bits 2^32 + 1 to 1");
        assertTrue(!IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(fixture.tokenWithClaims(
                mutations.get("exp at the evaluation instant")), URI, NOW), "Multipaz accepts exp == at");
        assertTrue(IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(fixture.tokenWithClaims(
                mutations.get("exp at the evaluation instant")), URI, NOW.plusMillis(500)), "and refuses it 500 ms later");
        assertTrue(IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(fixture.tokenWithClaims(
                mutations.get("no exp, iat 366 days ago")), URI, NOW), "an exp derived from an old iat is expired");
        assertTrue(!IndependentStatusListVerifier.fromCwtRefusesOnAReportedDefect(fixture.tokenWithClaims(
                mutations.get("no exp, iat 365 days ago")), URI, NOW), "iat + 365 days == at is accepted");
    }

    private static VerificationReport multipazRefusal(Fixture fixture, X509Cert signer, long exp,
                                                      java.util.function.Consumer<Map<DataItem, DataItem>> mutation) {
        Map<DataItem, DataItem> claims = claimsOf(fixture, exp);
        mutation.accept(claims);
        return verify(fixture, fixture.builder().signer(signer, fixture.statusKey).claims(claims).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), signer);
    }

    /** The canonical claims with exp set. */
    private static Map<DataItem, DataItem> claimsOf(Fixture fixture, long exp) {
        Map<DataItem, DataItem> claims = fixture.canonicalClaims();
        claims.put(claim(4), DataItemExtensionsKt.toDataItem(exp));
        return claims;
    }

    /** A signer past its notAfter at the evaluation instant fails the chain, not a claim, for the trust decision. */
    @Test
    void aSignerExpiredAtTheEvaluationInstantIsUntrusted() {
        Fixture fixture = new Fixture();
        X509Cert expired = fixture.issuedValid(fixture.statusKey, "Expired Status Signer", 22L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true, NOW.minusSeconds(10L * 24 * 3600),
                NOW.minusSeconds(3600));
        Map<DataItem, DataItem> claims = fixture.canonicalClaims();
        claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(7200).getEpochSecond()));
        claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(3 * 3600).getEpochSecond()));
        VerificationReport report = verify(fixture, fixture.builder().signer(expired, fixture.statusKey).claims(claims).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), expired);
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_CHAIN).codes().contains("untrusted"),
                () -> "the chain refuses a signer past notAfter: " + report);
        assertEquals(List.of("expired"), report.check(IndependentStatusListVerifier.CHECK_CLAIMS).codes(),
                "exp is before at too, and that is the claim check's code");
    }

    // ---- statusList.issuanceChain ----------------------------------------------------------------------------------

    @Test
    void aChainThatDiffersFromTheMdlsIssuanceChainIsRefused() {
        Fixture fixture = new Fixture();
        X509Cert otherSigner = fixture.issued(fixture.statusKey, "Status Signer", 11L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true);
        VerificationReport report = verify(fixture, fixture.builder().signer(otherSigner, fixture.statusKey).build(),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_ISSUANCE_CHAIN, List.of("differs")));
    }

    // ---- statusList.claims -----------------------------------------------------------------------------------------

    @Test
    void aSubThatIsNotTheMdlsUriIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(2), new Tstr("https://issuer.example/other"))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("subMismatch")));
    }

    @Test
    void aMissingIatIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.remove(claim(6))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("iatMissing")));
    }

    @Test
    void anIatInTheFutureIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(600).getEpochSecond()))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("iatFuture")));
    }

    @Test
    void aMissingExpIsRefusedEvenThoughTheTokenHasATtl() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.remove(claim(4))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expMissing")));
    }

    @Test
    void anExpiredExpIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> {
                    claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(60).getEpochSecond()));
                    claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(120).getEpochSecond()));
                }), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
    }

    /**
     * Review round 4, 2: TSL 5.2 takes exp from RFC 8392 3.1.4, which is RFC 7519 4.1.4: "the current date/time MUST
     * be before the expiration date/time", so a token is expired from its exp instant on. Multipaz 0.102.0 refuses
     * only {@code exp < now}, so exactly at exp only this check refuses and {@code fromCwt} accepts (no chain code).
     */
    @Test
    void aTokenIsExpiredAtItsExpInstantAndNotASecondBefore() {
        Fixture fixture = new Fixture();
        VerificationReport atExp = verify(fixture, tokenExpiringAt(fixture, NOW), NOW);
        assertProblems(atExp, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
        assertTrue(atExp.check(IndependentStatusListVerifier.CHECK_CHAIN).message().startsWith(
                "CompressedStatusList.fromCwt accepts"), () -> "Multipaz accepts exp == at: " + atExp);
        assertTrue(atExp.check(IndependentStatusListVerifier.CHECK_CLAIMS).message().contains(ALONE_AT_EXP),
                () -> "at exp the message says only this check refuses: " + atExp.check(IndependentStatusListVerifier.CHECK_CLAIMS));

        VerificationReport secondBefore = verify(fixture, tokenExpiringAt(fixture, NOW.plusSeconds(1)), NOW);
        assertEquals(List.of(), secondBefore.failures(), () -> "one second before exp the token is valid: " + secondBefore);

        VerificationReport secondAfter = verify(fixture, tokenExpiringAt(fixture, NOW.minusSeconds(1)), NOW);
        assertProblems(secondAfter, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
        assertTrue(!secondAfter.check(IndependentStatusListVerifier.CHECK_CLAIMS).message().contains(ALONE_AT_EXP),
                () -> "past exp Multipaz refuses too, and the message does not say otherwise: "
                        + secondAfter.check(IndependentStatusListVerifier.CHECK_CLAIMS));
    }

    /** The sentence the expired message adds only when Multipaz, handed {@code at} in milliseconds, accepts exp. */
    static final String ALONE_AT_EXP = "exactly at exp this check alone refuses";

    /**
     * A fractional evaluation instant is compared at full precision: expired when {@code at >= exp}, so half a second
     * after exp is expired and half a second before is not.
     */
    @Test
    void aFractionalEvaluationInstantIsComparedWithExpAtFullPrecision() {
        Fixture fixture = new Fixture();
        byte[] token = tokenExpiringAt(fixture, NOW);
        VerificationReport halfSecondAfter = verify(fixture, token, NOW.plusMillis(500));
        assertProblems(halfSecondAfter, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
        assertTrue(!halfSecondAfter.check(IndependentStatusListVerifier.CHECK_CLAIMS).message().contains(ALONE_AT_EXP),
                "500 ms after exp Multipaz refuses too");
        VerificationReport nanoAfter = verify(fixture, token, NOW.plusNanos(1));
        assertProblems(nanoAfter, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
        assertTrue(nanoAfter.check(IndependentStatusListVerifier.CHECK_CLAIMS).message().contains(ALONE_AT_EXP),
                "1 ns after exp Multipaz, handed milliseconds, still accepts");
        VerificationReport before = verify(fixture, token, NOW.minusMillis(500));
        assertEquals(List.of(), before.failures(), () -> "half a second before exp the token is valid: " + before);
        VerificationReport nanoBefore = verify(fixture, token, NOW.minusNanos(1));
        assertEquals(List.of(), nanoBefore.failures(), () -> "1 ns before exp the token is valid: " + nanoBefore);
    }

    /** A token whose exp is {@code exp}, issued a minute before it. */
    private static byte[] tokenExpiringAt(Fixture fixture, Instant exp) {
        return fixture.tokenWithClaims(claims -> {
            claims.put(claim(4), DataItemExtensionsKt.toDataItem(exp.getEpochSecond()));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(exp.minusSeconds(60).getEpochSecond()));
        });
    }

    @Test
    void anExpAfterTheSignersNotAfterIsRefused() {
        Fixture fixture = new Fixture();
        // a short-lived signer keeps exp inside Multipaz's 365-day maxValidity, so this mutation isolates notAfter
        X509Cert shortLived = fixture.issuedValid(fixture.statusKey, "Short-Lived Status Signer", 24L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true, NOW.minusSeconds(86_400),
                NOW.plusSeconds(30L * 24 * 3600));
        long afterSigner = shortLived.getValidityNotAfter().toEpochMilliseconds() / 1000 + 3600;
        VerificationReport report = verify(fixture, fixture.builder().signer(shortLived, fixture.statusKey).claims(
                        withExp(fixture.canonicalClaims(), afterSigner)).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, true), shortLived);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expAfterSigner")));
    }

    private static Map<DataItem, DataItem> withExp(Map<DataItem, DataItem> claims, long exp) {
        claims.put(claim(4), DataItemExtensionsKt.toDataItem(exp));
        return claims;
    }

    @Test
    void anIatAfterExpIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> {
                    claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(1).getEpochSecond()));
                    claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(4).getEpochSecond()));
                }), IndependentStatusListVerifier.StatusListOptions.strictMode(), fixture.dsc, 3);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("iatAfterExp")));
    }

    @Test
    void aTtlOfZeroIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(65534), DataItemExtensionsKt.toDataItem(0L))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("ttlInvalid")));
    }

    @Test
    void aTtlThatIsNotAPositiveUnsignedIntegerIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(65534), DataItemExtensionsKt.toDataItem(-1L))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("ttlInvalid")));
    }

    // ---- statusList.list -------------------------------------------------------------------------------------------

    @Test
    void aMissingStatusListClaimIsItsOwnCode() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.remove(claim(65533))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("missing")));
    }

    @Test
    void aBitsValueOtherThanOneIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(65533),
                        statusListClaim(2, fixture.zlib(STATUSES)))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("bitsNotOne")));
    }

    @Test
    void anLstThatIsNotZlibIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(65533),
                        statusListClaim(1, new byte[] {(byte) 0xb9, (byte) 0xa3}))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("lstNotZlib")));
    }

    @Test
    void aRawDeflateLstWithoutTheZlibWrapperIsRefused() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(claims -> claims.put(claim(65533),
                        statusListClaim(1, rawDeflate(STATUSES)))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("lstNotZlib")));
    }

    @Test
    void anIndexOutsideTheListIsRejected() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.token(), fixture.iacaJava,
                IndependentStatusListVerifier.StatusListOptions.strictMode(), fixture.dsc, 100_000);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("idxOutOfRange")));
    }

    @Test
    void aStatusOtherThanTheExpectedOneNamesTheStatusItFound() {
        Fixture fixture = new Fixture();
        byte[] statuses = new byte[32];
        statuses[0] = 0b0000_0001; // idx 0 INVALID
        VerificationReport report = verify(fixture, fixture.token(statuses, TTL, URI, NOW, fixture.dsc),
                IndependentStatusListVerifier.StatusListOptions.strictMode(), fixture.dsc, 0);
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_LIST, List.of("statusMismatch:1")));
    }

    // ---- statusList.signerPurpose ----------------------------------------------------------------------------------

    @Test
    void aDedicatedSignerWithoutTheStatusSigningEkuIsRefused() {
        Fixture fixture = new Fixture();
        X509Cert noEku = fixture.issued(fixture.statusKey, "Status Signer", 12L, List.of(), true);
        VerificationReport report = verify(fixture, fixture.builder().signer(noEku, fixture.statusKey).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE, List.of("ekuMissing")));
    }

    @Test
    void aDedicatedSignerWithoutDigitalSignatureKeyUsageIsRefused() {
        Fixture fixture = new Fixture();
        X509Cert noKeyUsage = fixture.issued(fixture.statusKey, "Status Signer", 13L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), false);
        VerificationReport report = verify(fixture, fixture.builder().signer(noKeyUsage, fixture.statusKey).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE, List.of("kuMissing")));
    }

    @Test
    void aDedicatedSignerWithTheEkuAndDigitalSignaturePasses() {
        Fixture fixture = new Fixture();
        X509Cert dedicated = fixture.issued(fixture.statusKey, "Status Signer", 14L,
                List.of(IndependentStatusListVerifier.STATUS_SIGNING_EKU), true);
        VerificationReport report = verify(fixture, fixture.builder().signer(dedicated, fixture.statusKey).build(),
                new IndependentStatusListVerifier.StatusListOptions(true, 0, false));
        assertEquals(List.of(), report.failures(), () -> "a well-formed dedicated signer passes: " + report);
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_ISSUANCE_CHAIN).skipped(),
                "requireIssuanceChain=false is skipped visibly");
    }

    @Test
    void aListSignedWithTheMdlsOwnDocumentSignerNeedsNoSeparatePurpose() {
        Fixture fixture = new Fixture();
        VerificationReport report = verify(fixture, fixture.token(), IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(VerificationReport.State.PASS, report.check(IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE).state());
        assertTrue(report.check(IndependentStatusListVerifier.CHECK_SIGNER_PURPOSE).message().contains("own Document Signer"));
    }

    // ---- the MSO reference and the combined gap set (review round 1) -----------------------------------------------

    /**
     * A present-but-malformed {@code status.status_list} must fail the sample instead of skipping the list: a wallet
     * that cannot read {@code {uri, idx}} cannot fetch the list at all. Each malformed shape carries its own reason,
     * and an absent status (or an unreadable MSO, which stays M-01's) is not malformed.
     */
    @Test
    void everyMalformedMsoStatusListShapeIsMalformedWithItsReason() {
        Fixture fixture = new Fixture();
        record Case(String label, DataItem status, String reason) {}
        List<Case> cases = List.of(
                new Case("idx as text", statusWith(statusListMap(new Tstr(URI), new Tstr("3"))), "idx"),
                new Case("idx negative", statusWith(statusListMap(new Tstr(URI), DataItemExtensionsKt.toDataItem(-1L))), "idx"),
                new Case("idx missing", statusWith(statusListMap(new Tstr(URI), null)), "idx"),
                new Case("uri missing", statusWith(statusListMap(null, DataItemExtensionsKt.toDataItem(3L))), "uri"),
                new Case("uri as a bstr", statusWith(statusListMap(new Bstr(new byte[] {1}), DataItemExtensionsKt.toDataItem(3L))), "uri"),
                new Case("status_list as an array", statusWith(new org.multipaz.cbor.CborArray(List.of(), false)), "status_list"),
                new Case("status as text", new Tstr("status_list"), "status is"));
        for (Case testCase : cases) {
            MdocSamples.StatusListReference reference = MdocSamples.statusListReferenceOf(
                    fixture.issuerSignedWithStatusItem(testCase.status()));
            assertTrue(reference.isMalformed(), () -> testCase.label() + " must be malformed, was " + reference);
            assertTrue(reference.malformed().orElseThrow().contains(testCase.reason()),
                    () -> testCase.label() + " names " + testCase.reason() + ": " + reference.malformed().orElseThrow());
            VerificationReport report = new VerificationReport(List.of(
                    IndependentStatusListVerifier.mso(reference.malformed().orElse(null))));
            assertEquals(List.of("malformed"), report.check(IndependentStatusListVerifier.CHECK_MSO).codes(),
                    () -> testCase.label() + " must fail statusList.mso:malformed");
        }

        assertEquals(MdocSamples.StatusListReference.absent(),
                MdocSamples.statusListReferenceOf(fixture.issuerSignedWithStatusItem(null)),
                "a credential without status is absent, not malformed");
        assertEquals(MdocSamples.StatusListReference.absent(),
                MdocSamples.statusListReferenceOf(fixture.issuerSignedWithStatusItem(new CborMap(new LinkedHashMap<>(), false))),
                "ISO/IEC 18013-5 second edition 12.3.6: status: {} has no status_list and is valid");
        Map<DataItem, DataItem> identifierList = new LinkedHashMap<>();
        identifierList.put(new Tstr("id"), new Tstr("x"));
        assertEquals(MdocSamples.StatusListReference.absent(),
                MdocSamples.statusListReferenceOf(fixture.issuerSignedWithStatusItem(
                        statusWithIdentifierList(new CborMap(identifierList, false)))),
                "a status map with identifier_list only is valid and has no status list (12.3.6)");
        assertEquals(MdocSamples.StatusListReference.present(new MdocSamples.StatusListInfo(URI, 3)),
                MdocSamples.statusListReferenceOf(fixture.issuerSignedWithStatus(URI, 3)),
                "a well-formed reference is present, not malformed");
        assertEquals(MdocSamples.StatusListReference.absent(),
                MdocSamples.statusListReferenceOf("not a credential".getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                "an unreadable IssuerAuth stays M-01's problem and is not this check's failure");
    }

    /**
     * Review round 2, 1(b): one sidecar, one combined report, but only {@code statusList.mso:malformed} is declarable.
     * M-11e's samples must pass with no other {@code statusList.*} gap, so a line for one is refused when the sidecar is
     * parsed instead of being accepted; the combined matching itself stays exact both ways.
     */
    @Test
    void oneGapSetCoversBothReportsAndOnlyTheMalformedMsoGapIsDeclarable() {
        Fixture fixture = new Fixture();
        VerificationReport listReport = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(2), new Tstr("https://issuer.example/other"))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertEquals(List.of("subMismatch"), listReport.check(IndependentStatusListVerifier.CHECK_CLAIMS).codes());
        List<VerificationReport.Check> checks = new ArrayList<>();
        checks.add(VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_SHAPE, "the credential is a bare IssuerSigned"));
        checks.addAll(listReport.checks());
        VerificationReport combined = new VerificationReport(checks);

        assertThrows(AssertionError.class, () -> AcceptedGaps.none().assertMatches(combined, "a-synthetic-sample"),
                "an undeclared statusList problem fails the combined set");
        for (String[] refused : List.of(
                new String[] {"statusList.claims", "subMismatch"},
                new String[] {"statusList.list", "missing"},
                new String[] {"statusList.chain", "untrusted"},
                new String[] {"statusList.envelope", "notTagged18"})) {
            assertTrue(assertThrowsIllegalArgument(() -> AcceptedGaps.none()
                            .gap(refused[0], refused[1], "review round 2: not declarable")),
                    refused[0] + ":" + refused[1] + " must not be declarable");
        }

        AcceptedGaps malformed = AcceptedGaps.none().gap(IndependentStatusListVerifier.CHECK_MSO, "malformed",
                "the sample's MSO reference is malformed; M-11e fixes the list defects instead");
        VerificationReport malformedReport = new VerificationReport(List.of(
                VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_SHAPE, "the credential is a bare IssuerSigned"),
                IndependentStatusListVerifier.mso("status_list.idx is text, not the unsigned integer TSL 6.3 requires")));
        malformed.assertMatches(malformedReport, "a-synthetic-sample");
        assertThrows(AssertionError.class,
                () -> malformed.assertMatches(combined, "a-synthetic-sample"),
                "a declared statusList.mso:malformed that is no longer reported fails too");
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------

    /** Every problem of the whole report, as {@code check -> codes}; an unexpected check or code is a test failure. */
    private static void assertProblems(VerificationReport report, Map<String, List<String>> expected) {
        Map<String, List<String>> actual = new LinkedHashMap<>();
        for (VerificationReport.Check check : report.checks()) {
            if (!check.problems().isEmpty()) {
                actual.put(check.name(), check.codes());
            }
        }
        assertEquals(expected, actual, () -> "the mutation must fire exactly its codes: " + report);
    }

    private static VerificationReport verify(Fixture fixture, byte[] body,
                                            IndependentStatusListVerifier.StatusListOptions options) {
        return verify(fixture, body, options, fixture.dsc, 3);
    }

    private static VerificationReport verifyWithoutAnchor(Fixture fixture, byte[] body,
                                                          IndependentStatusListVerifier.StatusListOptions options) {
        return IndependentStatusListVerifier.verify(body, IndependentStatusListVerifier.MEDIA_TYPE, URI, 3,
                javaCerts(List.of(fixture.dsc)), null, NOW, options);
    }

    /** The same checks with a caller-chosen Content-Type, for the media-type mutation. */
    private static VerificationReport verify(Fixture fixture, byte[] body, String contentType,
                                            IndependentStatusListVerifier.StatusListOptions options) {
        return IndependentStatusListVerifier.verify(body, contentType, URI, 3, javaCerts(List.of(fixture.dsc)),
                fixture.iacaJava, NOW, options);
    }

    private static VerificationReport verify(Fixture fixture, byte[] body,
                                            IndependentStatusListVerifier.StatusListOptions options,
                                            X509Cert issuanceLeaf) {
        return verify(fixture, body, options, issuanceLeaf, 3);
    }

    private static VerificationReport verify(Fixture fixture, byte[] body,
                                            IndependentStatusListVerifier.StatusListOptions options,
                                            X509Cert issuanceLeaf, long idx) {
        return verify(fixture, body, fixture.iacaJava, options, issuanceLeaf, idx);
    }

    private static VerificationReport verify(Fixture fixture, byte[] body, X509Certificate iaca,
                                            IndependentStatusListVerifier.StatusListOptions options) {
        return verify(fixture, body, iaca, options, fixture.dsc, 3);
    }

    private static VerificationReport verify(Fixture fixture, byte[] body, X509Certificate iaca,
                                            IndependentStatusListVerifier.StatusListOptions options,
                                            X509Cert issuanceLeaf) {
        return verify(fixture, body, iaca, options, issuanceLeaf, 3);
    }

    /**
     * The one call under test: the mDL's IssuerAuth chain is the leaf alone (HAIP keeps the IACA out of it), so the
     * list's protected chain equals it for the Document Signer the sample stands for.
     */
    private static VerificationReport verify(Fixture fixture, byte[] body, X509Certificate iaca,
                                            IndependentStatusListVerifier.StatusListOptions options,
                                            X509Cert issuanceLeaf, long idx) {
        return IndependentStatusListVerifier.verify(body, IndependentStatusListVerifier.MEDIA_TYPE, URI, idx,
                javaCerts(List.of(issuanceLeaf)), iaca, NOW, options);
    }

    /** The verifier at a caller-chosen evaluation instant, otherwise as {@link #verify(Fixture, byte[], IndependentStatusListVerifier.StatusListOptions)}. */
    private static VerificationReport verify(Fixture fixture, byte[] body, Instant at) {
        return IndependentStatusListVerifier.verify(body, IndependentStatusListVerifier.MEDIA_TYPE, URI, 3,
                javaCerts(List.of(fixture.dsc)), fixture.iacaJava, at, IndependentStatusListVerifier.StatusListOptions.strictMode());
    }

    private static byte[] enc(DataItem item) {
        return Cbor.INSTANCE.encode(item);
    }

    /**
     * A definite-length CBOR map written byte for byte from already-encoded keys and values, alternating — the only
     * way to put a key on the wire twice, since every encoder builds its map from a map.
     */
    private static byte[] rawMap(byte[]... keysAndValues) {
        int entries = keysAndValues.length / 2;
        if (keysAndValues.length % 2 != 0 || entries > 23) {
            throw new IllegalArgumentException("key/value pairs, at most 23");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa0 | entries);
        for (byte[] encoded : keysAndValues) {
            out.writeBytes(encoded);
        }
        return out.toByteArray();
    }

    private static boolean assertThrowsIllegalArgument(Runnable runnable) {
        try {
            runnable.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static DataItem claim(long number) {
        return DataItemExtensionsKt.toDataItem(number);
    }

    private static DataItem statusListClaim(long bits, byte[] lst) {
        Map<DataItem, DataItem> map = new LinkedHashMap<>();
        map.put(new Tstr("bits"), DataItemExtensionsKt.toDataItem(bits));
        map.put(new Tstr("lst"), new Bstr(lst));
        return new CborMap(map, false);
    }

    /** DEFLATE without the zlib wrapper (RFC 1951), the shape TSL 4.3 does not define for {@code lst}. */
    private static byte[] rawDeflate(byte[] bytes) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        try {
            deflater.setInput(bytes);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            while (!deflater.finished()) {
                out.write(buffer, 0, deflater.deflate(buffer));
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    private static DataItem statusWith(DataItem statusListValue) {
        Map<DataItem, DataItem> status = new LinkedHashMap<>();
        status.put(new Tstr("status_list"), statusListValue);
        return new CborMap(status, false);
    }

    private static DataItem statusWithIdentifierList(DataItem identifierListValue) {
        Map<DataItem, DataItem> status = new LinkedHashMap<>();
        status.put(new Tstr("identifier_list"), identifierListValue);
        return new CborMap(status, false);
    }

    private static DataItem statusListMap(DataItem uri, DataItem idx) {
        Map<DataItem, DataItem> map = new LinkedHashMap<>();
        if (uri != null) {
            map.put(new Tstr("uri"), uri);
        }
        if (idx != null) {
            map.put(new Tstr("idx"), idx);
        }
        return new CborMap(map, false);
    }

    private static byte[] wrap(long tag, byte[] body) {
        return Cbor.INSTANCE.encode(new Tagged(tag, Cbor.INSTANCE.decode(body)));
    }

    private static List<X509Certificate> javaCerts(List<X509Cert> certificates) {
        return X509CertChainJvmKt.getJavaX509Certificates(new X509CertChain(certificates));
    }

    private static X509Certificate javaCert(X509Cert certificate) {
        return javaCerts(List.of(certificate)).get(0);
    }

    static kotlin.time.Instant kotlinInstant(Instant instant) {
        return kotlin.time.Instant.Companion.fromEpochMilliseconds(instant.toEpochMilli());
    }

    static <T> T await(Function<Continuation<? super T>, Object> block) {
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
            throw new IllegalStateException("interrupted while building the status-list fixture", e);
        }
    }

    /**
     * An IACA and a Document Signer built by Multipaz itself ({@link MdocUtil}), and the tokens the tests mutate.
     * Nothing here uses Certify code: a fixture bug cannot make the verifier agree with the writer.
     */
    static final class Fixture {

        final Instant notBefore = NOW.minusSeconds(86_400);
        final Instant notAfter = NOW.plusSeconds(365L * 24 * 3600);
        final EcPrivateKey iacaKey = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.createEcPrivateKey(EcCurve.P256, continuation));
        final EcPrivateKey dscKey = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.createEcPrivateKey(EcCurve.P256, continuation));
        final EcPrivateKey statusKey = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.createEcPrivateKey(EcCurve.P256, continuation));
        final EcPrivateKey otherIacaKey = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.createEcPrivateKey(EcCurve.P256, continuation));
        final EcPrivateKey foreignKey = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.createEcPrivateKey(EcCurve.P256, continuation));
        final X509Cert iaca;
        final X509Cert dsc;
        final X509Cert otherIaca;
        final X509Certificate iacaJava;
        final X509Certificate dscJava;

        Fixture() {
            AsymmetricKey iacaAsymmetric = AsymmetricKey.Companion.anonymous(iacaKey, Algorithm.ES256);
            iaca = await(continuation -> MdocUtil.INSTANCE.generateIacaCertificate(iacaAsymmetric,
                    X500Name.Companion.fromName("CN=Test IACA,C=IN"), new ASN1Integer(1L, 2), kotlinInstant(notBefore),
                    kotlinInstant(notAfter), "https://iaca.example", "https://iaca.example/crl", continuation));
            dsc = await(continuation -> MdocUtil.INSTANCE.generateDsCertificate(certified(iaca, iacaKey), dscKey.getPublicKey(),
                    X500Name.Companion.fromName("CN=Test DSC,C=IN"), new ASN1Integer(2L, 2), kotlinInstant(notBefore),
                    kotlinInstant(notAfter), continuation));
            AsymmetricKey otherAsymmetric = AsymmetricKey.Companion.anonymous(otherIacaKey, Algorithm.ES256);
            otherIaca = await(continuation -> MdocUtil.INSTANCE.generateIacaCertificate(otherAsymmetric,
                    X500Name.Companion.fromName("CN=Other IACA,C=IN"), new ASN1Integer(3L, 2), kotlinInstant(notBefore),
                    kotlinInstant(notAfter), "https://other.example", "https://other.example/crl", continuation));
            iacaJava = javaCert(iaca);
            dscJava = javaCert(dsc);
        }

        /** A status-list token carrying all VALID statuses, exactly as Multipaz's own issuer serialises one. */
        byte[] token() {
            return token(STATUSES, TTL, URI, NOW, dsc);
        }

        byte[] token(byte[] statuses, long ttl, String sub, Instant issuedAt, X509Cert signer) {
            CompressedStatusList list = compressed(statuses, ttl, issuedAt);
            AsymmetricKey key = new AsymmetricKey.X509CertifiedExplicit(new X509CertChain(List.of(signer)),
                    signer == dsc ? dscKey : statusKey, Algorithm.ES256);
            return await(continuation -> list.serializeAsCwt(key, sub, continuation));
        }

        CompressedStatusList compressed(byte[] statuses, long ttl, Instant issuedAt) {
            byte[] deflated = zlib(statuses);
            return new CompressedStatusList(1, new ByteString(deflated, 0, deflated.length),
                    kotlinInstant(issuedAt), kotlinInstant(issuedAt.plusSeconds(ttl)));
        }

        byte[] zlib(byte[] bytes) {
            return await(continuation -> CompressionKt.zlibDeflate(bytes, 9, continuation));
        }

        /** A token whose claims are the canonical ones with {@code mutation} applied; signed by the Document Signer. */
        byte[] tokenWithClaims(java.util.function.Consumer<Map<DataItem, DataItem>> mutation) {
            Map<DataItem, DataItem> claims = canonicalClaims();
            mutation.accept(claims);
            return builder().claims(claims).build();
        }

        Map<DataItem, DataItem> canonicalClaims() {
            Map<DataItem, DataItem> claims = new LinkedHashMap<>();
            claims.put(claim(2), new Tstr(URI));
            claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.plusSeconds(TTL).getEpochSecond()));
            claims.put(claim(6), DataItemExtensionsKt.toDataItem(NOW.getEpochSecond()));
            claims.put(claim(65533), statusListClaim(1, zlib(STATUSES)));
            claims.put(claim(65534), DataItemExtensionsKt.toDataItem(TTL));
            return claims;
        }

        Builder builder() {
            return new Builder(this);
        }

        /** The canonical claims as the encoded payload a signer signs. */
        byte[] canonicalPayload() {
            return Cbor.INSTANCE.encode(new CborMap(canonicalClaims(), false));
        }

        /** The canonical protected header {1: -7, 16: typ, 33: [DSC]}, encoded. */
        byte[] canonicalProtectedHeader() {
            Map<DataItem, DataItem> headers = new LinkedHashMap<>();
            headers.put(claim(1), DataItemExtensionsKt.toDataItem(-7L));
            headers.put(claim(16), new Tstr(IndependentStatusListVerifier.MEDIA_TYPE));
            headers.put(claim(33), new X509CertChain(List.of(dsc)).toCoseX5Chain(false));
            return Cbor.INSTANCE.encode(new CborMap(headers, false));
        }

        /**
         * A tag-18 COSE_Sign1 over raw header bytes, signed by hand (RFC 9052 4.4: Sig_structure =
         * ["Signature1", protected, external_aad h'', payload], ES256 with Multipaz's own {@code Crypto.sign}), for the
         * headers no encoder can produce because they carry a label twice. The bytes of {@code protectedHeader},
         * {@code unprotectedMap} and {@code payload} go on the wire exactly as given.
         */
        byte[] signRaw(byte[] protectedHeader, byte[] unprotectedMap, byte[] payload, EcPrivateKey key) {
            byte[] toBeSigned = Cbor.INSTANCE.encode(new org.multipaz.cbor.CborArray(List.of(new Tstr("Signature1"),
                    new Bstr(protectedHeader), new Bstr(new byte[0]), new Bstr(payload)), false));
            org.multipaz.crypto.EcSignature signature = await(continuation -> org.multipaz.crypto.Crypto.INSTANCE.sign(key,
                    Algorithm.ES256, toBeSigned, continuation));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0xd2); // tag 18
            out.write(0x84); // array(4)
            out.writeBytes(Cbor.INSTANCE.encode(new Bstr(protectedHeader)));
            out.writeBytes(unprotectedMap);
            out.writeBytes(Cbor.INSTANCE.encode(new Bstr(payload)));
            out.writeBytes(Cbor.INSTANCE.encode(new Bstr(signature.toCoseEncoded())));
            return out.toByteArray();
        }

        /** The positive token with the last signature byte flipped, so both oracles must reject it. */
        byte[] tamperedSignature() {
            DataItem decoded = Cbor.INSTANCE.decode(token());
            List<DataItem> array = decoded.getAsTagged().getAsArray();
            byte[] signature = array.get(3).getAsBstr();
            signature[signature.length - 1] ^= 0x01;
            List<DataItem> tampered = new ArrayList<>(array);
            tampered.set(3, new Bstr(signature));
            return Cbor.INSTANCE.encode(new Tagged(18L, new org.multipaz.cbor.CborArray(tampered, false)));
        }

        /**
         * A minimal {@code IssuerSigned} whose MSO carries {@code status.status_list {uri, idx}}, signed by the
         * Document Signer with the IssuerAuth x5chain in the unprotected header — enough for the sample reader and the
         * status-list verifier, and not a credential M-01 would accept (its MSO has no namespaces of its own).
         */
        byte[] issuerSignedWithStatus(String uri, long idx) {
            return issuerSignedWithStatusItem(statusWith(statusListMap(new Tstr(uri), DataItemExtensionsKt.toDataItem(idx))));
        }

        /** The same credential with {@code status} set to {@code statusItem}, or without a status key when null. */
        byte[] issuerSignedWithStatusItem(DataItem statusItem) {
            Map<DataItem, DataItem> mso = new LinkedHashMap<>();
            mso.put(new Tstr("version"), new Tstr("1.0"));
            mso.put(new Tstr("docType"), new Tstr("org.iso.18013.5.1.mDL"));
            if (statusItem != null) {
                mso.put(new Tstr("status"), statusItem);
            }
            byte[] msoBytes = Cbor.INSTANCE.encode(new CborMap(mso, false));
            byte[] payload = Cbor.INSTANCE.encode(new Tagged(24L, new Bstr(msoBytes)));
            Map<CoseLabel, DataItem> unprotected = new LinkedHashMap<>();
            unprotected.put(new CoseNumberLabel(33), new X509CertChain(List.of(dsc)).toCoseX5Chain(false));
            CoseSign1 issuerAuth = await(continuation -> Cose.INSTANCE.coseSign1Sign(
                    AsymmetricKey.Companion.anonymous(dscKey, Algorithm.ES256), payload, true,
                    Map.of(new CoseNumberLabel(1), DataItemExtensionsKt.toDataItem(-7L)), unprotected, continuation));
            Map<DataItem, DataItem> issuerSigned = new LinkedHashMap<>();
            issuerSigned.put(new Tstr("nameSpaces"), new CborMap(new LinkedHashMap<>(), false));
            issuerSigned.put(new Tstr("issuerAuth"), issuerAuth.toDataItem());
            return Cbor.INSTANCE.encode(new CborMap(issuerSigned, false));
        }

        /** A certificate for {@code subjectKey}, issued by this fixture's IACA, with the given EKU (none when empty). */
        X509Cert issued(EcPrivateKey subjectKey, String commonName, long serial, List<String> eku, boolean digitalSignature) {
            return issuedUnder(iaca, iacaKey, commonName, serial, eku, digitalSignature, subjectKey);
        }

        /** The same, with its own validity window (the Annex B 457-day cap, an expired signer). */
        X509Cert issuedValid(EcPrivateKey subjectKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature, Instant validFrom, Instant validUntil) {
            return issuedUnder(iaca, iacaKey, commonName, serial, eku, digitalSignature, subjectKey, validFrom, validUntil);
        }

        X509Cert issuedUnder(X509Cert anchor, EcPrivateKey anchorKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature) {
            return issuedUnder(anchor, anchorKey, commonName, serial, eku, digitalSignature, statusKey);
        }

        X509Cert issuedUnder(X509Cert anchor, EcPrivateKey anchorKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature, EcPrivateKey subjectKey) {
            return issuedUnder(anchor, anchorKey, commonName, serial, eku, digitalSignature, subjectKey, notBefore, notAfter);
        }

        X509Cert issuedUnder(X509Cert anchor, EcPrivateKey anchorKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature, EcPrivateKey subjectKey, Instant validFrom, Instant validUntil) {
            org.multipaz.crypto.X509Cert.Builder builder = new org.multipaz.crypto.X509Cert.Builder(subjectKey.getPublicKey(),
                    certified(anchor, anchorKey), new ASN1Integer(serial, 2),
                    X500Name.Companion.fromName("CN=" + commonName + ",C=IN"), anchor.getSubject(),
                    kotlinInstant(validFrom), kotlinInstant(validUntil))
                    .includeSubjectKeyIdentifier(true)
                    .setAuthorityKeyIdentifierToCertificate(anchor);
            if (digitalSignature) {
                builder.setKeyUsage(Set.of(X509KeyUsage.DIGITAL_SIGNATURE));
            }
            if (eku != null && !eku.isEmpty()) {
                builder.addExtension(OID.X509_EXTENSION_EXTENDED_KEY_USAGE.getOid(), true, ASN1.INSTANCE.encode(
                        new ASN1Sequence(eku.stream().map(ASN1ObjectIdentifier::new).map(o -> (org.multipaz.asn1.ASN1Object) o).toList())));
            }
            org.multipaz.crypto.X509Cert.Builder self = builder;
            return await(continuation -> self.build(continuation));
        }

        static AsymmetricKey.X509CertifiedExplicit certified(X509Cert certificate, EcPrivateKey key) {
            return new AsymmetricKey.X509CertifiedExplicit(new X509CertChain(List.of(certificate)), key, Algorithm.ES256);
        }
    }

    /** A token under construction: every header and body field a mutation needs can be moved, dropped or retyped. */
    static final class Builder {

        private final Fixture fixture;
        private List<X509Cert> protectedChain;
        private List<X509Cert> unprotectedChain = List.of();
        private DataItem protectedTyp = new Tstr(IndependentStatusListVerifier.MEDIA_TYPE);
        private boolean typInUnprotected;
        private boolean chainInUnprotected;
        private boolean noChain;
        private DataItem alg = DataItemExtensionsKt.toDataItem(-7L);
        private Map<DataItem, DataItem> claims;
        /** The payload bytes as signed, when a mutation needs an encoding no map can produce (a key twice). */
        private byte[] rawPayload;
        private Long tag = 18L;
        private boolean detached;
        private EcPrivateKey signerKey;
        private X509Cert signerCertificate;

        Builder(Fixture fixture) {
            this.fixture = fixture;
            this.signerKey = fixture.dscKey;
            this.signerCertificate = fixture.dsc;
            this.protectedChain = List.of(fixture.dsc);
            this.claims = fixture.canonicalClaims();
        }

        Builder protectedTyp(DataItem typ) {
            this.protectedTyp = typ;
            return this;
        }

        Builder typInUnprotected() {
            this.typInUnprotected = true;
            return this;
        }

        Builder protectedChain(List<X509Cert> chain) {
            this.protectedChain = chain;
            return this;
        }

        Builder chainInUnprotected() {
            this.chainInUnprotected = true;
            return this;
        }

        Builder noChain() {
            this.noChain = true;
            return this;
        }

        Builder tag(Long tag) {
            this.tag = tag;
            return this;
        }

        Builder detached() {
            this.detached = true;
            return this;
        }

        Builder claims(Map<DataItem, DataItem> claims) {
            this.claims = claims;
            return this;
        }

        Builder rawPayload(byte[] payload) {
            this.rawPayload = payload;
            return this;
        }

        Builder signer(X509Cert certificate, EcPrivateKey key) {
            this.signerCertificate = certificate;
            this.signerKey = key;
            if (protectedChain != null && protectedChain.size() == 1) {
                this.protectedChain = List.of(certificate);
            }
            return this;
        }

        byte[] build() {
            Map<CoseLabel, DataItem> protectedHeaders = new LinkedHashMap<>();
            Map<CoseLabel, DataItem> unprotectedHeaders = new LinkedHashMap<>();
            if (alg != null) {
                protectedHeaders.put(new CoseNumberLabel(1), alg);
            }
            if (protectedTyp != null) {
                (typInUnprotected ? unprotectedHeaders : protectedHeaders).put(new CoseNumberLabel(16), protectedTyp);
            }
            if (!noChain) {
                if (chainInUnprotected) {
                    unprotectedHeaders.put(new CoseNumberLabel(33),
                            new X509CertChain(List.of(signerCertificate)).toCoseX5Chain(false));
                } else if (protectedChain != null && !protectedChain.isEmpty()) {
                    protectedHeaders.put(new CoseNumberLabel(33), new X509CertChain(protectedChain).toCoseX5Chain(false));
                }
            }
            byte[] message = rawPayload != null ? rawPayload : Cbor.INSTANCE.encode(new CborMap(claims, false));
            CoseSign1 sign1 = await(continuation -> Cose.INSTANCE.coseSign1Sign(
                    AsymmetricKey.Companion.anonymous(signerKey, Algorithm.ES256), message, !detached,
                    protectedHeaders, unprotectedHeaders, continuation));
            DataItem cose = sign1.toDataItem();
            return Cbor.INSTANCE.encode(tag == null ? cose : new Tagged(tag, cose));
        }
    }
}
