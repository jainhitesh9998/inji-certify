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

import static org.junit.jupiter.api.Assertions.assertEquals;
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

        assertEquals(IndependentStatusListVerifier.CHECKS,
                report.checks().stream().map(VerificationReport.Check::name).toList(),
                "every check runs, in report order");
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
    void theOptionsRefuseAStatusOutsideTheTokenStatusListRegistry() {
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, 4, true)));
        assertTrue(assertThrowsIllegalArgument(() -> new IndependentStatusListVerifier.StatusListOptions(true, -1, false)));
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
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(4), DataItemExtensionsKt.toDataItem(NOW.minusSeconds(60).getEpochSecond()))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expired")));
    }

    @Test
    void anExpAfterTheSignersNotAfterIsRefused() {
        Fixture fixture = new Fixture();
        long afterSigner = fixture.notAfter.getEpochSecond() + 3600;
        VerificationReport report = verify(fixture, fixture.tokenWithClaims(
                        claims -> claims.put(claim(4), DataItemExtensionsKt.toDataItem(afterSigner))),
                IndependentStatusListVerifier.StatusListOptions.strictMode());
        assertProblems(report, Map.of(IndependentStatusListVerifier.CHECK_CLAIMS, List.of("expAfterSigner")));
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
            Map<DataItem, DataItem> statusList = new LinkedHashMap<>();
            statusList.put(new Tstr("uri"), new Tstr(uri));
            statusList.put(new Tstr("idx"), DataItemExtensionsKt.toDataItem(idx));
            Map<DataItem, DataItem> status = new LinkedHashMap<>();
            status.put(new Tstr("status_list"), new CborMap(statusList, false));
            Map<DataItem, DataItem> mso = new LinkedHashMap<>();
            mso.put(new Tstr("version"), new Tstr("1.0"));
            mso.put(new Tstr("docType"), new Tstr("org.iso.18013.5.1.mDL"));
            mso.put(new Tstr("status"), new CborMap(status, false));
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

        X509Cert issuedUnder(X509Cert anchor, EcPrivateKey anchorKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature) {
            return issuedUnder(anchor, anchorKey, commonName, serial, eku, digitalSignature, statusKey);
        }

        X509Cert issuedUnder(X509Cert anchor, EcPrivateKey anchorKey, String commonName, long serial, List<String> eku,
                             boolean digitalSignature, EcPrivateKey subjectKey) {
            org.multipaz.crypto.X509Cert.Builder builder = new org.multipaz.crypto.X509Cert.Builder(subjectKey.getPublicKey(),
                    certified(anchor, anchorKey), new ASN1Integer(serial, 2),
                    X500Name.Companion.fromName("CN=" + commonName + ",C=IN"), anchor.getSubject(),
                    kotlinInstant(notBefore), kotlinInstant(notAfter))
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
            byte[] message = Cbor.INSTANCE.encode(new CborMap(claims, false));
            CoseSign1 sign1 = await(continuation -> Cose.INSTANCE.coseSign1Sign(
                    AsymmetricKey.Companion.anonymous(signerKey, Algorithm.ES256), message, !detached,
                    protectedHeaders, unprotectedHeaders, continuation));
            DataItem cose = sign1.toDataItem();
            return Cbor.INSTANCE.encode(tag == null ? cose : new Tagged(tag, cose));
        }
    }
}
