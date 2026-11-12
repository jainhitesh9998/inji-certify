/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.format.mdoc;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.testkit.mdoc.AcceptedGaps;
import io.mosip.certify.testkit.mdoc.IndependentMdocVerifier;
import io.mosip.certify.testkit.mdoc.MdocSamples;
import io.mosip.certify.testkit.mdoc.Options;
import io.mosip.certify.testkit.mdoc.VerificationReport;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The formatter's own tests agree with its writer; this one checks the bytes with libraries Certify does not maintain
 * (Multipaz and Authlete CBOR, {@code certify-testkit-mdoc}).
 *
 * <p>Every credential here is real formatter output for the complete ISO/IEC 18013-5 Table 5 mDL of {@link MdlFixtures},
 * signed by a document signer certificate issued by a test IACA ({@link MdlFixtures#dscWithIaca()}), so the IssuerAuth
 * carries the DSC alone (HAIP, {@code without-anchor}). Three kinds of test:
 * <ul>
 *     <li>the output under every rule, in strict mode, held to exactly the gaps it declares ({@link #FORMATTER_GAPS},
 *     written next to each sample as its {@code .gaps} sidecar), for a P-256 and an Ed25519 holder; a declared gap that
 *     starts passing fails the test until its line is removed;</li>
 *     <li>the gaps M-02 and M-03 closed (G1, G2/G3, G6, G8, G9), one test each, so a regression names the gap;</li>
 *     <li>mutations and strict-mode negatives, so a check that stops detecting what it claims to detect goes red:
 *     a re-signed-over signature, a wrong docType, an expired window, a foreign IACA, a self-signed certificate in
 *     the chain, a retyped or missing element, a non-preferred integer encoding.</li>
 * </ul>
 *
 * <p>The two samples written here ({@code MdocIndependentVerificationTest-formatter} and
 * {@code MdocIndependentVerificationTest-ed25519}) go to {@code target/mdoc-samples/} together with their holder key,
 * docType and gaps, for {@code certify-conformance-mdoc} and {@code docs/design/tools/verify_mdoc.py} to re-verify with
 * two more independent stacks.
 */
class MdocIndependentVerificationTest {

    static final String DOCTYPE = MdlFixtures.MDL_DOCTYPE;
    static final String NAMESPACE = MdlFixtures.MDL_NAMESPACE;

    static final Path SAMPLES = Path.of("target", "mdoc-samples");

    static final Path MUTATIONS = Path.of("target", "mdoc-mutations");

    /** The document signer every credential here is signed with: chain [DSC, IACA], the IACA a test anchor. */
    static final SigningKey DSC = MdlFixtures.dscWithIaca();
    static final X509Certificate IACA = DSC.chain().root().orElseThrow();

    /**
     * What the formatter's output cannot pass yet, one problem code per line, with the gap and the work package that
     * closes it. Written next to each sample as its {@code .gaps} sidecar; the work package that fixes one deletes its
     * line, and a problem not listed here (an expired window, a new element-type regression) fails. The x5chain is the
     * DSC alone, as it must be, so a verifier needs the IACA from elsewhere: the sample does not hand it out
     * ({@code .iaca.pem} is written only for a chain that carries its anchor), and configured trust anchors are M-06.
     * {@link #theChainWithoutItsAnchorValidatesToTheIaca} shows the same credential passes every check once the IACA is
     * supplied.
     */
    static final AcceptedGaps FORMATTER_GAPS = AcceptedGaps.none()
            .gap(IndependentMdocVerifier.CHECK_CHAIN_TO_IACA, "noAnchorSupplied",
                    "the x5chain is the DSC alone (HAIP) and the sample carries no IACA for the verifier; trust anchors are M-06");

    final IndependentMdocVerifier verifier = new IndependentMdocVerifier();
    final MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)));

    // ---- the credential under test -----------------------------------------------------------------------------

    byte[] issue(Map<String, Object> document) {
        return issue(document, MdlFixtures.holder(), DSC);
    }

    byte[] issue(Map<String, Object> document, HolderBinding holder, SigningKey key) {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), MdlFixtures.configuration(formatter),
                MdlFixtures.context(), holder);
        IssuedCredential issued = formatter.sign(unsigned, MdlFixtures.signing(key), MdlFixtures.context());
        return Base64.getUrlDecoder().decode((String) issued.credential());
    }

    VerificationReport verify(byte[] issuerSigned, Optional<X509Certificate> iaca, Options options) throws Exception {
        // the formatter signs at the request clock (MdlFixtures.NOW, truncated to seconds); now is inside the window
        return verifier.verify(issuerSigned, JWK.parse(MdlFixtures.HOLDER_JWK), iaca, Instant.now(), options);
    }

    static void assertFails(VerificationReport report, String check, String why) {
        assertFalse(report.check(check).passed(), why + System.lineSeparator() + report);
        assertTrue(report.check(check).state() == VerificationReport.State.FAIL, why + " (state must be FAIL, not skipped)"
                + System.lineSeparator() + report);
    }

    static void assertPasses(VerificationReport report, String check, String why) {
        assertTrue(report.check(check).state() == VerificationReport.State.PASS, why + System.lineSeparator() + report);
    }

    static String didJwk(JWK holder) {
        return "did:jwk:" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(holder.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8));
    }

    // ---- the formatter's output, strict, held to exactly its declared gaps -------------------------------------

    @Test
    void formatterOutputVerifiesWithExactlyTheDeclaredGaps() throws Exception {
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        // before the assertions: the conformance module and the CI python verifier read the sample even when a check fails
        MdocSamples.write(SAMPLES, getClass(), "formatter", issuerSigned, JWK.parse(MdlFixtures.HOLDER_JWK), DOCTYPE, FORMATTER_GAPS);
        VerificationReport report = verify(issuerSigned, Optional.empty(), Options.strict(DOCTYPE));
        assertEquals(IndependentMdocVerifier.CHECKS, report.checks().stream().map(VerificationReport.Check::name).toList(),
                "the harness still runs every check it claims to");
        FORMATTER_GAPS.assertMatches(report, MdocSamples.name(getClass(), "formatter"));
    }

    @Test
    void anEd25519HolderIsBoundAsItsOkpDeviceKey() throws Exception {
        // G6 (fixed by M-02): the formatter binds an Ed25519 holder as the OKP COSE_Key {1: 1, -1: 6, -2: x}
        // (ISO/IEC 18013-5 9.1.5.2, decision D4); this is its own output, not a re-signed P-256 credential
        OctetKeyPair holder = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        byte[] issuerSigned = issue(MdlFixtures.mdl(), HolderBinding.did(didJwk(holder), "jwt"), DSC);
        MdocSamples.write(SAMPLES, getClass(), "ed25519", issuerSigned, holder.toPublicJWK(), DOCTYPE, FORMATTER_GAPS);

        VerificationReport report = verifier.verify(issuerSigned, holder.toPublicJWK(), Optional.empty(), Instant.now(),
                Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "the MSO deviceKey is the Ed25519 holder key");
        FORMATTER_GAPS.assertMatches(report, MdocSamples.name(getClass(), "ed25519"));
    }

    @Test
    void theChainWithoutItsAnchorValidatesToTheIaca() throws Exception {
        // the verifier holds the IACA (HAIP): given it, the formatter's output passes every check, the chain included
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        assertEquals(1, x5chain(issuerSigned).size(), "the x5chain is the DSC alone");
        VerificationReport report = verify(issuerSigned, Optional.of(IACA), Options.strict(DOCTYPE));
        AcceptedGaps.none().assertMatches(report, "formatter-with-iaca");
        assertTrue(report.passed(), report.toString());
    }

    // ---- the gaps M-02 and M-03 closed, one test each ----------------------------------------------------------

    @Test
    void g1TheValidityDatesAreWholeSecondTagZeroTdates() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_TDATE_TAGS, "#6.0(tstr), whole seconds, Z (ISO/IEC 18013-5 9.1.2.4)");
        assertPasses(report, IndependentMdocVerifier.CHECK_MSO_PARSE, "Multipaz's MobileSecurityObject parser reads the MSO as sent");
    }

    @Test
    void g2g3EveryTable5ElementIsTypedAndPresent() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_ELEMENT_TYPES,
                "the mandatory elements of ISO/IEC 18013-5 7.2.1 Table 5, each with its type (portrait a bstr, dates full-date)");
    }

    @Test
    void g8SignedIsValidFromWhateverTheGapBetweenBuildAndSign() throws Exception {
        // the core path builds at the request instant and signs after the data source answered; the window is decided
        // in sign() as one instant, so a later signing clock moves signed and validFrom together (never signed > validFrom)
        Instant buildAt = MdlFixtures.NOW;
        Instant signAt = buildAt.plusMillis(1_500);
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(MdlFixtures.mdl()), MdlFixtures.configuration(formatter),
                MdlFixtures.context(buildAt), MdlFixtures.holder());
        IssuedCredential issued = formatter.sign(unsigned, MdlFixtures.signing(DSC), MdlFixtures.context(signAt));
        byte[] issuerSigned = Base64.getUrlDecoder().decode((String) issued.credential());
        VerificationReport report = verify(issuerSigned, Optional.empty(), Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signed <= validFrom < validUntil");
        co.nstant.in.cbor.model.Map validity = (co.nstant.in.cbor.model.Map) mso(issuerSigned).get(new UnicodeString("validityInfo"));
        String signed = ((UnicodeString) validity.get(new UnicodeString("signed"))).getString();
        assertEquals(signed, ((UnicodeString) validity.get(new UnicodeString("validFrom"))).getString(), "one instant for both");
        assertEquals(MdlFixtures.tdate(signAt), signed, "the signing clock, truncated to whole seconds");
    }

    @Test
    void g9TheX5chainCarriesNoSelfSignedCertificate() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_NO_SELF_SIGNED, "without-anchor drops the IACA (HAIP)");
    }

    // ---- mutations: the checks that must catch a bad credential ------------------------------------------------

    @Test
    void aTamperedSignatureFailsBothCoseOracles() throws Exception {
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        Array issuerAuth = (Array) root.get(new UnicodeString("issuerAuth"));
        List<DataItem> coseSign1 = new ArrayList<>(issuerAuth.getDataItems());
        byte[] signature = ((ByteString) coseSign1.get(3)).getBytes().clone();
        signature[signature.length - 1] ^= 0x01; // one bit of the ECDSA signature, everything else untouched
        coseSign1.set(3, new ByteString(signature));
        root.put(new UnicodeString("issuerAuth"), array(coseSign1));

        VerificationReport report = verify(encode(root), Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ, "Multipaz must reject a tampered signature");
        assertFails(report, IndependentMdocVerifier.CHECK_SIGNATURE_AUTHLETE, "Authlete must reject a tampered signature");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_VALUE_DIGESTS).passed(),
                "the signature covers the MSO, not the items: the digest check must still pass" + System.lineSeparator() + report);
    }

    @Test
    void aWrongDocTypeFailsTheDocTypeCheck() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.baseline(DOCTYPE + ".mdl"));
        assertFails(report, IndependentMdocVerifier.CHECK_DOC_TYPE, "a doctype other than the issued one must fail");
    }

    @Test
    void anExpiredCredentialFailsTheValidityWindow() throws Exception {
        // properly signed and properly tagged, only the window is in the past: nothing but the window check can tell
        byte[] expired = resignValidity(issue(MdlFixtures.mdl()),
                Map.of("signed", "2020-01-01T00:00:00Z", "validFrom", "2020-01-01T00:00:00Z",
                        "validUntil", "2021-01-01T00:00:00Z"), Set.of());
        VerificationReport report = verify(expired, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "validUntil in 2021 must fail at " + Instant.now());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).passed(),
                "the credential is properly re-signed: only the window is wrong" + System.lineSeparator() + report);
        assertTrue(report.check(IndependentMdocVerifier.CHECK_TDATE_TAGS).passed(),
                "the fixture is a whole-second tag-0 tdate, so the tdate check must pass" + System.lineSeparator() + report);
    }

    @Test
    void aForeignIacaFailsTheChainCheck() throws Exception {
        JcaKeyProvider other = new JcaKeyProvider();
        X509Certificate foreign = other.generate("dev-other", SignatureAlgorithm.ES256, "CN=Not the IACA", "vc-signing")
                .chain().leaf().orElseThrow();
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.of(foreign), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_CHAIN_TO_IACA,
                "an x5chain that does not reach the supplied IACA must fail");
    }

    @Test
    void aSelfSignedCertificateInTheX5chainIsDetected() throws Exception {
        // the formatter refuses to carry the anchor (x5chain full over a self-signed IACA), so the mutation puts it back:
        // x5chain sits in the unprotected header, the signature still verifies, and only the HAIP rule can tell
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        Array issuerAuth = (Array) root.get(new UnicodeString("issuerAuth"));
        List<DataItem> coseSign1 = new ArrayList<>(issuerAuth.getDataItems());
        co.nstant.in.cbor.model.Map unprotected = (co.nstant.in.cbor.model.Map) coseSign1.get(1);
        unprotected.put(new UnsignedInteger(33), array(List.of(x5chain(issuerSigned).get(0), new ByteString(IACA.getEncoded()))));
        root.put(new UnicodeString("issuerAuth"), array(coseSign1));
        byte[] withAnchor = encode(root);

        VerificationReport report = verify(withAnchor, Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_NO_SELF_SIGNED, "the self-signed IACA in x5chain must be reported (HAIP)");
        assertEquals(List.of("selfSigned:1"), report.check(IndependentMdocVerifier.CHECK_NO_SELF_SIGNED).codes(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).passed(), report.toString());
        assertEquals(2, x5chain(withAnchor).size(), "the mutation must actually carry [DSC, IACA]");

        // and a lone self-signed signer certificate (a plain dev key, G10/G11) is the same problem at index 0
        VerificationReport lone = verify(issue(MdlFixtures.mdl(), MdlFixtures.holder(), MdlFixtures.dsc()), Optional.empty(),
                Options.strict(DOCTYPE));
        assertEquals(List.of("selfSigned:0"), lone.check(IndependentMdocVerifier.CHECK_NO_SELF_SIGNED).codes(), lone.toString());
    }

    @Test
    void anX5chainAsArrayIsAccepted() throws Exception {
        // RFC 9360 allows x5chain as a bstr or an array; the harness must read both
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        Array issuerAuth = (Array) root.get(new UnicodeString("issuerAuth"));
        List<DataItem> coseSign1 = new ArrayList<>(issuerAuth.getDataItems());
        co.nstant.in.cbor.model.Map unprotected = (co.nstant.in.cbor.model.Map) coseSign1.get(1);
        DataItem chain = unprotected.get(new UnsignedInteger(33));
        unprotected.put(new UnsignedInteger(33),
                array(List.of(chain instanceof Array existing ? existing.getDataItems().get(0) : chain)));
        coseSign1.set(1, unprotected);
        root.put(new UnicodeString("issuerAuth"), array(coseSign1));

        VerificationReport report = verify(encode(root), Optional.empty(), Options.baseline(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).passed(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_AUTHLETE).passed(), report.toString());
    }

    @Test
    void aNonPreferredIntegerEncodingFailsTheDigestCheck() throws Exception {
        // ISO/IEC 18013-5 9.1.2.5 hashes the bytes as sent: 0x00 becomes the legal but non-preferred 0x18 0x00 and
        // the valueDigests entry is left alone. A verifier that re-encodes would not notice, so this test is the
        // reason the harness hashes the received bytes and keeps calculateDigest as a second opinion only.
        byte[] issuerSigned = issue(MdlFixtures.with("age_in_years", 0));
        byte[] nonPreferred = nonPreferredInteger(issuerSigned, 0);

        VerificationReport report = verify(nonPreferred, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALUE_DIGESTS,
                "the received tag-24 bytes no longer hash to the declared digest");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_CALCULATED_DIGESTS).passed(),
                "Multipaz re-encodes 0x18 0x00 back to 0x00, which is exactly why it cannot be the primary oracle"
                        + System.lineSeparator() + report);
    }

    @Test
    void aDuplicatedElementInANamespaceFailsTheNamespaceCheck() throws Exception {
        // two items with the same elementIdentifier: Multipaz's IssuerNamespaces.validate must report it
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        co.nstant.in.cbor.model.Map nameSpaces = (co.nstant.in.cbor.model.Map) root.get(new UnicodeString("nameSpaces"));
        Array items = (Array) nameSpaces.get(new UnicodeString(NAMESPACE));
        List<DataItem> duplicated = new ArrayList<>(items.getDataItems());
        duplicated.add(duplicated.get(0));
        nameSpaces.put(new UnicodeString(NAMESPACE), array(duplicated));
        root.put(new UnicodeString("nameSpaces"), nameSpaces);

        VerificationReport report = verify(encode(root), Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_NAMESPACES,
                "a duplicate elementIdentifier must fail the Multipaz namespace validator");
    }

    @Test
    void aCredentialBoundToAnotherHolderFailsTheDeviceKeyCheck() throws Exception {
        byte[] issuerSigned = issue(MdlFixtures.mdl());
        JWK other = JWK.parse(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString());
        VerificationReport report = verifier.verify(issuerSigned, other, Optional.empty(), Instant.now(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "the deviceKey must be the holder key");
    }

    @Test
    void aDeviceKeyCarryingThePrivateKeyFails() throws Exception {
        OctetKeyPair holder = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        byte[] leaked = resignMso(issue(MdlFixtures.mdl()), mso -> mso.put(new UnicodeString("deviceKeyInfo"),
                deviceKeyInfo(okpCoseKey(holder.getX().decode(), holder.getD().decode()))));
        VerificationReport report = verifier.verify(leaked, holder.toPublicJWK(), Optional.empty(),
                Instant.now(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "a COSE_Key with d (label -4) must fail");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_DEVICE_KEY).message().contains("private key"), report.toString());
    }

    @Test
    void anOkpHolderDoesNotMatchAnotherOkpKey() throws Exception {
        OctetKeyPair holder = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        OctetKeyPair other = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        byte[] issuerSigned = issue(MdlFixtures.mdl(), HolderBinding.did(didJwk(holder), "jwt"), DSC);
        VerificationReport report = verifier.verify(issuerSigned, other.toPublicJWK(), Optional.empty(),
                Instant.now(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "another Ed25519 key must not match by curve alone");
    }

    @Test
    void anExpectedUpdateBeforeValidFromFailsEvenWhenTheParseIsRepaired() throws Exception {
        // signed t-10s, expectedUpdate t-7s, validFrom t-5s and untagged: baseline mode repairs the tag for Multipaz,
        // and the wire ordering must still catch expectedUpdate < validFrom (ISO/IEC 18013-5 9.1.2.4)
        Instant t = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        byte[] bent = resignValidity(issue(MdlFixtures.mdl()), Map.of("signed", t.minusSeconds(10).toString(),
                "expectedUpdate", t.minusSeconds(7).toString(), "validFrom", t.minusSeconds(5).toString()), Set.of("validFrom"));
        VerificationReport report = verify(bent, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "expectedUpdate before validFrom must fail");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_VALIDITY_INFO).message().contains("is before validFrom"),
                report.toString());
    }

    @Test
    void signedAfterValidFromFailsTheWindow() throws Exception {
        // G8 as the core path signed before M-02: validFrom from the request instant, signed from the wall clock later
        Instant t = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        byte[] bent = resignValidity(issue(MdlFixtures.mdl()), Map.of("signed", t.minusSeconds(4).toString(),
                "validFrom", t.minusSeconds(5).toString()), Set.of());
        VerificationReport report = verify(bent, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signed after validFrom must fail");
        assertEquals(List.of("signedAfterValidFrom"), report.check(IndependentMdocVerifier.CHECK_VALIDITY_INFO).codes(),
                report.toString());
    }

    // ---- one accepted problem cannot hide another one in the same check ----------------------------------------

    @Test
    void anExpiredResignedCredentialFailsEvenWithTheG8GapDeclared() throws Exception {
        // the review's mutation: with G8 accepted as a whole check, an expired, re-signed credential passed both gates.
        // Whole-second tag-0 dates, signed after validFrom (G8) and validUntil in 2021: only expired is new.
        byte[] expired = resignValidity(issue(MdlFixtures.mdl()), Map.of("signed", "2020-01-01T00:00:05Z",
                "validFrom", "2020-01-01T00:00:00Z", "validUntil", "2021-01-01T00:00:00Z"), Set.of());
        AcceptedGaps g8 = FORMATTER_GAPS.gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signedAfterValidFrom",
                "G8: signed after validFrom, as the core path signed before M-02");
        String name = MdocSamples.name(getClass(), "expired-g8");
        // for the CI python step, which must fail on it for the same reason (the .expect sidecar names the problem)
        Path written = MdocSamples.write(MUTATIONS, getClass(), "expired-g8", expired, JWK.parse(MdlFixtures.HOLDER_JWK),
                DOCTYPE, g8);
        java.nio.file.Files.writeString(written.resolveSibling(name + ".expect"), "mso.validityInfo:expired\n");

        VerificationReport report = verify(expired, Optional.empty(), Options.strict(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).passed(), report.toString());
        AssertionError refused = assertThrows(AssertionError.class, () -> g8.assertMatches(report, name));
        assertTrue(refused.getMessage().contains("not an accepted gap of " + name + ": mso.validityInfo:expired"),
                refused.getMessage());
        // and expired is the only difference: accept it too and the same report matches
        g8.gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "expired", "the mutation").assertMatches(report, name);
    }

    @Test
    void aNewElementTypeRegressionFailsWithAnotherElementGapDeclared() throws Exception {
        // given_name dropped (selective disclosure leaves its digest, so nothing is re-signed for it) and family_name
        // re-encoded as a uint with its digest updated and the MSO re-signed: declaring the missing element must not
        // accept the retyped one
        byte[] withoutGivenName = withoutElement(issue(MdlFixtures.mdl()), "given_name");
        byte[] regressed = replaceElementValue(withoutGivenName, "family_name", new UnsignedInteger(42));
        VerificationReport report = verify(regressed, Optional.empty(), Options.strict(DOCTYPE));
        assertPasses(report, IndependentMdocVerifier.CHECK_VALUE_DIGESTS, "the mutation keeps the digests consistent");
        AcceptedGaps missing = FORMATTER_GAPS.gap(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "missing:given_name", "the mutation");
        AssertionError refused = assertThrows(AssertionError.class, () -> missing.assertMatches(report, "regression"));
        assertTrue(refused.getMessage().contains("not an accepted gap of regression: mdl.elementTypes:untyped:family_name"),
                refused.getMessage());
        missing.gap(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "untyped:family_name", "the mutation")
                .assertMatches(report, "regression");
    }

    @Test
    void theDraft13DocumentShapeAndTaggedIssuerAuthAreTheirOwnProblems() throws Exception {
        // the 0.14.0 wire shape: Document {docType, issuerSigned} around the formatter's output, IssuerAuth under tag 18;
        // both signature oracles still verify after unwrapping, and nothing but the two shape codes is new
        co.nstant.in.cbor.model.Map issuerSigned = (co.nstant.in.cbor.model.Map) decode(issue(MdlFixtures.mdl()));
        Array issuerAuth = (Array) issuerSigned.get(new UnicodeString("issuerAuth"));
        issuerAuth.setTag(18);
        co.nstant.in.cbor.model.Map documentWrapper = new co.nstant.in.cbor.model.Map();
        documentWrapper.put(new UnicodeString("docType"), new UnicodeString(DOCTYPE));
        documentWrapper.put(new UnicodeString("issuerSigned"), issuerSigned);
        VerificationReport report = verify(encode(documentWrapper), Optional.empty(), Options.strict(DOCTYPE));
        assertEquals(List.of("documentWrapper"), report.check(IndependentMdocVerifier.CHECK_SHAPE).codes(), report.toString());
        assertEquals(List.of("tagged"), report.check(IndependentMdocVerifier.CHECK_UNTAGGED).codes(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ).passed(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SIGNATURE_AUTHLETE).passed(), report.toString());
        FORMATTER_GAPS.gap(IndependentMdocVerifier.CHECK_SHAPE, "documentWrapper", "0.14.0")
                .gap(IndependentMdocVerifier.CHECK_UNTAGGED, "tagged", "0.14.0").assertMatches(report, "d13-shape");
        // a Document whose docType disagrees with the MSO is its own problem
        documentWrapper.put(new UnicodeString("docType"), new UnicodeString(DOCTYPE + ".other"));
        assertEquals(List.of("documentMismatch"), verify(encode(documentWrapper), Optional.empty(), Options.strict(DOCTYPE))
                .check(IndependentMdocVerifier.CHECK_DOC_TYPE).codes());
    }

    @Test
    void formatterOutputIsABareUntaggedIssuerSigned() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.strict(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SHAPE).passed(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_UNTAGGED).passed(), report.toString());
    }

    // ---- strict-mode negatives -----------------------------------------------------------------------------------

    @Test
    void strictModeRejectsAnUntaggedDate() throws Exception {
        // a plain tstr where #6.0(tstr) belongs. The formatter always tags, so the fixture re-signs a valid credential
        // with validFrom untagged and Multipaz must not be given a repaired copy.
        byte[] untagged = resignValidity(issue(MdlFixtures.mdl()), Map.of(), Set.of("validFrom"));
        VerificationReport report = verify(untagged, Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_TDATE_TAGS, "an untagged validFrom must fail strict mode");
        assertEquals(List.of("untagged:validFrom"), report.check(IndependentMdocVerifier.CHECK_TDATE_TAGS).codes(), report.toString());
    }

    @Test
    void strictModeWithoutAnIacaFailsTheChainCheck() throws Exception {
        VerificationReport report = verify(issue(MdlFixtures.mdl()), Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_CHAIN_TO_IACA,
                "strict mode must fail, not skip, when there is no IACA to anchor the chain");
        assertEquals(List.of("noAnchorSupplied"), report.check(IndependentMdocVerifier.CHECK_CHAIN_TO_IACA).codes(),
                report.toString());
        assertFalse(report.passed(), "without its IACA the output cannot pass strict mode" + System.lineSeparator() + report);
    }

    // ---- CBOR mutation helpers ---------------------------------------------------------------------------------

    static DataItem decode(byte[] cbor) throws Exception {
        return new CborDecoder(new ByteArrayInputStream(cbor)).decode().get(0);
    }

    static byte[] encode(DataItem item) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new CborEncoder(out).encode(item);
        return out.toByteArray();
    }

    static Array array(List<DataItem> items) {
        Array array = new Array();
        items.forEach(array::add);
        return array;
    }

    static List<DataItem> x5chain(byte[] issuerSigned) throws Exception {
        Array issuerAuth = (Array) ((co.nstant.in.cbor.model.Map) decode(issuerSigned)).get(new UnicodeString("issuerAuth"));
        co.nstant.in.cbor.model.Map unprotected = (co.nstant.in.cbor.model.Map) issuerAuth.getDataItems().get(1);
        DataItem chain = unprotected.get(new UnsignedInteger(33));
        return chain instanceof Array values ? values.getDataItems() : List.of(chain);
    }

    /** The decoded MSO of an IssuerSigned (the COSE payload is a bstr holding #6.24(bstr .cbor MSO)). */
    static co.nstant.in.cbor.model.Map mso(byte[] issuerSigned) throws Exception {
        Array issuerAuth = (Array) ((co.nstant.in.cbor.model.Map) decode(issuerSigned)).get(new UnicodeString("issuerAuth"));
        ByteString taggedMso = (ByteString) decode(((ByteString) issuerAuth.getDataItems().get(2)).getBytes());
        return (co.nstant.in.cbor.model.Map) decode(taggedMso.getBytes());
    }

    /** Drops the element from the namespace; its digest stays in the MSO, as for an element the holder withholds. */
    static byte[] withoutElement(byte[] issuerSigned, String identifier) throws Exception {
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        co.nstant.in.cbor.model.Map nameSpaces = (co.nstant.in.cbor.model.Map) root.get(new UnicodeString("nameSpaces"));
        List<DataItem> kept = new ArrayList<>();
        for (DataItem item : ((Array) nameSpaces.get(new UnicodeString(NAMESPACE))).getDataItems()) {
            co.nstant.in.cbor.model.Map decoded = (co.nstant.in.cbor.model.Map) decode(((ByteString) item).getBytes());
            if (!new UnicodeString(identifier).equals(decoded.get(new UnicodeString("elementIdentifier")))) {
                kept.add(item);
            }
        }
        nameSpaces.put(new UnicodeString(NAMESPACE), array(kept));
        root.put(new UnicodeString("nameSpaces"), nameSpaces);
        return encode(root);
    }

    /**
     * Replaces one element's value, re-encodes its IssuerSignedItem as #6.24(bstr), puts the SHA-256 of those bytes into
     * the MSO's valueDigests and re-signs, so only the element's type is wrong (the digests and signature verify).
     */
    static byte[] replaceElementValue(byte[] issuerSigned, String identifier, DataItem value) throws Exception {
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        co.nstant.in.cbor.model.Map nameSpaces = (co.nstant.in.cbor.model.Map) root.get(new UnicodeString("nameSpaces"));
        List<DataItem> items = new ArrayList<>(((Array) nameSpaces.get(new UnicodeString(NAMESPACE))).getDataItems());
        for (int i = 0; i < items.size(); i++) {
            co.nstant.in.cbor.model.Map item = (co.nstant.in.cbor.model.Map) decode(((ByteString) items.get(i)).getBytes());
            if (!new UnicodeString(identifier).equals(item.get(new UnicodeString("elementIdentifier")))) {
                continue;
            }
            item.put(new UnicodeString("elementValue"), value);
            ByteString replacement = new ByteString(encode(item));
            replacement.setTag(24);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(encode(replacement));
            DataItem digestId = item.get(new UnicodeString("digestID"));
            items.set(i, replacement);
            nameSpaces.put(new UnicodeString(NAMESPACE), array(items));
            root.put(new UnicodeString("nameSpaces"), nameSpaces);
            return resignMso(encode(root), mso -> {
                co.nstant.in.cbor.model.Map valueDigests = (co.nstant.in.cbor.model.Map) mso.get(new UnicodeString("valueDigests"));
                ((co.nstant.in.cbor.model.Map) valueDigests.get(new UnicodeString(NAMESPACE))).put(digestId, new ByteString(digest));
            });
        }
        throw new AssertionError("no element " + identifier + " in the fixture");
    }

    /** Re-encodes one integer element as 0x18 <value>, which CBOR allows and canonical encoders never emit. */
    static byte[] nonPreferredInteger(byte[] issuerSigned, int value) throws Exception {
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        co.nstant.in.cbor.model.Map nameSpaces = (co.nstant.in.cbor.model.Map) root.get(new UnicodeString("nameSpaces"));
        Array items = (Array) nameSpaces.get(new UnicodeString(NAMESPACE));
        List<DataItem> replaced = new ArrayList<>(items.getDataItems());
        byte[] key = "elementValue".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (int i = 0; i < replaced.size(); i++) {
            ByteString item = (ByteString) replaced.get(i);
            byte[] inner = item.getBytes();
            int at = indexOf(inner, key);
            if (at < 0 || inner[at + key.length] != (byte) value) {
                continue;
            }
            byte[] patched = new byte[inner.length + 1];
            int valueOffset = at + key.length;
            System.arraycopy(inner, 0, patched, 0, valueOffset);
            patched[valueOffset] = 0x18; // additional information 24: one more byte carries the argument
            patched[valueOffset + 1] = (byte) value;
            System.arraycopy(inner, valueOffset + 1, patched, valueOffset + 2, inner.length - valueOffset - 1);
            ByteString replacement = new ByteString(patched);
            if (item.hasTag()) {
                replacement.setTag(item.getTag());
            }
            replaced.set(i, replacement);
            nameSpaces.put(new UnicodeString(NAMESPACE), array(replaced));
            root.put(new UnicodeString("nameSpaces"), nameSpaces);
            return encode(root);
        }
        throw new AssertionError("no IssuerSignedItem with elementValue " + value + " in the fixture");
    }

    /**
     * Rewrites the MSO validityInfo and signs the result again with the same DSC, so a test can bend the validity
     * dates (or drop a tdate tag) while everything else — the item digests, the COSE headers — stays as the formatter
     * wrote it.
     */
    static byte[] resignValidity(byte[] issuerSigned, Map<String, String> replace, Set<String> untag) throws Exception {
        return resignMso(issuerSigned, mso -> {
            co.nstant.in.cbor.model.Map validity = (co.nstant.in.cbor.model.Map) mso.get(new UnicodeString("validityInfo"));
            replace.forEach((field, text) -> validity.put(new UnicodeString(field), tdate(text)));
            untag.forEach(field -> {
                String text = ((UnicodeString) validity.get(new UnicodeString(field))).getString();
                validity.put(new UnicodeString(field), new UnicodeString(text)); // same text, no #6.0 tag
            });
        });
    }

    /** Applies {@code mutate} to the decoded MSO and signs the result again with the same DSC. */
    static byte[] resignMso(byte[] issuerSigned, Consumer<co.nstant.in.cbor.model.Map> mutate) throws Exception {
        co.nstant.in.cbor.model.Map root = (co.nstant.in.cbor.model.Map) decode(issuerSigned);
        Array issuerAuth = (Array) root.get(new UnicodeString("issuerAuth"));
        List<DataItem> coseSign1 = new ArrayList<>(issuerAuth.getDataItems());
        byte[] protectedBytes = ((ByteString) coseSign1.get(0)).getBytes();
        // the COSE payload is a plain bstr whose content is #6.24(bstr .cbor MSO); co.nstant models a tag as a flag
        ByteString taggedMso = (ByteString) decode(((ByteString) coseSign1.get(2)).getBytes());
        co.nstant.in.cbor.model.Map mso = (co.nstant.in.cbor.model.Map) decode(taggedMso.getBytes());
        mutate.accept(mso);
        ByteString rewrittenMso = new ByteString(encode(mso));
        rewrittenMso.setTag(24); // #6.24(bstr .cbor MobileSecurityObject)
        byte[] payloadBytes = encode(rewrittenMso);
        byte[] sigStructure = encode(array(List.of(new UnicodeString("Signature1"),
                new ByteString(protectedBytes), new ByteString(new byte[0]), new ByteString(payloadBytes))));
        byte[] signature = MdlFixtures.KEYS.signRaw(sigStructure, DSC, SignatureAlgorithm.ES256);
        coseSign1.set(2, new ByteString(payloadBytes)); // a plain bstr, as CoseEnvelope.sign1 writes it
        coseSign1.set(3, new ByteString(signature));
        root.put(new UnicodeString("issuerAuth"), array(coseSign1));
        return encode(root);
    }

    /** {@code deviceKeyInfo} holding an OKP Ed25519 COSE_Key {1: 1, -1: 6, -2: x}, plus {-4: d} when given. */
    static co.nstant.in.cbor.model.Map deviceKeyInfo(co.nstant.in.cbor.model.Map coseKey) {
        co.nstant.in.cbor.model.Map info = new co.nstant.in.cbor.model.Map();
        info.put(new UnicodeString("deviceKey"), coseKey);
        return info;
    }

    static co.nstant.in.cbor.model.Map okpCoseKey(byte[] x, byte[] d) {
        co.nstant.in.cbor.model.Map key = new co.nstant.in.cbor.model.Map();
        key.put(new UnsignedInteger(1), new UnsignedInteger(1));
        key.put(new co.nstant.in.cbor.model.NegativeInteger(-1), new UnsignedInteger(6));
        key.put(new co.nstant.in.cbor.model.NegativeInteger(-2), new ByteString(x));
        if (d != null) {
            key.put(new co.nstant.in.cbor.model.NegativeInteger(-4), new ByteString(d));
        }
        return key;
    }

    static UnicodeString tdate(String text) {
        UnicodeString tdate = new UnicodeString(text);
        tdate.setTag(0); // #6.0(tstr)
        return tdate;
    }

    static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(haystack, i, i + needle.length), needle)) {
                return i;
            }
        }
        return -1;
    }
}
