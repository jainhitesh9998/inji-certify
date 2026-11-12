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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.testkit.mdoc.AcceptedGaps;
import io.mosip.certify.testkit.mdoc.IndependentMdocVerifier;
import io.mosip.certify.testkit.mdoc.MdocSamples;
import io.mosip.certify.testkit.mdoc.Options;
import io.mosip.certify.testkit.mdoc.VerificationReport;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
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
 * <p>Two kinds of test:
 * <ul>
 *     <li>today's output under every rule, in strict mode, held to exactly the gaps it declares ({@link #FORMATTER_GAPS},
 *     written next to the sample as its {@code .gaps} sidecar); a declared gap that starts passing fails the test
 *     until its line is removed;</li>
 *     <li>mutations and strict-mode negatives, so a check that stops detecting what it claims to detect goes red:
 *     a re-signed-over signature, a wrong docType, an expired window, a foreign IACA, a self-signed certificate in
 *     the chain, and the strict-mode failures the M-02/M-03/M-06 work packages will flip.</li>
 * </ul>
 *
 * <p>The two samples written here ({@code MdocIndependentVerificationTest-formatter} and
 * {@code MdocIndependentVerificationTest-ed25519-fixture}) go to {@code target/mdoc-samples/} together with their holder
 * key, docType and gaps, for {@code certify-conformance-mdoc} and {@code docs/design/tools/verify_mdoc.py} to
 * re-verify with two more independent stacks.
 */
class MdocIndependentVerificationTest {

    static final String DOCTYPE = "org.iso.18013.5.1.mDL";
    static final String NAMESPACE = "org.iso.18013.5.1";
    static final JcaKeyProvider KEYS = JcaKeyProvider.devMode();
    static final Instant AT = Instant.now();
    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, null, List.of(),
            ProtocolVersion.OID4VCI_1_0, "c", AT, Map.of());
    static final String HOLDER_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
    static final String HOLDER = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(HOLDER_JWK.getBytes());

    static final Path SAMPLES = Path.of("target", "mdoc-samples");

    static final Path MUTATIONS = Path.of("target", "mdoc-mutations");

    /** ISO/IEC 18013-5 7.2.1 Table 5: the mandatory elements of org.iso.18013.5.1. */
    static final List<String> MANDATORY = List.of("family_name", "given_name", "birth_date", "issue_date", "expiry_date",
            "issuing_country", "issuing_authority", "document_number", "portrait", "driving_privileges",
            "un_distinguishing_sign");

    static final String G1 = "G1: signed/validFrom/validUntil carry milliseconds (UTC_DATETIME_PATTERN); fixed by M-02";

    /**
     * What the formatter's own output cannot pass yet, one problem code per line, with the gap and the work package
     * that closes it. Written next to each sample as its {@code .gaps} sidecar; the work package that fixes one
     * deletes its line, and a problem not listed here (an expired window, a new element-type regression) fails.
     */
    static final AcceptedGaps FORMATTER_GAPS = missingMandatory(AcceptedGaps.none()
            .gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:signed", G1)
            .gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:validFrom", G1)
            .gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:validUntil", G1)
            .gap(IndependentMdocVerifier.CHECK_CHAIN_TO_IACA, "noAnchorSupplied",
                    "the JCA dev key is a lone self-signed certificate, there is no IACA to anchor it; M-05/M-06")
            .gap(IndependentMdocVerifier.CHECK_NO_SELF_SIGNED, "selfSigned:0",
                    "G9/G10: the self-signed dev certificate is the whole x5chain (HAIP); M-02 and M-05"),
            "family_name", "birth_date");

    /** {@code gaps} plus {@code mdl.elementTypes:missing:<id>} for every Table 5 mandatory element not in {@code present}. */
    static AcceptedGaps missingMandatory(AcceptedGaps gaps, String... present) {
        AcceptedGaps result = gaps;
        for (String identifier : MANDATORY) {
            if (!List.of(present).contains(identifier)) {
                result = result.gap(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "missing:" + identifier,
                        "G3: the two-element fixture lacks this Table 5 mandatory element; M-03");
            }
        }
        return result;
    }

    final IndependentMdocVerifier verifier = new IndependentMdocVerifier();
    final MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), new MdocProperties("SHA-256", "1.0", 2));

    // ---- the credential under test -----------------------------------------------------------------------------

    static Map<String, Object> element(int digestId, String identifier, Object value) {
        return Map.of("digestID", digestId, "elementIdentifier", identifier, "elementValue", value);
    }

    static Map<String, Object> validity() {
        return Map.of("validFrom", "${_validFrom}", "validUntil", "${_validUntil}", "signed", "${_signed}");
    }

    static Map<String, Object> document() {
        return Map.of("docType", DOCTYPE,
                "validityInfo", validity(),
                "nameSpaces", Map.of(NAMESPACE, List.of(
                        element(0, "family_name", "Farmer"), element(1, "birth_date", "1990-01-01"))));
    }

    /** A document with a non-negative integer element, for the re-encoding digest test. */
    static Map<String, Object> documentWithInteger() {
        return Map.of("docType", DOCTYPE,
                "validityInfo", validity(),
                "nameSpaces", Map.of(NAMESPACE, List.of(
                        element(0, "family_name", "Farmer"), element(1, "age_in_years", 0))));
    }

    SigningContext signing(JcaKeyProvider provider, String alias) {
        SigningKey key = provider.resolve(KeyRef.parse("jca:" + alias));
        return new SigningContext(new SigningConfig(key.ref(), SignatureAlgorithm.ES256, null, null, null,
                "did:web:issuer.example"), key, provider);
    }

    SigningContext signing() {
        return signing(KEYS, "dev-es256");
    }

    CredentialConfiguration configuration(SigningContext signing) {
        return new CredentialConfiguration(null, "mdl", "mdl_scope", "mso_mdoc",
                formatter.parseConfig(Map.of("docType", DOCTYPE)), null, signing.config(), null, null, null, null, null);
    }

    byte[] issue(Map<String, Object> document) throws Exception {
        return issue(document, signing());
    }

    byte[] issue(Map<String, Object> document, SigningContext signing) throws Exception {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), configuration(signing), CONTEXT,
                HolderBinding.did(HOLDER, "jwt"));
        IssuedCredential issued = formatter.sign(unsigned, signing, CONTEXT);
        return Base64.getUrlDecoder().decode((String) issued.credential());
    }

    VerificationReport verify(byte[] issuerSigned, Optional<X509Certificate> iaca, Options options) throws Exception {
        // the formatter signs at the wall clock, so verification happens after it rather than at AT
        return verifier.verify(issuerSigned, JWK.parse(HOLDER_JWK), iaca, Instant.now().plusSeconds(1), options);
    }

    static void assertFails(VerificationReport report, String check, String why) {
        assertFalse(report.check(check).passed(), why + System.lineSeparator() + report);
        assertTrue(report.check(check).state() == VerificationReport.State.FAIL, why + " (state must be FAIL, not skipped)"
                + System.lineSeparator() + report);
    }

    // ---- today's output, strict, held to exactly its declared gaps ---------------------------------------------

    @Test
    void todayOutputVerifiesWithExactlyTheDeclaredGaps() throws Exception {
        byte[] issuerSigned = issue(document());
        // before the assertions: the conformance module and the CI python verifier read the sample even when a check fails
        MdocSamples.write(SAMPLES, getClass(), "formatter", issuerSigned, JWK.parse(HOLDER_JWK), DOCTYPE, FORMATTER_GAPS);
        VerificationReport report = verify(issuerSigned, Optional.empty(), Options.strict(DOCTYPE));
        assertEquals(IndependentMdocVerifier.CHECKS, report.checks().stream().map(VerificationReport.Check::name).toList(),
                "the harness still runs every check it claims to");
        FORMATTER_GAPS.assertMatches(report, MdocSamples.name(getClass(), "formatter"));
    }

    @Test
    void anEd25519HolderVerifiesByItsOkpDeviceKey() throws Exception {
        // gap G6: the formatter cannot bind an OKP key yet (formatterCurrentlyRefusesAnEd25519Holder), so the sample
        // is today's P-256 output with the MSO deviceKey replaced by the Ed25519 COSE_Key {1: 1, -1: 6, -2: x} and
        // re-signed with the same DSC. M-02 replaces it with the formatter's own Ed25519 output.
        OctetKeyPair holder = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();
        byte[] issuerSigned = resignMso(issue(document()), mso -> mso.put(new UnicodeString("deviceKeyInfo"),
                deviceKeyInfo(okpCoseKey(holder.getX().decode(), null))));
        MdocSamples.write(SAMPLES, getClass(), "ed25519-fixture", issuerSigned, holder.toPublicJWK(), DOCTYPE, FORMATTER_GAPS);

        VerificationReport report = verifier.verify(issuerSigned, holder.toPublicJWK(), Optional.empty(),
                Instant.now().plusSeconds(1), Options.strict(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_DEVICE_KEY).passed(), report.toString());
        FORMATTER_GAPS.assertMatches(report, MdocSamples.name(getClass(), "ed25519-fixture"));
    }

    // ---- mutations: the checks that must catch a bad credential ------------------------------------------------

    @Test
    void aTamperedSignatureFailsBothCoseOracles() throws Exception {
        byte[] issuerSigned = issue(document());
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
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.baseline(DOCTYPE + ".mdl"));
        assertFails(report, IndependentMdocVerifier.CHECK_DOC_TYPE, "a doctype other than the issued one must fail");
    }

    @Test
    void anExpiredCredentialFailsTheValidityWindow() throws Exception {
        // properly signed and properly tagged, only the window is in the past: nothing but the window check can tell
        byte[] expired = resignValidity(issue(document()),
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
        VerificationReport report = verify(issue(document()), Optional.of(foreign), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_CHAIN_TO_IACA,
                "an x5chain that does not reach the supplied IACA must fail");
    }

    @Test
    void aSelfSignedCertificateInTheX5chainIsDetected() throws Exception {
        // [leaf, ca] where the ca is self-signed: HAIP forbids carrying the trust anchor, so strict mode must catch it
        JcaKeyProvider chainKeys = new JcaKeyProvider();
        chainKeys.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify dev CA", "vc-signing");
        chainKeys.generateSignedBy("dev-dsc", SignatureAlgorithm.ES256, "CN=Inji Certify dev DSC", "vc-signing", "dev-ca");
        SigningContext withChain = signing(chainKeys, "dev-dsc");
        byte[] issuerSigned = issue(document(), withChain);

        VerificationReport report = verify(issuerSigned, Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_NO_SELF_SIGNED,
                "the self-signed CA in x5chain must be reported (HAIP)");
        assertEquals(2, x5chain(issuerSigned).size(), "the fixture must actually carry [leaf, ca]");
    }

    @Test
    void anX5chainAsArrayIsAccepted() throws Exception {
        // RFC 9360 allows x5chain as a bstr or an array; the harness must read both
        byte[] issuerSigned = issue(document());
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
        byte[] issuerSigned = issue(documentWithInteger());
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
        byte[] issuerSigned = issue(document());
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
        byte[] issuerSigned = issue(document());
        JWK other = JWK.parse(new com.nimbusds.jose.jwk.gen.ECKeyGenerator(
                com.nimbusds.jose.jwk.Curve.P_256).generate().toPublicJWK().toJSONString());
        VerificationReport report = verifier.verify(issuerSigned, other, Optional.empty(), AT, Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "the deviceKey must be the holder key");
    }

    @Test
    void aDeviceKeyCarryingThePrivateKeyFails() throws Exception {
        OctetKeyPair holder = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();
        byte[] leaked = resignMso(issue(document()), mso -> mso.put(new UnicodeString("deviceKeyInfo"),
                deviceKeyInfo(okpCoseKey(holder.getX().decode(), holder.getD().decode()))));
        VerificationReport report = verifier.verify(leaked, holder.toPublicJWK(), Optional.empty(),
                Instant.now().plusSeconds(1), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "a COSE_Key with d (label -4) must fail");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_DEVICE_KEY).message().contains("private key"), report.toString());
    }

    @Test
    void anOkpHolderDoesNotMatchAnotherOkpKey() throws Exception {
        OctetKeyPair holder = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();
        OctetKeyPair other = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();
        byte[] issuerSigned = resignMso(issue(document()), mso -> mso.put(new UnicodeString("deviceKeyInfo"),
                deviceKeyInfo(okpCoseKey(holder.getX().decode(), null))));
        VerificationReport report = verifier.verify(issuerSigned, other.toPublicJWK(), Optional.empty(),
                Instant.now().plusSeconds(1), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_DEVICE_KEY, "another Ed25519 key must not match by curve alone");
    }

    @Test
    void anExpectedUpdateBeforeValidFromFailsEvenWhenTheParseIsRepaired() throws Exception {
        // signed t-10s, expectedUpdate t-7s, validFrom t-5s and untagged: baseline mode repairs the tag for Multipaz,
        // and the wire ordering must still catch expectedUpdate < validFrom (ISO/IEC 18013-5 9.1.2.4)
        Instant t = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        byte[] bent = resignValidity(issue(document()), Map.of("signed", t.minusSeconds(10).toString(),
                "expectedUpdate", t.minusSeconds(7).toString(), "validFrom", t.minusSeconds(5).toString()), Set.of("validFrom"));
        VerificationReport report = verify(bent, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "expectedUpdate before validFrom must fail");
        assertTrue(report.check(IndependentMdocVerifier.CHECK_VALIDITY_INFO).message().contains("is before validFrom"),
                report.toString());
    }

    @Test
    void signedAfterValidFromFailsTheWindow() throws Exception {
        // the core path's G8: validFrom from the request instant, signed from the wall clock a moment later
        Instant t = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        byte[] bent = resignValidity(issue(document()), Map.of("signed", t.minusSeconds(4).toString(),
                "validFrom", t.minusSeconds(5).toString()), Set.of());
        VerificationReport report = verify(bent, Optional.empty(), Options.baseline(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signed after validFrom must fail");
    }

    @Test
    void formatterCurrentlyRefusesAnEd25519Holder() throws Exception {
        // gap G6: createDeviceKeyInfo knows EC2 only. M-02 binds OKP keys and replaces the ed25519 fixture sample.
        OctetKeyPair holder = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();
        String did = "did:jwk:" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(holder.toPublicJWK().toJSONString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        FormatException refused = assertThrows(FormatException.class, () -> {
            UnsignedCredential unsigned = formatter.build(ClaimSet.of(document()), configuration(signing()), CONTEXT,
                    HolderBinding.did(did, "jwt"));
            formatter.sign(unsigned, signing(), CONTEXT);
        });
        assertTrue(refused.getMessage().contains("Ed25519"), refused.getMessage());
    }

    // ---- one accepted problem cannot hide another one in the same check ----------------------------------------

    @Test
    void anExpiredResignedCredentialFailsEvenWithTheG8GapDeclared() throws Exception {
        // the review's mutation: with G8 accepted as a whole check, an expired, re-signed credential passed both gates.
        // Whole-second tag-0 dates, signed after validFrom (G8) and validUntil in 2021: only expired is new.
        byte[] expired = resignValidity(issue(document()), Map.of("signed", "2020-01-01T00:00:05Z",
                "validFrom", "2020-01-01T00:00:00Z", "validUntil", "2021-01-01T00:00:00Z"), Set.of());
        AcceptedGaps g8 = FORMATTER_GAPS.without(IndependentMdocVerifier.CHECK_TDATE_TAGS)
                .gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signedAfterValidFrom",
                        "G8: signed after validFrom, as the core path signs today; fixed by M-02");
        String name = MdocSamples.name(getClass(), "expired-g8");
        // for the CI python step, which must fail on it for the same reason (the .expect sidecar names the problem)
        Path written = MdocSamples.write(MUTATIONS, getClass(), "expired-g8", expired, JWK.parse(HOLDER_JWK), DOCTYPE, g8);
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
    void aNewElementTypeRegressionFailsWithTheOtherElementGapsDeclared() throws Exception {
        // family_name as a uint: every element gap of today's output stays declared, the new one is not
        Map<String, Object> regressed = Map.of("docType", DOCTYPE, "validityInfo", validity(),
                "nameSpaces", Map.of(NAMESPACE, List.of(element(0, "family_name", 42), element(1, "birth_date", "1990-01-01"))));
        VerificationReport report = verify(issue(regressed), Optional.empty(), Options.strict(DOCTYPE));
        AssertionError refused = assertThrows(AssertionError.class, () -> FORMATTER_GAPS.assertMatches(report, "regression"));
        assertTrue(refused.getMessage().contains("not an accepted gap of regression: mdl.elementTypes:untyped:family_name"),
                refused.getMessage());
        FORMATTER_GAPS.gap(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "untyped:family_name", "the mutation")
                .assertMatches(report, "regression");
    }

    @Test
    void theDraft13DocumentShapeAndTaggedIssuerAuthAreTheirOwnProblems() throws Exception {
        // the 0.14.0 wire shape: Document {docType, issuerSigned} around today's output, IssuerAuth under tag 18; both
        // signature oracles still verify after unwrapping, and nothing but the two shape codes is new
        co.nstant.in.cbor.model.Map issuerSigned = (co.nstant.in.cbor.model.Map) decode(issue(document()));
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
    void todayOutputIsABareUntaggedIssuerSigned() throws Exception {
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.strict(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_SHAPE).passed(), report.toString());
        assertTrue(report.check(IndependentMdocVerifier.CHECK_UNTAGGED).passed(), report.toString());
    }

    // ---- strict mode today: each check fails, and M-02/M-03/M-06 flip these tests ------------------------------
    // These are enabled on purpose. They assert where today's output stands, so the work packages that fix it must
    // change the assertion in the same commit that changes the output; they cannot be forgotten as @Disabled tests.

    @Test
    void strictModeCurrentlyRejectsFractionalSecondTdate() throws Exception {
        // gap G1: UTC_DATETIME_PATTERN emits "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"; M-02 truncates to whole seconds
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_TDATE_TAGS,
                "today's tdate carries milliseconds (ISO/IEC 18013-5 9.1.2.4)");
    }

    @Test
    void strictModeCurrentlyRejectsAnUntaggedDate() throws Exception {
        // same rule, other half: a plain tstr where #6.0(tstr) belongs. The formatter always tags, so the fixture
        // re-signs a valid credential with validFrom untagged and Multipaz must not be given a repaired copy.
        byte[] untagged = resignValidity(issue(document()), Map.of(), Set.of("validFrom"));
        VerificationReport report = verify(untagged, Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_TDATE_TAGS, "an untagged validFrom must fail strict mode");
    }

    @Test
    void strictModeCurrentlyRejectsASelfSignedX5chain() throws Exception {
        // gap G9: CoseHeaderPolicy.mdocIssuerAuth() carries the whole chain; M-02 signs without the anchor
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_NO_SELF_SIGNED,
                "the self-signed leaf is in x5chain today (HAIP)");
    }

    @Test
    void strictModeCurrentlyRejectsUntypedMandatoryElements() throws Exception {
        // gap G2/G3: no element typing table and no mandatory-element check; M-03 adds both
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_ELEMENT_TYPES,
                "an mDL without its Table 5 mandatory elements must fail");
    }

    @Test
    void strictModeWithoutAnIacaFailsTheChainCheck() throws Exception {
        VerificationReport report = verify(issue(document()), Optional.empty(), Options.strict(DOCTYPE));
        assertFails(report, IndependentMdocVerifier.CHECK_CHAIN_TO_IACA,
                "strict mode must fail, not skip, when there is no IACA to anchor the chain");
        assertFalse(report.passed(), "today's output cannot pass strict mode" + System.lineSeparator() + report);
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
        byte[] signature = KEYS.signRaw(sigStructure, KEYS.resolve(KeyRef.parse("jca:dev-es256")),
                SignatureAlgorithm.ES256);
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
