/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.testkit.mdoc.IndependentMdocVerifier;
import io.mosip.certify.testkit.mdoc.Options;
import io.mosip.certify.testkit.mdoc.VerificationReport;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The formatter's own tests agree with its writer; this one checks the bytes with libraries Certify does not maintain
 * (Multipaz and Authlete CBOR, {@code certify-testkit-mdoc}). Checks today's output cannot pass are separate,
 * disabled methods naming the work package that enables them (docs/design/20-mdl-issuer.md M-01).
 */
class MdocIndependentVerificationTest {

    static final String DOCTYPE = "org.iso.18013.5.1.mDL";
    static final JcaKeyProvider KEYS = JcaKeyProvider.devMode();
    static final Instant AT = Instant.now();
    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, null, List.of(),
            ProtocolVersion.OID4VCI_1_0, "c", AT, Map.of());
    static final String HOLDER_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
    static final String HOLDER = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(HOLDER_JWK.getBytes());

    final IndependentMdocVerifier verifier = new IndependentMdocVerifier();
    final MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), new MdocProperties("SHA-256", "1.0", 2));

    static Map<String, Object> element(int digestId, String identifier, Object value) {
        return Map.of("digestID", digestId, "elementIdentifier", identifier, "elementValue", value);
    }

    static Map<String, Object> document() {
        return Map.of("docType", DOCTYPE,
                "validityInfo", Map.of("validFrom", "${_validFrom}", "validUntil", "${_validUntil}", "signed", "${_signed}"),
                "nameSpaces", Map.of("org.iso.18013.5.1", List.of(
                        element(0, "family_name", "Farmer"), element(1, "birth_date", "1990-01-01"))));
    }

    SigningContext signing() {
        SigningKey key = KEYS.resolve(KeyRef.parse("jca:dev-es256"));
        return new SigningContext(new SigningConfig(key.ref(), SignatureAlgorithm.ES256, null, null, null,
                "did:web:issuer.example"), key, KEYS);
    }

    CredentialConfiguration configuration() {
        return new CredentialConfiguration(null, "mdl", "mdl_scope", "mso_mdoc",
                formatter.parseConfig(Map.of("docType", DOCTYPE)), null, signing().config(), null, null, null, null, null);
    }

    byte[] issue(Map<String, Object> document) throws Exception {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), configuration(), CONTEXT,
                HolderBinding.did(HOLDER, "jwt"));
        IssuedCredential issued = formatter.sign(unsigned, signing(), CONTEXT);
        return Base64.getUrlDecoder().decode((String) issued.credential());
    }

    VerificationReport verify(byte[] issuerSigned, Optional<X509Certificate> iaca, Options options) throws Exception {
        // the formatter signs at the wall clock, so verification happens after it rather than at AT
        return verifier.verify(issuerSigned, JWK.parse(HOLDER_JWK), iaca, Instant.now().plusSeconds(1), options);
    }

    @Test
    void todayOutputPassesEveryCheckTheHarnessCanEnforce() throws Exception {
        byte[] issuerSigned = issue(document());
        writeSample(issuerSigned); // before the assertions: the CI python verifier reads it even when a check fails
        VerificationReport report = verify(issuerSigned, Optional.empty(), Options.baseline(DOCTYPE));
        report.assertAllPassed();
        assertEquals(Set.of(IndependentMdocVerifier.CHECK_SIGNATURE_MULTIPAZ,
                        IndependentMdocVerifier.CHECK_SIGNATURE_AUTHLETE,
                        IndependentMdocVerifier.CHECK_VALUE_DIGESTS,
                        IndependentMdocVerifier.CHECK_DIGEST_IDS_UNIQUE,
                        IndependentMdocVerifier.CHECK_DEVICE_KEY,
                        IndependentMdocVerifier.CHECK_DOC_TYPE,
                        IndependentMdocVerifier.CHECK_VALIDITY_INFO,
                        IndependentMdocVerifier.CHECK_CHAIN_TO_IACA,
                        IndependentMdocVerifier.CHECK_NO_SELF_SIGNED,
                        IndependentMdocVerifier.CHECK_ELEMENT_TYPES),
                report.checks().stream().map(VerificationReport.Check::name).collect(Collectors.toSet()));
    }

    /** The sample {@code docs/design/tools/verify_mdoc.py} runs over in CI, and the one an operator can inspect. */
    static void writeSample(byte[] issuerSigned) throws Exception {
        Path directory = Path.of("target", "mdoc-samples");
        Files.createDirectories(directory);
        Files.write(directory.resolve("mdl-issuer-signed.mdoc"), issuerSigned);
        Files.writeString(directory.resolve("mdl-issuer-signed.b64url"),
                Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned));
    }

    @Test
    void aTamperedElementFailsTheDigestCheck() throws Exception {
        byte[] issuerSigned = issue(document());
        // flip a byte in the CBOR of the first IssuerSignedItem: the signature covers the MSO, not the items,
        // so only the digest check can catch this
        byte[] tampered = issuerSigned.clone();
        byte[] needle = "Farmer".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (int i = 0; i + needle.length <= tampered.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (tampered[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                tampered[i] = 'B';
                break;
            }
        }
        VerificationReport report = verify(tampered, Optional.empty(), Options.baseline(DOCTYPE));
        assertFalse(report.check(IndependentMdocVerifier.CHECK_VALUE_DIGESTS).passed(), report.toString());
    }

    @Test
    void aCredentialBoundToAnotherHolderFailsTheDeviceKeyCheck() throws Exception {
        byte[] issuerSigned = issue(document());
        JWK other = JWK.parse(new com.nimbusds.jose.jwk.gen.ECKeyGenerator(
                com.nimbusds.jose.jwk.Curve.P_256).generate().toPublicJWK().toJSONString());
        VerificationReport report = verifier.verify(issuerSigned, other, Optional.empty(), AT, Options.baseline(DOCTYPE));
        assertFalse(report.check(IndependentMdocVerifier.CHECK_DEVICE_KEY).passed(), report.toString());
    }

    @Test
    @Disabled("enabled by M-02: seconds-only tdate (gap G1, ISO/IEC 18013-5 9.1.2.4)")
    void strictTdateRejectsFractionalSeconds() throws Exception {
        VerificationReport report = verify(issue(document()), Optional.empty(),
                new Options(DOCTYPE, true, false, false));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_VALIDITY_INFO).passed(), report.toString());
    }

    @Test
    @Disabled("enabled by M-02: x5chain without the trust anchor (gap G9, HAIP)")
    void x5chainCarriesNoSelfSignedCertificate() throws Exception {
        VerificationReport report = verify(issue(document()), Optional.empty(),
                new Options(DOCTYPE, false, true, false));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_NO_SELF_SIGNED).passed(), report.toString());
    }

    @Test
    @Disabled("enabled by M-06: the DSC chain reaches the configured IACA")
    void x5chainValidatesToTheConfiguredIaca() throws Exception {
        X509Certificate iaca = signing().key().chain().root().orElseThrow();
        VerificationReport report = verify(issue(document()), Optional.of(iaca), Options.strict(DOCTYPE));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_CHAIN_TO_IACA).passed(), report.toString());
    }

    @Test
    @Disabled("enabled by M-03: typed elements and a binary portrait (gap G2, ISO/IEC 18013-5 7.2.1 Table 5)")
    void mdlElementsAreTypedLikeMultipazDrivingLicense() throws Exception {
        Map<String, Object> document = Map.of("docType", DOCTYPE,
                "validityInfo", Map.of("validFrom", "${_validFrom}", "validUntil", "${_validUntil}", "signed", "${_signed}"),
                "nameSpaces", Map.of("org.iso.18013.5.1", List.of(
                        element(0, "family_name", "Farmer"), element(1, "given_name", "Golden"),
                        element(2, "birth_date", "1990-01-01"), element(3, "issue_date", "2024-01-01"),
                        element(4, "expiry_date", "2034-01-01"), element(5, "issuing_country", "IN"),
                        element(6, "issuing_authority", "Lorem Ipsum Demo"), element(7, "document_number", "MDL-0001"),
                        element(8, "un_distinguishing_sign", "LID"), element(9, "portrait", "aGVsbG8="),
                        element(10, "driving_privileges", List.of(Map.of("vehicle_category_code", "B",
                                "issue_date", "2024-01-01", "expiry_date", "2034-01-01"))))));
        VerificationReport report = verify(issue(document), Optional.empty(),
                new Options(DOCTYPE, false, false, true));
        assertTrue(report.check(IndependentMdocVerifier.CHECK_ELEMENT_TYPES).passed(), report.toString());
    }
}
