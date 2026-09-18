package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end goldens for develop's OpenID4VCI 1.0 surface: the real service (H2, PKCS#12 keymanager,
 * Velocity, keymanager signing) issues ldp_vc and dc+sd-jwt credentials through MockMvc; every credential
 * is verified with a library Certify did not write (danubetech for Data Integrity / LD proofs, Nimbus for
 * JWS) against what the service itself publishes (did.json, jwks.json); normalized responses are compared
 * with the recorded goldens under src/test/resources/goldens/v1.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"}) // local activates the TestBearer filter; test (last) wins for properties
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        // MockMvc requests carry no servlet path; the TestBearer filter matches exact paths
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        // the local profile file names the PostgreSQL dialect; this context runs on H2
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'Ed25519Signature2018': {'EdDSA'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'EcdsaSecp256k1Signature2019': {'ES256K'}, 'eddsa-rdfc-2022': {'EdDSA'}, 'ecdsa-rdfc-2019': {'ES256'}, 'RsaSignature2018': {'RS256'}, 'ES256': {'ES256'}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class IssuanceGoldenTest {

    static final String LDP_ID = "GoldenLdpCredential";
    static final String SDJWT_ID = "GoldenSdJwtCredential";
    static final String DI_ID = "GoldenDataIntegrityCredential";
    static final String RSA_ID = "GoldenRsaCredential";
    static final String EC_R1_ID = "GoldenEcR1Credential";
    static final String EC_K1_ID = "GoldenEcK1Credential";
    static final String ED_2018_ID = "GoldenEd2018Credential";
    static final String MDOC_ID = "GoldenMdlCredential";
    static final String QR_ID = "GoldenQrCredential";
    static final String SCOPE = "sample_vc_ldp"; // the scope LocalAccessTokenValidationFilter injects

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired StaticContextLoader staticContextLoader;
    @Autowired io.mosip.certify.issuance.ConfigurationRegistry configurationRegistry;
    @Autowired io.mosip.certify.format.ldpvc.LdpVcFormatter ldpVcFormatter; // auto-configured over the service's StaticContextLoader
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;   // proof audience
    @Value("${mosip.certify.domain.url}") String domainUrl;           // metadata credential_issuer (a second identity key, see docs/design/14-configuration.md)

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(SDJWT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(sdJwtConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(DI_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig(DI_ID, "golden-ldp-di.vm",
                    "https://www.w3.org/ns/credentials/v2", "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "eddsa-rdfc-2022"));
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(RSA_ID).isEmpty()) {
            CredentialConfigurationDTO rsa = ldpConfig(RSA_ID, "golden-ldp-rsa.vm",
                    "https://www.w3.org/2018/credentials/v1", "CERTIFY_VC_SIGN_RSA", "", "RS256", "RsaSignature2018");
            rsa.setCredentialTypes(List.of("VerifiableCredential", "GoldenRsaCredential")); // ldp_vc configs are unique per (context, types)
            credentialConfigurationService.addCredentialConfiguration(rsa);
        }
        addLegacySuiteConfig(EC_R1_ID, "golden-ldp-ecr1.vm", "CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN", "ES256", "EcdsaSecp256r1Signature2019");
        addLegacySuiteConfig(EC_K1_ID, "golden-ldp-eck1.vm", "CERTIFY_VC_SIGN_EC_K1", "EC_SECP256K1_SIGN", "ES256K", "EcdsaSecp256k1Signature2019");
        addLegacySuiteConfig(ED_2018_ID, "golden-ldp-ed2018.vm", "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2018");
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(mdocConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(QR_ID).isEmpty()) {
            CredentialConfigurationDTO qr = ldpConfig(QR_ID, "golden-ldp-qr.vm", "https://www.w3.org/2018/credentials/v1",
                    "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2020");
            qr.setCredentialTypes(List.of("VerifiableCredential", QR_ID));
            // claim-169 QR: PixelPass maps these display names to numeric claim keys; the CWT is signed with the EdDSA key
            qr.setQrSettings(List.of(Map.of("Full Name", "${fullName}", "Date of Birth", "${dateOfBirth}")));
            qr.setQrSignatureAlgo("EdDSA");
            credentialConfigurationService.addCredentialConfiguration(qr);
        }
    }

    private void addLegacySuiteConfig(String id, String templateFile, String appId, String refId, String algo, String suite) throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(id).isEmpty()) {
            CredentialConfigurationDTO dto = ldpConfig(id, templateFile, "https://www.w3.org/2018/credentials/v1", appId, refId, algo, suite);
            dto.setCredentialTypes(List.of("VerifiableCredential", id));
            credentialConfigurationService.addCredentialConfiguration(dto);
        }
    }

    // ---- goldens -------------------------------------------------------------------------------------

    @Test
    void issuerMetadataGolden() throws Exception {
        JsonNode metadata = getJson("/.well-known/openid-credential-issuer");
        assertEquals(domainUrl, metadata.get("credential_issuer").asText());
        assertTrue(metadata.get("credential_configurations_supported").has(LDP_ID));
        Goldens.assertGolden("v1/well-known/openid-credential-issuer", metadata);
    }

    /** The new core's view of the same rows: every golden configuration maps, with the key the legacy columns name. */
    @Test
    void configurationRegistryMapsTheGoldenConfigurations() {
        io.mosip.certify.spi.CredentialConfiguration ldp = configurationRegistry.byId("default", LDP_ID).orElseThrow();
        assertEquals("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", ldp.signing().keyRef().toString());
        assertEquals("Ed25519Signature2020", ldp.signing().cryptosuite());
        assertEquals(io.mosip.certify.spi.TemplateRef.Mode.FULL_DOCUMENT, ldp.template().mode());
        io.mosip.certify.spi.CredentialConfiguration sd = configurationRegistry.bySelector("default", "dc+sd-jwt", "GoldenCredential").orElseThrow();
        assertEquals(SDJWT_ID, sd.id());
        io.mosip.certify.spi.CredentialConfiguration mdoc = configurationRegistry.bySelector("default", "mso_mdoc", "org.iso.18013.5.1.mDL").orElseThrow();
        assertEquals(MDOC_ID, mdoc.id());
        assertTrue(configurationRegistry.all("default").size() >= 9, "all nine golden configurations are visible: " + configurationRegistry.all("default").size());
        assertTrue(configurationRegistry.all("acme").isEmpty(), "single tenant");
        assertEquals("ldp_vc", ldpVcFormatter.formatId());
        // the row stores the types sorted alphabetically (finding: credential_definition.type order), the fragment reads them as stored
        assertEquals(java.util.List.of("GoldenCredential", "VerifiableCredential"), ((java.util.Map<?, ?>) ldpVcFormatter.metadataFragment(ldp, io.mosip.certify.spi.ProtocolVersion.OID4VCI_1_0).get("credential_definition")).get("type"));
    }

    /** The published keys: one JWK per certificate of every mapped alias plus CERTIFY_SERVICE; key material masked. */
    @Test
    void jwksGolden() throws Exception {
        JsonNode jwks = getJson("/.well-known/jwks.json");
        assertTrue(jwks.get("keys").size() >= 5, "four signing keys and the service key: " + jwks);
        for (JsonNode key : jwks.get("keys")) {
            assertTrue(key.hasNonNull("kid") && key.hasNonNull("kty"), "kid and kty on every JWK: " + key);
        }
        Goldens.assertGolden("v1/well-known/jwks", jwks);
    }

    /**
     * The DID document: one verification method per (suite, key) of the signing-alg map. Finding (PROGRESS.md):
     * assertionMethod and authentication list the DID itself instead of verification method ids.
     */
    @Test
    void didDocumentGolden() throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        assertEquals("did:web:localhost:certify", did.get("id").asText());
        assertTrue(did.get("verificationMethod").size() >= 4, did.toString());
        for (JsonNode method : did.get("verificationMethod")) {
            assertEquals("did:web:localhost:certify", method.get("controller").asText());
            assertTrue(method.get("id").asText().startsWith("did:web:localhost:certify#"), method.get("id").asText());
        }
        assertEquals("did:web:localhost:certify", did.get("assertionMethod").get(0).asText(), "documents today's behaviour, see findings");
        Goldens.assertGolden("v1/well-known/did", did);
    }

    @Test
    void ldpVcIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(LDP_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("GoldenCredential", credential.get("type").get(1).asText());
        assertEquals("Ed25519Signature2020", credential.get("proof").get("type").asText());
        assertEquals("Golden Farmer", credential.get("credentialSubject").get("fullName").asText());

        // independent verification: danubetech verifier with the key the service publishes in did.json
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new Ed25519Signature2020LdVerifier(publicKey).verify(jsonLd), "ldp_vc proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-response", body);
    }

    @Test
    void sdJwtIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(SDJWT_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String sdJwt = body.get("credentials").get(0).get("credential").asText();
        String[] parts = sdJwt.split("~");
        assertTrue(parts.length >= 3, "issuer JWS plus two disclosures: " + parts.length);

        JWSObject jws = JWSObject.parse(parts[0]);
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertNotNull(jws.getHeader().getX509CertChain(), "x5c is present");
        JsonNode payload = objectMapper.readTree(jws.getPayload().toString());
        assertEquals("GoldenCredential", payload.get("vct").asText());
        assertEquals(issuerIdentifier, payload.get("iss").asText(), "SD-JWT iss is mosip.certify.identifier");
        assertTrue(payload.has("_sd"), "selective disclosure digests present");
        assertEquals("1990-01-01", payload.get("dateOfBirth").asText(), "non-SD claim stays in clear");

        // independent verification with Nimbus against the JWKS the service publishes
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK key = jwks.getKeyByKeyId(jws.getHeader().getKeyID());
        assertNotNull(key, "kid " + jws.getHeader().getKeyID() + " must be in jwks.json");
        assertTrue(jws.verify(new ECDSAVerifier(key.toECKey())), "SD-JWT issuer signature must verify with Nimbus");

        Goldens.assertGolden("v1/issuance/dc+sd-jwt-payload", payload);
        Goldens.assertGolden("v1/issuance/dc+sd-jwt-header", objectMapper.readTree(jws.getHeader().toString()));
    }

    @Test
    void dataIntegrityIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(DI_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("DataIntegrityProof", credential.get("proof").get("type").asText());
        assertEquals("eddsa-rdfc-2022", credential.get("proof").get("cryptosuite").asText());
        assertEquals("https://www.w3.org/ns/credentials/v2", credential.get("@context").get(0).asText());

        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new DataIntegrityProofLdVerifier(new Ed25519_EdDSA_PublicKeyVerifier(publicKey)).verify(jsonLd),
                "eddsa-rdfc-2022 proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-data-integrity-response", body);
    }

    @Test
    void rsaIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(RSA_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("RsaSignature2018", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"));

        java.security.interfaces.RSAPublicKey publicKey = rsaPublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new RsaSignature2018LdVerifier(publicKey).verify(jsonLd), "RsaSignature2018 proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-rsa-response", body);
    }

    @Test
    void ed25519Signature2018GoldenAndIndependentVerification() throws Exception {
        JsonNode body = issuedBody(ED_2018_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("Ed25519Signature2018", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"), "2018 suites carry a detached jws");
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier(publicKey).verify(jsonLd),
                "Ed25519Signature2018 proof must verify with danubetech");
        Goldens.assertGolden("v1/issuance/ldp_vc-ed25519-2018-response", body);
    }

    @Test
    void ecdsaSecp256k1Signature2019GoldenAndIndependentVerification() throws Exception {
        JsonNode body = issuedBody(EC_K1_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("EcdsaSecp256k1Signature2019", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"));
        JsonNode method = verificationMethod(credential.get("proof").get("verificationMethod").asText());
        assertEquals("EcdsaSecp256k1VerificationKey2019", method.get("type").asText());
        JWK jwk = JWK.parse(method.get("publicKeyJwk").toString());
        java.security.PublicKey publicKey = jwk.toECKey().toECPublicKey(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
        // danubetech canonicalizes and parses the detached JWS; the ES256K signature itself is checked by plain JCA
        com.danubetech.keyformats.crypto.ByteVerifier jca = new com.danubetech.keyformats.crypto.ByteVerifier(com.danubetech.keyformats.jose.JWSAlgorithm.ES256K) {
            @Override
            protected boolean verify(byte[] content, byte[] signature) throws java.security.GeneralSecurityException {
                java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
                verifier.initVerify(publicKey);
                verifier.update(content);
                try {
                    return verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature));
                } catch (com.nimbusds.jose.JOSEException e) {
                    throw new java.security.SignatureException(e);
                }
            }
        };
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier(jca).verify(jsonLd),
                "EcdsaSecp256k1Signature2019 proof must verify with danubetech + JCA");
        Goldens.assertGolden("v1/issuance/ldp_vc-secp256k1-2019-response", body);
    }

    /**
     * EcdsaSecp256r1Signature2019 is Certify's own suite name (no registered LD suite, no third-party verifier exists);
     * verified here by canonicalizing with danubetech and checking the ECDSA signature with plain JCA against the
     * P-256 key in did.json. Logged as a spec finding in PROGRESS.md; the registered equivalent is ecdsa-rdfc-2019.
     */
    @Test
    void ecdsaSecp256r1Signature2019GoldenAndJcaVerification() throws Exception {
        JsonNode body = issuedBody(EC_R1_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("EcdsaSecp256r1Signature2019", credential.get("proof").get("type").asText());
        JsonNode method = verificationMethod(credential.get("proof").get("verificationMethod").asText());
        assertEquals("EcdsaSecp256r1VerificationKey2019", method.get("type").asText());
        byte[] multicodec = Multibase.decode(method.get("publicKeyMultibase").asText());
        byte[] compressed = Arrays.copyOfRange(multicodec, 2, multicodec.length); // strip 0x8024 (p256-pub)
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
        java.security.PublicKey publicKey = java.security.KeyFactory.getInstance("EC", "BC").generatePublic(
                new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getCurve().decodePoint(compressed), spec));

        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        info.weboftrust.ldsignatures.LdProof proof = info.weboftrust.ldsignatures.LdProof.getFromJsonLDObject(jsonLd);
        byte[] signature = Multibase.decode(proof.getProofValue());
        info.weboftrust.ldsignatures.LdProof options = info.weboftrust.ldsignatures.LdProof.builder().base(proof).defaultContexts(false).build(); // as CredentialUtils.generateLdProof canonicalizes
        info.weboftrust.ldsignatures.LdProof.removeLdProofValues(options);
        info.weboftrust.ldsignatures.LdProof.removeFromJsonLdObject(jsonLd);
        byte[] hash = new info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer().canonicalize(options, jsonLd);
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(hash);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature)),
                "EcdsaSecp256r1Signature2019 proofValue must verify with JCA over the URDNA2015 hash");
        Goldens.assertGolden("v1/issuance/ldp_vc-secp256r1-2019-response", body);
    }

    /**
     * mso_mdoc: the IssuerAuth COSE_Sign1 is verified with plain JCA against the x5chain leaf certificate; the MSO is
     * decoded with the CBOR library and checked structurally (ISO/IEC 18013-5 §9.1.2.4), including the device key
     * derived from the holder proof.
     */
    @Test
    void mdocIssuanceGoldenAndIndependentVerification() throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        MvcResult result = issue(MDOC_ID, proofJwt(nonce(), holder));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String credential = body.get("credentials").get(0).get("credential").asText();

        com.upokecenter.cbor.CBORObject issuerSigned = com.upokecenter.cbor.CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(credential));
        assertTrue(issuerSigned.ContainsKey("nameSpaces"), "IssuerSigned.nameSpaces");
        com.upokecenter.cbor.CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        assertEquals(4, issuerAuth.size(), "untagged COSE_Sign1 [protected, unprotected, payload, signature]");
        assertFalse(issuerAuth.isTagged(), "IssuerAuth is not tagged inside IssuerSigned");
        byte[] protectedBytes = issuerAuth.get(0).GetByteString();
        com.upokecenter.cbor.CBORObject protectedHeader = com.upokecenter.cbor.CBORObject.DecodeFromBytes(protectedBytes);
        assertEquals(-7, protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32(), "alg ES256 in the protected header");
        com.upokecenter.cbor.CBORObject unprotectedHeader = issuerAuth.get(1);
        com.upokecenter.cbor.CBORObject x5chain = unprotectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(33));
        assertNotNull(x5chain, "x5chain (33) in the unprotected header");
        byte[] leafDer = x5chain.getType() == com.upokecenter.cbor.CBORType.Array ? x5chain.get(0).GetByteString() : x5chain.GetByteString();
        java.security.cert.X509Certificate leaf = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(leafDer));
        byte[] payload = issuerAuth.get(2).GetByteString();
        byte[] signature = issuerAuth.get(3).GetByteString();
        byte[] sigStructure = com.upokecenter.cbor.CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(payload).EncodeToBytes();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(sigStructure);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature)), "IssuerAuth must verify with JCA against the x5chain leaf");
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        assertTrue(jwks.getKeys().stream().anyMatch(k -> {
            try { return k.toECKey().toECPublicKey().equals(leaf.getPublicKey()); } catch (Exception e) { return false; }
        }), "the x5chain leaf key is one of the published JWKS keys");

        com.upokecenter.cbor.CBORObject msoWrapped = com.upokecenter.cbor.CBORObject.DecodeFromBytes(payload);
        com.upokecenter.cbor.CBORObject mso = msoWrapped.HasMostOuterTag(24)
                ? com.upokecenter.cbor.CBORObject.DecodeFromBytes(msoWrapped.Untag().GetByteString()) : msoWrapped;
        assertEquals("org.iso.18013.5.1.mDL", mso.get("docType").AsString());
        assertEquals("SHA-256", mso.get("digestAlgorithm").AsString());
        com.upokecenter.cbor.CBORObject digests = mso.get("valueDigests").get("org.iso.18013.5.1");
        assertEquals(3, digests.size(), "one digest per namespace element");
        com.upokecenter.cbor.CBORObject deviceKey = mso.get("deviceKeyInfo").get("deviceKey");
        assertEquals(2, deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32(), "kty EC2");
        assertEquals(1, deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(-1)).AsInt32(), "crv P-256");
        assertArrayEquals(holder.getX().decode(), deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(-2)).GetByteString(), "device key x is the holder's");
        assertArrayEquals(holder.getY().decode(), deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(-3)).GetByteString(), "device key y is the holder's");
        for (String field : List.of("signed", "validFrom", "validUntil")) {
            assertTrue(mso.get("validityInfo").ContainsKey(field), "validityInfo." + field);
        }
        com.upokecenter.cbor.CBORObject items = issuerSigned.get("nameSpaces").get("org.iso.18013.5.1");
        assertEquals(3, items.size(), "three IssuerSignedItems");

        com.fasterxml.jackson.databind.node.ObjectNode summary = objectMapper.createObjectNode();
        summary.put("docType", mso.get("docType").AsString());
        summary.put("version", mso.get("version").AsString());
        summary.put("digestAlgorithm", mso.get("digestAlgorithm").AsString());
        summary.put("digests", digests.size());
        summary.put("issuerSignedItems", items.size());
        summary.put("protectedAlg", protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32());
        summary.put("unprotectedHeaderLabels", unprotectedHeader.getKeys().toString());
        summary.put("deviceKeyKty", deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32());
        summary.put("deviceKeyCrv", deviceKey.get(com.upokecenter.cbor.CBORObject.FromObject(-1)).AsInt32());
        summary.put("validityInfoKeys", mso.get("validityInfo").getKeys().toString());
        com.fasterxml.jackson.databind.node.ObjectNode responseShape = body.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) responseShape.get("credentials").get(0)).put("credential", "<mso_mdoc>");
        Goldens.assertGolden("v1/issuance/mso_mdoc-response", responseShape);
        Goldens.assertGolden("v1/issuance/mso_mdoc-summary", summary);
    }

    /**
     * Claim-169 QR (the compose FarmerCredential uses this): the template embeds the PixelPass-encoded CWT; decoded here,
     * the COSE_Sign1 (tag 61 around tag 18) is verified with plain JCA against the x5chain certificate and the claims
     * checked (iss, claim 169 with the mapped values).
     */
    @Test
    void claim169QrGoldenAndIndependentVerification() throws Exception {
        JsonNode body = issuedBody(QR_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        String qr = credential.get("credentialSubject").get("qr").asText();
        assertFalse(qr.isBlank(), "claim_169_values rendered into the credential");

        String decoded = new io.mosip.pixelpass.PixelPass().decode(qr);
        byte[] cwtBytes = java.util.HexFormat.of().parseHex(decoded);
        com.upokecenter.cbor.CBORObject outer = com.upokecenter.cbor.CBORObject.DecodeFromBytes(cwtBytes);
        assertTrue(outer.HasMostOuterTag(61), "CWT tag 61");
        com.upokecenter.cbor.CBORObject taggedSign1 = outer.UntagOne();
        assertTrue(taggedSign1.HasMostOuterTag(18), "COSE_Sign1 tag 18");
        com.upokecenter.cbor.CBORObject sign1 = taggedSign1.UntagOne();
        assertEquals(4, sign1.size());
        byte[] protectedBytes = sign1.get(0).GetByteString();
        com.upokecenter.cbor.CBORObject protectedHeader = com.upokecenter.cbor.CBORObject.DecodeFromBytes(protectedBytes);
        assertEquals(-8, protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsInt32(), "alg EdDSA");
        // Finding (PROGRESS.md): Credential.signQRData asks keymanager for x5c+kid, but keymanager only emits kid; the
        // certificate chain is absent from both headers, so a verifier must resolve the key by kid (jwks.json).
        assertFalse(protectedHeader.ContainsKey(com.upokecenter.cbor.CBORObject.FromObject(33)) || sign1.get(1).ContainsKey(com.upokecenter.cbor.CBORObject.FromObject(33)),
                "documents today's behaviour: no x5chain in the CWT");
        assertTrue(protectedHeader.ContainsKey(com.upokecenter.cbor.CBORObject.FromObject(4)), "kid in the protected header");
        String kid = new String(protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(4)).GetByteString(), StandardCharsets.UTF_8);
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK jwk = jwks.getKeyByKeyId(kid);
        assertNotNull(jwk, "CWT kid " + kid + " must be in jwks.json");
        byte[] rawX = jwk.toOctetKeyPair().getX().decode();
        byte[] spki = new byte[12 + 32];
        System.arraycopy(java.util.HexFormat.of().parseHex("302a300506032b6570032100"), 0, spki, 0, 12);
        System.arraycopy(rawX, 0, spki, 12, 32);
        java.security.PublicKey issuerKey = java.security.KeyFactory.getInstance("Ed25519").generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
        byte[] payload = sign1.get(2).GetByteString();
        byte[] sigStructure = com.upokecenter.cbor.CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(payload).EncodeToBytes();
        java.security.Signature verifier = java.security.Signature.getInstance("Ed25519");
        verifier.initVerify(issuerKey);
        verifier.update(sigStructure);
        assertTrue(verifier.verify(sign1.get(3).GetByteString()), "CWT signature must verify with JCA against the JWKS key named by kid");

        com.upokecenter.cbor.CBORObject claims = com.upokecenter.cbor.CBORObject.DecodeFromBytes(payload);
        assertEquals(domainUrl, claims.get(com.upokecenter.cbor.CBORObject.FromObject(1)).AsString(), "iss is the domain URL");
        com.upokecenter.cbor.CBORObject claim169 = claims.get(com.upokecenter.cbor.CBORObject.FromObject(169));
        assertNotNull(claim169, "claim 169 present");
        assertEquals(com.upokecenter.cbor.CBORType.ByteString, claim169.getType(), "claim 169 is bstr .cbor");
        com.upokecenter.cbor.CBORObject claim169Map = com.upokecenter.cbor.CBORObject.DecodeFromBytes(claim169.GetByteString());
        assertEquals(com.upokecenter.cbor.CBORType.Map, claim169Map.getType());
        assertTrue(claim169Map.getValues().stream().map(com.upokecenter.cbor.CBORObject::AsString).toList().contains("Golden Farmer"), claim169Map.toString());

        com.fasterxml.jackson.databind.node.ObjectNode summary = objectMapper.createObjectNode();
        summary.put("outerTag", 61).put("innerTag", 18);
        summary.put("protectedLabels", protectedHeader.getKeys().toString());
        summary.put("unprotectedLabels", sign1.get(1).getKeys().toString());
        summary.put("claimLabels", claims.getKeys().toString());
        summary.put("claim169Keys", claim169Map.getKeys().toString());
        Goldens.assertGolden("v1/issuance/ldp_vc-qr-response", body);
        Goldens.assertGolden("v1/issuance/claim169-cwt-summary", summary);
    }

    /** The flow docs/design/VALIDATE.md drives by hand: offer, offer fetch, token; the access token is verified against jwks.json. */
    @Test
    void preAuthorizedCodeFlowGoldenAndAccessTokenVerification() throws Exception {
        MvcResult offerResult = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", LDP_ID, "claims", Map.of("fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru"),
                        "expires_in", 600, "tx_code", "1234")))).andReturn();
        JsonNode offerBody = objectMapper.readTree(offerResult.getResponse().getContentAsString());
        assertEquals(200, offerResult.getResponse().getStatus(), offerBody.toString());
        assertTrue(offerBody.has("credential_offer_uri"), "offer response: " + offerBody);
        String offerUri = offerBody.get("credential_offer_uri").asText();
        assertTrue(offerUri.startsWith("openid-credential-offer://"), offerUri);
        String offerUrl = java.net.URLDecoder.decode(offerUri.substring(offerUri.indexOf("credential_offer_uri=") + "credential_offer_uri=".length()), StandardCharsets.UTF_8);
        String offerId = offerUrl.substring(offerUrl.lastIndexOf('/') + 1);
        Goldens.assertGolden("v1/pre-authorized/offer-uri", offerBody);

        JsonNode offer = getJson("/credential-offer-data/" + offerId);
        // Finding (PROGRESS.md): the offer names the issuer as mosip.certify.identifier (with servlet path) while the
        // issuer metadata's credential_issuer is mosip.certify.domain.url; OpenID4VCI requires the same identifier.
        assertEquals(issuerIdentifier, offer.get("credential_issuer").asText());
        assertNotEquals(domainUrl, offer.get("credential_issuer").asText(), "the two identity keys still differ (dual identity finding)");
        assertEquals(LDP_ID, offer.get("credential_configuration_ids").get(0).asText());
        JsonNode grant = offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        String code = grant.get("pre-authorized_code").asText();
        Goldens.assertGolden("v1/pre-authorized/credential-offer", offer);

        MvcResult tokenResult = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", code).param("tx_code", "1234")).andReturn();
        JsonNode token = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        assertEquals(200, tokenResult.getResponse().getStatus(), token.toString());
        assertEquals("Bearer", token.get("token_type").asText());
        SignedJWT accessToken = SignedJWT.parse(token.get("access_token").asText());
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK key = jwks.getKeyByKeyId(accessToken.getHeader().getKeyID());
        assertNotNull(key, "access token kid " + accessToken.getHeader().getKeyID() + " must be in jwks.json");
        assertTrue(accessToken.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(key.toRSAKey())), "access token must verify with Nimbus");
        assertEquals(SCOPE, accessToken.getJWTClaimsSet().getStringClaim("scope"));
        Goldens.assertGolden("v1/pre-authorized/token-response", token);
        // Finding (PROGRESS.md): sub carries the offer claims as a JSON string in map order (PII inside the access token,
        // nondeterministic key order); parsed here so the golden is stable while the finding stands.
        com.fasterxml.jackson.databind.node.ObjectNode claims = (com.fasterxml.jackson.databind.node.ObjectNode) objectMapper.readTree(accessToken.getJWTClaimsSet().toString());
        claims.set("sub", objectMapper.readTree(claims.get("sub").asText()));
        Goldens.assertGolden("v1/pre-authorized/access-token-claims", claims);
        Goldens.assertGolden("v1/pre-authorized/access-token-header", objectMapper.readTree(accessToken.getHeader().toString()));
    }

    @Test
    void wrongNonceIsRejectedGolden() throws Exception {
        nonce();
        MvcResult result = issue(LDP_ID, proofJwt("not-the-nonce"));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        Goldens.assertGolden("v1/issuance/error-invalid-nonce", objectMapper.createObjectNode()
                .put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body)));
    }

    @Test
    void unknownConfigurationIsRejectedGolden() throws Exception {
        MvcResult result = issue("NoSuchCredential", proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        Goldens.assertGolden("v1/issuance/error-unknown-configuration", objectMapper.createObjectNode()
                .put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body)));
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private JsonNode getJson(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/nonce")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private JsonNode issuedBody(String configurationId) throws Exception {
        MvcResult result = issue(configurationId, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        return body;
    }

    private JsonNode verificationMethod(String id) throws Exception {
        for (JsonNode method : getJson("/.well-known/did.json").get("verificationMethod")) {
            if (id.equals(method.get("id").asText())) {
                return method;
            }
        }
        throw new AssertionError("verification method " + id + " not in did.json");
    }

    private MvcResult issue(String configurationId, String proof) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "credential_configuration_id", configurationId,
                "proofs", Map.of("jwt", List.of(proof))));
        return mockMvc.perform(post("/issuance/credential")
                .header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    /** A holder proof as a wallet builds it: ES256, typ openid4vci-proof+jwt, public jwk in the header. */
    private String proofJwt(String nonce) throws Exception {
        return proofJwt(nonce, new ECKeyGenerator(Curve.P_256).generate());
    }

    private String proofJwt(String nonce, ECKey holder) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().audience(issuerIdentifier).issueTime(new Date())
                .claim("nonce", nonce).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private byte[] ed25519PublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                byte[] decoded = Multibase.decode(method.get("publicKeyMultibase").asText());
                return Arrays.copyOfRange(decoded, 2, decoded.length); // strip the 0xed01 multicodec prefix
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }

    private java.security.interfaces.RSAPublicKey rsaPublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                String pem = method.get("publicKeyPem").asText().replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
                return (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }

    private static String template(String name) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates", name);
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Base64.getEncoder().encodeToString(Files.readString(path, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
    }

    private static MetaDataDisplayDTO display(String name) {
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(name);
        display.setLocale("en");
        return display;
    }

    private static ClaimsDTO claim(String name) {
        ClaimsDTO.Display display = new ClaimsDTO.Display();
        display.setName(name);
        display.setLocale("en");
        ClaimsDTO claims = new ClaimsDTO();
        claims.setDisplay(List.of(display));
        return claims;
    }

    private static CredentialConfigurationDTO ldpConfig() throws Exception {
        return ldpConfig(LDP_ID, "golden-ldp.vm", "https://www.w3.org/2018/credentials/v1",
                "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2020");
    }

    private static CredentialConfigurationDTO ldpConfig(String id, String templateFile, String context, String appId,
                                                        String refId, String algo, String suite) throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(template(templateFile));
        dto.setContextURLs(List.of(context));
        dto.setCredentialTypes(List.of("VerifiableCredential", "GoldenCredential"));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId(appId);
        dto.setKeyManagerRefId(refId);
        dto.setSignatureAlgo(algo);
        dto.setSignatureCryptoSuite(suite);
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth", "city"));
        dto.setClaims(Map.of("fullName", claim("Full name"), "dateOfBirth", claim("Date of birth"), "city", claim("City")));
        return dto;
    }

    /** mso_mdoc: docType, namespace claims, ES256 with the EC_R1 key; the validator wants a cryptosuite key of the signing-alg map. */
    private static CredentialConfigurationDTO mdocConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(MDOC_ID);
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate(template("golden-mdoc.vm"));
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256");
        dto.setSignatureCryptoSuite("ES256");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden mDL")));
        dto.setDisplayOrder(List.of("family_name", "birth_date"));
        ClaimsDisplayFieldsConfigDTO familyName = new ClaimsDisplayFieldsConfigDTO();
        dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", familyName)));
        return dto;
    }

    private static CredentialConfigurationDTO sdJwtConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(SDJWT_ID);
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setVcTemplate(template("golden-sdjwt.vm"));
        dto.setSdJwtVct("GoldenCredential");
        dto.setSdClaim("$.fullName,$.address.city");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256"); // SD-JWT configs carry no cryptosuite (SdJwtCredentialConfigValidator)
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden SD-JWT Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth"));
        ClaimsDisplayFieldsConfigDTO fullName = new ClaimsDisplayFieldsConfigDTO();
        dto.setSdJwtClaims(Map.of("fullName", fullName));
        return dto;
    }
}
