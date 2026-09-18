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

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'eddsa-rdfc-2022': {'EdDSA'}, 'ecdsa-rdfc-2019': {'ES256'}, 'RsaSignature2018': {'RS256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class IssuanceGoldenTest {

    static final String LDP_ID = "GoldenLdpCredential";
    static final String SDJWT_ID = "GoldenSdJwtCredential";
    static final String DI_ID = "GoldenDataIntegrityCredential";
    static final String RSA_ID = "GoldenRsaCredential";
    static final String SCOPE = "sample_vc_ldp"; // the scope LocalAccessTokenValidationFilter injects

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired StaticContextLoader staticContextLoader;
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
    }

    // ---- goldens -------------------------------------------------------------------------------------

    @Test
    void issuerMetadataGolden() throws Exception {
        JsonNode metadata = getJson("/.well-known/openid-credential-issuer");
        assertEquals(domainUrl, metadata.get("credential_issuer").asText());
        assertTrue(metadata.get("credential_configurations_supported").has(LDP_ID));
        Goldens.assertGolden("v1/well-known/openid-credential-issuer", metadata);
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
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
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
