package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.api.spi.DataProviderPlugin;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Key attestations on the new surface (OpenID4VCI 1.0 Appendix D and F): a configuration that requires them refuses a
 * plain {@code jwt} proof, accepts a proof whose {@code key_attestation} header is signed by a configured attester and
 * attests the proof key, issues one credential per attested key, and takes an {@code attestation} proof (no proof of
 * possession) whose {@code nonce} is the {@code c_nonce}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:uuid:",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256'}}}"
})
class KeyAttestationTest {

    static final String CONFIG_ID = "KeyAttestedCredential";
    static final String ATTESTER_ID = "https://wallet-provider.example";
    static final ECKey ATTESTER = generate("wallet-provider-1");
    static final ECKey ROGUE_ATTESTER = generate("rogue-1");

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @DynamicPropertySource
    static void attester(DynamicPropertyRegistry registry) {
        registry.add("certify.protocol.oid4vci-v1.key-attestation.attesters.wallet-provider.jwks", () -> new JWKSet(ATTESTER.toPublicJWK()).toString());
    }

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Attested Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (mockMvc.perform(get("/v2/credential-configurations/" + CONFIG_ID)).andReturn().getResponse().getStatus() == 404) {
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(configuration()))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }
    }

    @Test
    void aJwtProofWithoutTheRequiredAttestationIsRefused() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        MvcResult result = issue(Map.of("jwt", List.of(proof(holder, nonce, null))));
        assertError(result, 400, "invalid_proof");
    }

    @Test
    void aJwtProofWithAnAttestationIssuesOneCredentialPerAttestedKey() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        ECKey sibling = generate(null);
        String attestation = attestation(ATTESTER, List.of(holder, sibling), nonce, List.of("iso_18045_high"), Instant.now().plusSeconds(600));
        MvcResult result = issue(Map.of("jwt", List.of(proof(holder, nonce, attestation))));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertEquals(2, body.get("credentials").size(), body.toString());
        assertEquals(didJwk(holder), body.get("credentials").get(0).get("credential").get("credentialSubject").get("id").asText());
        assertEquals(didJwk(sibling), body.get("credentials").get(1).get("credential").get("credentialSubject").get("id").asText());
    }

    @Test
    void aJwtProofSignedByAKeyTheAttestationDoesNotCoverIsRefused() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        String attestation = attestation(ATTESTER, List.of(generate(null)), nonce, List.of("iso_18045_high"), Instant.now().plusSeconds(600));
        assertError(issue(Map.of("jwt", List.of(proof(holder, nonce, attestation)))), 400, "invalid_proof");
    }

    @Test
    void anAttestationFromAnUnknownAttesterIsRefused() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        String attestation = attestation(ROGUE_ATTESTER, List.of(holder), nonce, List.of("iso_18045_high"), Instant.now().plusSeconds(600));
        assertError(issue(Map.of("jwt", List.of(proof(holder, nonce, attestation)))), 400, "invalid_proof");
    }

    @Test
    void anAttestationBelowTheAcceptedKeyStorageIsRefused() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        String attestation = attestation(ATTESTER, List.of(holder), nonce, List.of("iso_18045_basic"), Instant.now().plusSeconds(600));
        assertError(issue(Map.of("jwt", List.of(proof(holder, nonce, attestation)))), 400, "invalid_proof");
    }

    @Test
    void anAttestationWhoseNonceIsNotTheProofNonceIsRefused() throws Exception {
        String nonce = nonce();
        ECKey holder = generate(null);
        String attestation = attestation(ATTESTER, List.of(holder), "another-nonce", List.of("iso_18045_high"), Instant.now().plusSeconds(600));
        assertError(issue(Map.of("jwt", List.of(proof(holder, nonce, attestation)))), 400, "invalid_proof");
    }

    @Test
    void anAttestationProofIssuesOneCredentialPerAttestedKey() throws Exception {
        String nonce = nonce();
        ECKey first = generate(null);
        ECKey second = generate(null);
        String attestation = attestation(ATTESTER, List.of(first, second), nonce, List.of("iso_18045_moderate"), null);
        MvcResult result = issue(Map.of("attestation", List.of(attestation)));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertEquals(2, body.get("credentials").size(), body.toString());
        assertEquals(didJwk(first), body.get("credentials").get(0).get("credential").get("credentialSubject").get("id").asText());
        assertEquals(didJwk(second), body.get("credentials").get(1).get("credential").get("credentialSubject").get("id").asText());
        // the c_nonce was consumed by this request
        assertError(issue(Map.of("attestation", List.of(attestation))), 400, "invalid_nonce");
    }

    @Test
    void anAttestationProofWithoutTheNonceIsRefused() throws Exception {
        nonce();
        String attestation = attestation(ATTESTER, List.of(generate(null)), null, List.of("iso_18045_high"), null);
        assertError(issue(Map.of("attestation", List.of(attestation))), 400, "invalid_nonce");
    }

    @Test
    void moreAttestedKeysThanTheBatchSizeAreRefused() throws Exception {
        String nonce = nonce();
        List<ECKey> keys = new ArrayList<>();
        for (int i = 0; i < 11; i++) {
            keys.add(generate(null));
        }
        String attestation = attestation(ATTESTER, keys, nonce, List.of("iso_18045_high"), null);
        assertError(issue(Map.of("attestation", List.of(attestation))), 400, "invalid_credential_request");
    }

    @Test
    void theMetadataAdvertisesTheRequirementAndTheAttestationProofType() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        JsonNode proofTypes = metadata.get("credential_configurations_supported").get(CONFIG_ID).get("proof_types_supported");
        assertEquals("iso_18045_high", proofTypes.get("jwt").get("key_attestations_required").get("key_storage").get(0).asText(), proofTypes.toString());
        assertEquals("ES256", proofTypes.get("attestation").get("proof_signing_alg_values_supported").get(0).asText(), proofTypes.toString());
        assertTrue(proofTypes.get("attestation").get("key_attestations_required") == null, "attestation proofs carry their own attestation");
    }

    // ---- helpers -------------------------------------------------------------------------------------------------

    private void assertError(MvcResult result, int status, String error) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(status, result.getResponse().getStatus(), body.toString());
        assertEquals(error, body.get("error").asText(), body.toString());
    }

    private MvcResult issue(Map<String, List<String>> proofs) throws Exception {
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "proofs", proofs)))).andReturn();
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    /** A wallet's jwt proof: ES256, typ openid4vci-proof+jwt, public jwk in the header, optionally the key attestation. */
    private String proof(ECKey holder, String nonce, String keyAttestation) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK());
        if (keyAttestation != null) {
            header.customParam(JwtProofValidatorAdapterKeyAttestation.HEADER, keyAttestation);
        }
        SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    /** A key attestation as a wallet provider issues it (Appendix D.1). */
    static String attestation(ECKey attester, List<ECKey> keys, String nonce, List<String> keyStorage, Instant expiresAt) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(ATTESTER_ID).issueTime(new Date())
                .claim("attested_keys", keys.stream().map(k -> k.toPublicJWK().toJSONObject()).toList())
                .claim("key_storage", keyStorage)
                .claim("user_authentication", List.of("iso_18045_high"));
        if (expiresAt != null) {
            claims.expirationTime(Date.from(expiresAt));
        }
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("key-attestation+jwt")).keyID(attester.getKeyID()).build(), claims.build());
        jwt.sign(new ECDSASigner(attester));
        return jwt.serialize();
    }

    /** The did:jwk the issuer binds, encoded as the legacy proof managers encode it. */
    static String didJwk(JWK key) {
        return "did:jwk:" + Base64.getUrlEncoder().encodeToString(key.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8));
    }

    static ECKey generate(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> configuration() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + CONFIG_ID + "\": \"https://example.org/golden#" + CONFIG_ID + "\"").replace("\"GoldenCredential\"]", "\"" + CONFIG_ID + "\"]");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", CONFIG_ID);
        body.put("scope", "sample_vc_ldp"); // the local TestBearer token carries this scope
        body.put("format", "ldp_vc");
        body.put("formatConfig", Map.of("context", List.of("https://www.w3.org/2018/credentials/v1"), "types", List.of("VerifiableCredential", CONFIG_ID),
                "claims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
        body.put("signing", Map.of("alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg", "EdDSA", "cryptosuite", "Ed25519Signature2020", "didUrl", "did:web:localhost:certify"));
        body.put("template", Map.of("content", template));
        body.put("display", Map.of("display", List.of(Map.of("name", CONFIG_ID, "locale", "en")), "order", List.of("fullName")));
        Map<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"),
                "key_attestations_required", Map.of("key_storage", List.of("iso_18045_high", "iso_18045_moderate"))));
        proofTypes.put("attestation", Map.of("proof_signing_alg_values_supported", List.of("ES256")));
        body.put("protocol", Map.of("cryptographicBindingMethodsSupported", List.of("did:jwk"), "proofTypesSupported", proofTypes));
        return body;
    }

    /** The header name, kept next to the test so a rename in the adapter fails here first. */
    static final class JwtProofValidatorAdapterKeyAttestation {
        static final String HEADER = io.mosip.certify.proof.JwtProofValidatorAdapter.HEADER_KEY_ATTESTATION;
    }
}
