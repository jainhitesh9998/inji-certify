package io.mosip.certify.vcapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The VC-API issuer adapter: a registered client (HTTP Basic) posts a credential body to {@code /vc-api/credentials/issue}
 * and gets it back signed (201) by the supplied-strategy configuration whose context and type match; the proof verifies
 * with danubetech against the key in did.json. Unauthenticated calls, unknown types, an issuer that is not the
 * configuration's DID, selective-disclosure options and a client without the right to the configuration are refused
 * with problem details; the status endpoint validates its body and answers 404 for an unknown credential.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "certify.protocol.vc-api.enabled=true",
        "certify.protocol.vc-api.clients.coordinator.secret=s3cret",
        "certify.protocol.vc-api.clients.other.secret=other-secret",
        "certify.protocol.vc-api.clients.other.credential-configurations=SomeOtherConfiguration"
})
class VcApiIssuanceTest {

    static final String CONFIG_ID = "SuppliedGoldenCredential";
    static final String ISSUER = "did:web:localhost:certify";
    static final List<String> CONTEXT = List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1");
    static final List<String> TYPES = List.of("VerifiableCredential", CONFIG_ID);

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired StaticContextLoader staticContextLoader;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void configuration() throws Exception {
        if (mockMvc.perform(get("/v2/credential-configurations/" + CONFIG_ID)).andReturn().getResponse().getStatus() == 404) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("id", CONFIG_ID);
            body.put("scope", "vc_api_supplied");
            body.put("format", "ldp_vc");
            body.put("issuanceStrategy", "SUPPLIED");
            body.put("formatConfig", Map.of("context", CONTEXT, "types", TYPES, "claims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
            body.put("signing", Map.of("alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg", "EdDSA", "cryptosuite", "Ed25519Signature2020", "didUrl", ISSUER));
            body.put("display", Map.of("display", List.of(Map.of("name", CONFIG_ID, "locale", "en")), "order", List.of("fullName")));
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }
    }

    @Test
    void aRegisteredClientGetsTheSuppliedCredentialSignedAndItVerifies() throws Exception {
        Map<String, Object> credential = credential("urn:uuid:5f3a1c2e-0000-4000-8000-000000000001");
        MvcResult result = issue(basic("coordinator", "s3cret"), Map.of("credential", credential));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(201, result.getResponse().getStatus(), body.toString());
        JsonNode vc = body.get("verifiableCredential");
        assertNotNull(vc, body.toString());
        assertEquals("urn:uuid:5f3a1c2e-0000-4000-8000-000000000001", vc.get("id").asText());
        assertEquals("Supplied Farmer", vc.get("credentialSubject").get("fullName").asText());
        assertEquals("Ed25519Signature2020", vc.get("proof").get("type").asText());
        assertTrue(vc.get("proof").get("verificationMethod").asText().startsWith(ISSUER + "#"));

        JsonLDObject jsonLd = JsonLDObject.fromJson(vc.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        byte[] publicKey = ed25519PublicKeyFromDidDocument(vc.get("proof").get("verificationMethod").asText());
        assertTrue(new Ed25519Signature2020LdVerifier(publicKey).verify(jsonLd), "danubetech must verify the VC-API issued credential");
    }

    @Test
    void callsWithoutAValidClientAreRefused() throws Exception {
        MvcResult none = issue(null, Map.of("credential", credential(null)));
        assertEquals(401, none.getResponse().getStatus());
        assertEquals("Basic realm=\"vc-api\"", none.getResponse().getHeader("WWW-Authenticate"));
        assertEquals("UNAUTHORIZED", objectMapper.readTree(none.getResponse().getContentAsString()).get("title").asText());
        assertEquals(401, issue(basic("coordinator", "wrong"), Map.of("credential", credential(null))).getResponse().getStatus());
        assertEquals(401, issue(basic("nobody", "s3cret"), Map.of("credential", credential(null))).getResponse().getStatus());
    }

    @Test
    void badRequestsAnswerProblemDetails() throws Exception {
        assertProblem(issue(basic("coordinator", "s3cret"), Map.of("credential", "not-an-object")), 400, "MALFORMED_VALUE_ERROR");
        Map<String, Object> unknownType = credential(null);
        unknownType.put("type", List.of("VerifiableCredential", "NobodyIssuesThis"));
        assertProblem(issue(basic("coordinator", "s3cret"), Map.of("credential", unknownType)), 400, "NOT_CONFIGURED");
        Map<String, Object> wrongIssuer = credential(null);
        wrongIssuer.put("issuer", "did:web:someone-else.example");
        assertProblem(issue(basic("coordinator", "s3cret"), Map.of("credential", wrongIssuer)), 400, "ISSUER_MISMATCH");
        assertProblem(issue(basic("coordinator", "s3cret"), Map.of("credential", credential(null), "options", Map.of("mandatoryPointers", List.of("/issuer")))), 400, "NOT_SUPPORTED");
        assertProblem(issue(basic("other", "other-secret"), Map.of("credential", credential(null))), 403, "FORBIDDEN");
    }

    @Test
    void statusUpdatesValidateTheBodyAndAnswerNotFoundForUnknownCredentials() throws Exception {
        MvcResult malformed = mockMvc.perform(post("/vc-api/credentials/status").header("Authorization", basic("coordinator", "s3cret")).contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credentialId", "urn:uuid:x", "status", true)))).andReturn();
        assertProblem(malformed, 400, "MALFORMED_VALUE_ERROR");
        MvcResult unknown = mockMvc.perform(post("/vc-api/credentials/status").header("Authorization", basic("coordinator", "s3cret")).contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credentialId", "urn:uuid:unknown", "status", true,
                        "credentialStatus", Map.of("type", "BitstringStatusList", "statusPurpose", "revocation"))))).andReturn();
        assertProblem(unknown, 404, "NOT_FOUND");
        assertEquals(401, mockMvc.perform(post("/vc-api/credentials/status").contentType(MediaType.APPLICATION_JSON).content("{}")).andReturn().getResponse().getStatus());
    }

    private void assertProblem(MvcResult result, int status, String title) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(status, result.getResponse().getStatus(), body.toString());
        assertEquals(title, body.get("title").asText(), body.toString());
        assertTrue(body.get("type").asText().endsWith(title), body.toString());
        assertTrue(result.getResponse().getContentType().startsWith("application/problem+json"), result.getResponse().getContentType());
    }

    private MvcResult issue(String authorization, Map<String, Object> body) throws Exception {
        var request = post("/vc-api/credentials/issue").contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        return mockMvc.perform(request).andReturn();
    }

    private static String basic(String user, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> credential(String id) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", CONTEXT);
        if (id != null) {
            credential.put("id", id);
        }
        credential.put("type", TYPES);
        credential.put("issuer", ISSUER);
        credential.put("issuanceDate", "2026-09-19T00:00:00Z");
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Supplied Farmer"));
        return credential;
    }

    private byte[] ed25519PublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = objectMapper.readTree(mockMvc.perform(get("/.well-known/did.json")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                byte[] decoded = Multibase.decode(method.get("publicKeyMultibase").asText());
                return Arrays.copyOfRange(decoded, 2, decoded.length); // strip the 0xed01 multicodec prefix
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }
}
