package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
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
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The Phase 2 exit criterion "mixed-strategy deployment" (docs/design/11-roadmap.md): one deployment in DataProvider
 * plugin mode serves a templated configuration and, next to it, a configuration whose row names the EXTERNAL strategy
 * and the legacy VCIssuancePlugin as its data source; both issue through the same core and the same endpoint.
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
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class MixedStrategyIssuanceTest {

    static final String TEMPLATED_ID = "MixedTemplatedCredential";
    static final String EXTERNAL_ID = "MixedExternalCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @MockBean VCIssuancePlugin vcIssuancePlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Templated Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(), anyString(), any())).thenAnswer(inv -> {
            VCResult<JsonLDObject> result = new VCResult<>();
            result.setFormat("ldp_vc");
            result.setCredential(JsonLDObject.fromJson(objectMapper.writeValueAsString(Map.of(
                    "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                    "type", List.of("VerifiableCredential", EXTERNAL_ID),
                    "issuer", "did:web:external.example",
                    "issuanceDate", "2026-01-01T00:00:00Z",
                    "credentialSubject", Map.of("id", inv.getArgument(1, String.class), "source", "external plugin"),
                    "proof", Map.of("type", "Ed25519Signature2020", "verificationMethod", "did:web:external.example#key-1", "proofPurpose", "assertionMethod", "created", "2026-01-01T00:00:00Z", "proofValue", "z3xternal")))));
            return result;
        });
        if (credentialConfigRepository.findByCredentialConfigKeyId(TEMPLATED_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(templated());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(EXTERNAL_ID).isEmpty()) {
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(external()))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }
    }

    @Test
    void oneDeploymentServesTemplatedAndExternalConfigurationsSideBySide() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertTrue(metadata.get("credential_configurations_supported").has(TEMPLATED_ID));
        assertTrue(metadata.get("credential_configurations_supported").has(EXTERNAL_ID));

        JsonNode templated = objectMapper.readTree(issue(TEMPLATED_ID).getResponse().getContentAsString());
        JsonNode templatedVc = templated.get("credentials").get(0).get("credential");
        assertEquals("Templated Farmer", templatedVc.get("credentialSubject").get("fullName").asText(), templated.toString());
        assertEquals("did:web:localhost:certify", templatedVc.get("issuer").asText());
        assertTrue(templatedVc.get("proof").get("verificationMethod").asText().startsWith("did:web:localhost:certify#"));

        JsonNode external = objectMapper.readTree(issue(EXTERNAL_ID).getResponse().getContentAsString());
        JsonNode externalVc = external.get("credentials").get(0).get("credential");
        assertEquals("external plugin", externalVc.get("credentialSubject").get("source").asText(), external.toString());
        assertEquals("did:web:external.example", externalVc.get("issuer").asText(), "the plugin's credential is returned as the plugin made it");
        assertTrue(externalVc.get("credentialSubject").get("id").asText().startsWith("did:jwk:"), "the holder from the proof reaches the plugin");
        assertTrue(external.has("notification_id"));

        JsonNode stored = objectMapper.readTree(mockMvc.perform(get("/v2/credential-configurations/" + EXTERNAL_ID)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals("EXTERNAL", stored.get("issuanceStrategy").asText());
        assertEquals("vci-plugin", stored.get("dataSourceId").asText());
    }

    private MvcResult issue(String configurationId) throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", configurationId, "proofs", Map.of("jwt", List.of(jwt.serialize())))))).andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return result;
    }

    private static Map<String, Object> external() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", EXTERNAL_ID);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "ldp_vc");
        body.put("formatConfig", Map.of("context", List.of("https://www.w3.org/2018/credentials/v1"), "types", List.of("VerifiableCredential", EXTERNAL_ID),
                "claims", Map.of("source", Map.of("display", List.of(Map.of("name", "Source", "locale", "en"))))));
        body.put("signing", Map.of("alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg", "EdDSA", "cryptosuite", "Ed25519Signature2020", "didUrl", "did:web:localhost:certify"));
        body.put("issuanceStrategy", "EXTERNAL");
        body.put("dataSourceId", "vci-plugin");
        body.put("display", Map.of("display", List.of(Map.of("name", EXTERNAL_ID, "locale", "en")), "order", List.of("source")));
        return body;
    }

    private static CredentialConfigurationDTO templated() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + TEMPLATED_ID + "\": \"https://example.org/golden#" + TEMPLATED_ID + "\"").replace("\"GoldenCredential\"]", "\"" + TEMPLATED_ID + "\"]");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(TEMPLATED_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", TEMPLATED_ID));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(TEMPLATED_ID);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        ClaimsDTO claim = new ClaimsDTO();
        dto.setClaims(Map.of("fullName", claim));
        return dto;
    }
}
