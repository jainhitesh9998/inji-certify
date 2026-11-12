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
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.spi.CredentialDataSource;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
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
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M-10 regression on a real deployment shape: a file source is registered next to the data-provider plugin, and a
 * configuration written before {@code dataSourceId} existed (row NULL, i.e. most deployed rows) must keep issuing
 * through the plugin instead of failing with "several data sources registered"; a configuration naming {@code mdl-demo}
 * must reach the file. TestBearer's {@code sub} is not in the demo file, so the second path proves the file was
 * consulted by answering {@code 400 credential_request_denied} rather than issuing the plugin's data.
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
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}",
        "certify.datasource.file.sources.mdl-demo.path=../docker-compose/docker-compose-injistack/config/mdl/holders.json",
        "certify.datasource.file.sources.mdl-demo.key-claim=sub",
        "certify.datasource.file.sources.mdl-demo.binary-fields=portrait"
})
class FileDataSourceIssuanceTest {

    static final String PLUGIN_ID = "FilePluginCredential";
    static final String FILE_ID = "FileMdlCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired ApplicationContext context;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv ->
                new JSONObject(Map.of("fullName", "Plugin Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(PLUGIN_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(pluginConfiguration());
        }
    }

    @Test
    void bothSourcesAreRegisteredAndAPreExistingConfigurationStillUsesThePlugin() throws Exception {
        Set<String> ids = context.getBeansOfType(CredentialDataSource.class).values().stream()
                .map(CredentialDataSource::id).collect(Collectors.toSet());
        assertTrue(ids.containsAll(Set.of(DataProviderPluginDataSource.ID, "mdl-demo")), ids.toString());

        // a row with data_source_id NULL, as every configuration deployed before M-10 has
        JsonNode body = issue(PLUGIN_ID, 200);
        assertEquals("Plugin Farmer", body.get("credentials").get(0).get("credential").get("credentialSubject").get("fullName").asText(),
                body.toString());
    }

    @Test
    void aConfigurationNamingTheFileSourceReadsTheFileAndDeniesAnUnknownSubject() throws Exception {
        if (mockMvc.perform(get("/v2/credential-configurations/" + FILE_ID)).andReturn().getResponse().getStatus() == 404) {
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(fileConfiguration()))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }

        JsonNode body = issue(FILE_ID, 400);
        assertEquals("credential_request_denied", body.get("error").asText(), body.toString());
        assertTrue(body.get("error_description").asText().contains("mdl-demo"), body.toString());
    }

    private JsonNode issue(String configurationId, int expectedStatus) throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci")
                .issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", configurationId,
                        "proofs", Map.of("jwt", List.of(jwt.serialize())))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(expectedStatus, result.getResponse().getStatus(), body.toString());
        return body;
    }

    /** The v1 body: no dataSourceId column value, exactly like a configuration the service created before M-10. */
    private static CredentialConfigurationDTO pluginConfiguration() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(PLUGIN_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template(PLUGIN_ID).getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", PLUGIN_ID));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(PLUGIN_ID);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        dto.setClaims(Map.of("fullName", new ClaimsDTO()));
        return dto;
    }

    private Map<String, Object> fileConfiguration() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", FILE_ID);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "ldp_vc");
        body.put("formatConfig", Map.of("context", List.of("https://www.w3.org/2018/credentials/v1"),
                "types", List.of("VerifiableCredential", FILE_ID),
                "claims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
        body.put("signing", Map.of("provider", "keymanager", "alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN",
                "alg", "EdDSA", "cryptosuite", "Ed25519Signature2020", "didUrl", "did:web:localhost:certify"));
        body.put("template", Map.of("content", template(FILE_ID)));
        body.put("dataSourceId", "mdl-demo");
        body.put("display", Map.of("display", List.of(Map.of("name", FILE_ID, "locale", "en")), "order", List.of("fullName")));
        body.put("sampleClaims", Map.of("fullName", "Asha", "dateOfBirth", "1990-01-01", "city", "Pune"));
        return body;
    }

    private static String template(String type) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8)
                .replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                        "\"" + type + "\": \"https://example.org/golden#" + type + "\"")
                .replace("\"GoldenCredential\"]", "\"" + type + "\"]");
    }
}
