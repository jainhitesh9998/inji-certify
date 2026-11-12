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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The M-10 regression on a real deployment shape: a file source is registered next to the data-provider plugin.
 *
 * <p>A configuration written before {@code dataSourceId} existed (row NULL, i.e. most deployed rows) must keep issuing
 * through the plugin instead of failing with "several data sources registered"; a configuration naming {@code mdl-demo}
 * must reach the file, and its denial for a subject the file does not hold must answer {@code 400
 * credential_request_denied} rather than issuing the plugin's data. The compatibility surface (through the core, so
 * {@code certify.protocol.oid4vci-v1.compat-core.enabled}) and draft 13 answer the same denial with the same message
 * and a 400, each in its own error code.</p>
 *
 * <p>The positive path issues from a second file source whose record is keyed by the local profile's TestBearer
 * {@code sub}, so the credential proves the record — nested list-of-objects and nested object included — reaches the
 * Velocity template engine unchanged.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        // the compatibility surface must go through the core, or it never consults a data source
        "certify.protocol.oid4vci-v1.compat-core.enabled=true",
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
    static final String SAMPLE_SOURCE = "sample-holders";
    static final String SAMPLE_ID = "FileSampleCredential";
    /** The message the pre-M-10 core produced for a subject the file does not hold; it is compared byte for byte. */
    static final String NO_DATA = "No data in data source 'mdl-demo' for 'sub'";
    static final String LDP_CONTEXT = "https://www.w3.org/2018/credentials/v1";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired ApplicationContext context;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    /** A second source whose record is keyed by the local TestBearer token's {@code sub}, so a positive issue is possible. */
    @DynamicPropertySource
    static void sampleHolders(DynamicPropertyRegistry registry) {
        registry.add("certify.datasource.file.sources." + SAMPLE_SOURCE + ".path", () -> fixture("issuable-holders.json").toString());
        registry.add("certify.datasource.file.sources." + SAMPLE_SOURCE + ".key-claim", () -> "sub");
    }

    private static Path fixture(String name) {
        Path path = Path.of("src/test/resources/datasource/file").resolve(name);
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return path.toAbsolutePath().normalize();
    }

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv ->
                new JSONObject(Map.of("fullName", "Plugin Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(PLUGIN_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(pluginConfiguration());
        }
        createIfAbsent(FILE_ID, credentialConfigurationMap(FILE_ID, "mdl-demo", goldenTemplate(FILE_ID)));
        createIfAbsent(SAMPLE_ID, credentialConfigurationMap(SAMPLE_ID, SAMPLE_SOURCE, nestedTemplate()));
    }

    @Test
    void bothSourcesAreRegisteredAndAPreExistingConfigurationStillUsesThePlugin() throws Exception {
        Set<String> ids = context.getBeansOfType(CredentialDataSource.class).values().stream()
                .map(CredentialDataSource::id).collect(Collectors.toSet());
        assertTrue(ids.containsAll(Set.of(DataProviderPluginDataSource.ID, "mdl-demo", SAMPLE_SOURCE)), ids.toString());

        // a row with data_source_id NULL, as every configuration deployed before M-10 has
        JsonNode body = issue(PLUGIN_ID, 200);
        assertEquals("Plugin Farmer", body.get("credentials").get(0).get("credential").get("credentialSubject").get("fullName").asText(),
                body.toString());
    }

    @Test
    void aConfigurationNamingTheFileSourceIssuesTheRecordWithItsNestedValues() throws Exception {
        JsonNode credential = issue(SAMPLE_ID, 200).get("credentials").get(0).get("credential");

        assertEquals("did:web:localhost:certify", credential.get("issuer").asText(), credential.toString());
        JsonNode subject = credential.get("credentialSubject");
        assertEquals("Asha File", subject.get("fullName").asText(), "the file's record, not the plugin's: " + credential);
        // a nested object and a nested list of objects reach the template engine unchanged (and deeply immutable)
        assertEquals("B", subject.get("category").asText(), credential.toString());
        assertEquals("Bengaluru", subject.get("locality").asText(), credential.toString());
        assertTrue(credential.get("proof") != null, "the credential is signed: " + credential);
    }

    @Test
    void aConfigurationNamingTheFileSourceDeniesAnUnknownSubject() throws Exception {
        JsonNode body = issue(FILE_ID, 400);

        assertEquals("credential_request_denied", body.get("error").asText(), body.toString());
        assertEquals(NO_DATA, body.get("error_description").asText(), body.toString());
    }

    @Test
    void theCompatibilitySurfaceAnswersTheSameDenialWithTheSameMessage() throws Exception {
        MvcResult result = mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", FILE_ID,
                        "proofs", Map.of("jwt", List.of(proofJwt(nonce("/nonce"), issuerIdentifier))))))).andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(400, result.getResponse().getStatus(), body.toString());
        assertEquals("credential_request_denied", body.get("error").asText(), body.toString());
        assertEquals(NO_DATA, body.get("error_description").asText(), body.toString());
    }

    @Test
    void draft13MapsTheSameDenialToInvalidCredentialRequest() throws Exception {
        MvcResult result = mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "format", "ldp_vc",
                        "credential_definition", Map.of("@context", List.of(LDP_CONTEXT),
                                "type", List.of("VerifiableCredential", FILE_ID)),
                        "proof", Map.of("proof_type", "jwt", "jwt", proofJwt(nonce("/nonce"), issuerIdentifier)))))).andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(400, result.getResponse().getStatus(), body.toString());
        assertEquals("invalid_credential_request", body.get("error").asText(), "draft 13 has no credential_request_denied: " + body);
        assertEquals(NO_DATA, body.get("error_description").asText(), body.toString());
    }

    private JsonNode issue(String configurationId, int expectedStatus) throws Exception {
        String proof = proofJwt(nonce("/oid4vci/nonce"), issuerIdentifier + "/oid4vci");
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", configurationId,
                        "proofs", Map.of("jwt", List.of(proof)))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(expectedStatus, result.getResponse().getStatus(), body.toString());
        return body;
    }

    private String nonce(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(post(path)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private String proofJwt(String nonce, String audience) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(audience)
                .issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private void createIfAbsent(String id, Map<String, Object> configuration) throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(id).isPresent()) {
            return;
        }
        MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(configuration))).andReturn();
        assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
    }

    /** The v1 body: no dataSourceId column value, exactly like a configuration the service created before M-10. */
    private static CredentialConfigurationDTO pluginConfiguration() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(PLUGIN_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(goldenTemplate(PLUGIN_ID).getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of(LDP_CONTEXT));
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

    /** The v2 body of a file-backed configuration: the row names the source, so the core asks the file for the record. */
    private Map<String, Object> credentialConfigurationMap(String id, String dataSourceId, String template) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "ldp_vc");
        body.put("formatConfig", Map.of("context", List.of(LDP_CONTEXT),
                "types", List.of("VerifiableCredential", id),
                "claims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
        body.put("signing", Map.of("provider", "keymanager", "alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN",
                "alg", "EdDSA", "cryptosuite", "Ed25519Signature2020", "didUrl", "did:web:localhost:certify"));
        body.put("template", Map.of("content", template));
        body.put("dataSourceId", dataSourceId);
        body.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en")), "order", List.of("fullName")));
        // the dry run renders this through the same template engine; the nested values are the ones the file holds
        body.put("sampleClaims", Map.of("fullName", "Asha Sample",
                "resident_address", Map.of("locality", "Bengaluru"),
                "driving_privileges", List.of(Map.of("vehicle_category_code", "B"), Map.of("vehicle_category_code", "A1"))));
        return body;
    }

    private static String goldenTemplate(String type) throws Exception {
        return template().replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                        "\"" + type + "\": \"https://example.org/golden#" + type + "\"")
                .replace("\"GoldenCredential\"]", "\"" + type + "\"]");
    }

    /**
     * A template that reads a nested list of objects and a nested object, so the credential proves both reached the
     * engine as values rather than as text.
     */
    private static String nestedTemplate() {
        return """
                {
                    "@context": [
                        "%s",
                        "https://w3id.org/security/suites/ed25519-2020/v1",
                        {
                            "FileSampleCredential": "https://example.org/file#FileSampleCredential",
                            "fullName": "https://schema.org/name",
                            "category": "https://example.org/file#category",
                            "locality": "https://schema.org/addressLocality"
                        }
                    ],
                    "issuer": "${_issuer}",
                    "type": ["VerifiableCredential", "FileSampleCredential"],
                    "issuanceDate": "${validFrom}",
                    "expirationDate": "${validUntil}",
                    "credentialSubject": {
                        "id": "${_holderId}",
                        "fullName": "${fullName}",
                        "category": "${driving_privileges.get(0).vehicle_category_code}",
                        "locality": "${resident_address.locality}"
                    }
                }
                """.formatted(LDP_CONTEXT);
    }

    private static String template() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
