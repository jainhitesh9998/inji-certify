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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Single-use c_nonces and batch issuance on the new surface (OpenID4VCI 1.0 nonce endpoint, batch_credential_issuance). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.protocol.oid4vci-v1.batch.size=2",
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
class Oid4vciNonceBatchTest {

    static final String CONFIG_ID = "NonceBatchCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Batch Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config());
        }
    }

    @Test
    void aNonceAuthorisesOneCredentialRequest() throws Exception {
        String nonce = nonce();
        MvcResult first = issue(nonce, 1);
        assertEquals(200, first.getResponse().getStatus(), first.getResponse().getContentAsString());
        MvcResult replay = issue(nonce, 1);
        assertEquals(400, replay.getResponse().getStatus());
        assertEquals("invalid_nonce", error(replay));
    }

    @Test
    void aBatchIssuesOneCredentialPerProofAndConsumesTheNonceOnce() throws Exception {
        String nonce = nonce();
        MvcResult batch = issue(nonce, 2);
        JsonNode body = objectMapper.readTree(batch.getResponse().getContentAsString());
        assertEquals(200, batch.getResponse().getStatus(), body.toString());
        assertEquals(2, body.get("credentials").size());
        Set<String> holders = new HashSet<>();
        for (JsonNode entry : body.get("credentials")) {
            holders.add(entry.get("credential").get("credentialSubject").get("id").asText());
            assertEquals("Batch Farmer", entry.get("credential").get("credentialSubject").get("fullName").asText());
        }
        assertEquals(2, holders.size());
        assertTrue(body.has("notification_id"));
        assertEquals("invalid_nonce", error(issue(nonce, 1)));
    }

    @Test
    void moreProofsThanTheBatchSizeAreRefusedAndTheNonceSurvives() throws Exception {
        String nonce = nonce();
        MvcResult tooMany = issue(nonce, 3);
        assertEquals(400, tooMany.getResponse().getStatus());
        assertEquals("invalid_credential_request", error(tooMany));
        assertEquals(200, issue(nonce, 1).getResponse().getStatus());
    }

    @Test
    void theIssuerMetadataAdvertisesTheBatchSize() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals(2, metadata.get("batch_credential_issuance").get("batch_size").asInt());
        assertNotEquals(null, metadata.get("nonce_endpoint"));
    }

    private String error(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private MvcResult issue(String nonce, int proofs) throws Exception {
        List<String> jwts = new ArrayList<>();
        for (int i = 0; i < proofs; i++) {
            ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
            SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
            jwt.sign(new ECDSASigner(holder));
            jwts.add(jwt.serialize());
        }
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "proofs", Map.of("jwt", jwts))))).andReturn();
    }

    private static CredentialConfigurationDTO config() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + CONFIG_ID + "\": \"https://example.org/golden#" + CONFIG_ID + "\"").replace("\"GoldenCredential\"]", "\"" + CONFIG_ID + "\"]");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(CONFIG_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", CONFIG_ID));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(CONFIG_ID);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        ClaimsDTO claim = new ClaimsDTO();
        dto.setClaims(Map.of("fullName", claim));
        return dto;
    }
}
