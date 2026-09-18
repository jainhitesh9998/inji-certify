package io.mosip.certify.tenancy;

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
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.entity.CredentialConfig;
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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** {@code certify.tenancy.resolver=path}: a tenant lives under {@code /t/{tenant}/oid4vci/...} with its own issuer identifier. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.tenancy.enabled=true",
        "certify.tenancy.resolver=path",
        "certify.tenancy.tenants.beta.issuer-did=did:web:beta.example",
        "certify.tenancy.tenants.beta.display[0].name=Beta Issuer",
        "certify.tenancy.tenants.beta.display[0].locale=en",
        "certify.tenancy.tenants.beta.authorization-servers[0]=http://beta.example/as",
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class PathTenancyIssuanceTest {

    static final String DEFAULT_ID = "PathDefaultCredential";
    static final String ACME_ID = "PathAcmeCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired CredentialRegistry credentialRegistry;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Path Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByTenantIdAndCredentialConfigKeyId("default", DEFAULT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(DEFAULT_ID));
        }
        if (credentialConfigRepository.findByTenantIdAndCredentialConfigKeyId("beta", ACME_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(ACME_ID));
            CredentialConfig row = credentialConfigRepository.findByCredentialConfigKeyId(ACME_ID).orElseThrow();
            row.setTenantId("beta");
            credentialConfigRepository.save(row);
            credentialRegistry.evict();
        }
    }

    @Test
    void theTenantLivesUnderItsPathWithItsOwnIdentifier() throws Exception {
        String acmeIdentifier = issuerIdentifier + "/t/beta/oid4vci";
        JsonNode acme = objectMapper.readTree(mockMvc.perform(get("/t/beta/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals(acmeIdentifier, acme.get("credential_issuer").asText());
        assertEquals(acmeIdentifier + "/credential", acme.get("credential_endpoint").asText());
        assertEquals(acmeIdentifier + "/nonce", acme.get("nonce_endpoint").asText());
        assertEquals(acmeIdentifier + "/notification", acme.get("notification_endpoint").asText());
        assertTrue(acme.get("credential_configurations_supported").has(ACME_ID));
        assertFalse(acme.get("credential_configurations_supported").has(DEFAULT_ID));
        assertEquals("Beta Issuer", acme.get("display").get(0).get("name").asText(), "the tenant's own issuer display");
        assertEquals("http://beta.example/as", acme.get("authorization_servers").get(0).asText(), "the tenant's own authorization server");

        String nonce = objectMapper.readTree(mockMvc.perform(post("/t/beta/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        MvcResult issued = mockMvc.perform(post("/t/beta/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", ACME_ID, "proofs", Map.of("jwt", List.of(proof(acmeIdentifier, nonce))))))).andReturn();
        JsonNode body = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("did:web:beta.example", credential.get("issuer").asText());
        assertTrue(credential.get("proof").get("verificationMethod").asText().startsWith("did:web:beta.example#"));
        assertEquals("Path Farmer", credential.get("credentialSubject").get("fullName").asText());
        MvcResult accepted = mockMvc.perform(post("/t/beta/oid4vci/notification").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("notification_id", body.get("notification_id").asText(), "event", "credential_accepted")))).andReturn();
        assertEquals(204, accepted.getResponse().getStatus(), accepted.getResponse().getContentAsString());

        // the default surface is untouched and does not see acme's configuration; an unknown path tenant is the default
        JsonNode dflt = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals(issuerIdentifier + "/oid4vci", dflt.get("credential_issuer").asText());
        assertFalse(dflt.has("display") && "Beta Issuer".equals(dflt.get("display").get(0).get("name").asText()), "the default document keeps the deployment's display");
        assertTrue(dflt.get("credential_configurations_supported").has(DEFAULT_ID));
        assertFalse(dflt.get("credential_configurations_supported").has(ACME_ID));
        JsonNode nobody = objectMapper.readTree(mockMvc.perform(get("/t/nobody/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals(issuerIdentifier + "/oid4vci", nobody.get("credential_issuer").asText(), "an unconfigured path tenant is the default tenant");
        String defaultNonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        MvcResult invisible = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", ACME_ID, "proofs", Map.of("jwt", List.of(proof(issuerIdentifier + "/oid4vci", defaultNonce))))))).andReturn();
        assertEquals(400, invisible.getResponse().getStatus(), "acme's configuration is not reachable from the default surface");
    }

    private static String proof(String audience, String nonce) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private static CredentialConfigurationDTO config(String id) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + id + "\": \"https://example.org/golden#" + id + "\"").replace("\"GoldenCredential\"]", "\"" + id + "\"]");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", id));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(id);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        ClaimsDTO claim = new ClaimsDTO();
        dto.setClaims(Map.of("fullName", claim));
        return dto;
    }
}
