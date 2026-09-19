package io.mosip.certify.as;

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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** A DPoP proof at the token endpoint binds the issued token to the wallet key (RFC 9449 section 5, HAIP). */
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
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class DpopBoundTokenTest {

    static final String CONFIG_ID = "DpopTokenCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.domain.url}") String domainUrl;

    @BeforeEach
    void setUp() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config());
        }
    }

    @Test
    void aDpopProofAtTheTokenEndpointBindsTheToken() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertTrue(metadata.get("dpop_signing_alg_values_supported").toString().contains("ES256"), metadata.toString());

        ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
        String htu = domainUrl + "/oauth/token"; // the validator compares against the public domain plus the request URI
        MvcResult bound = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("DPoP", proof(walletKey, "POST", htu))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code").param("pre-authorized_code", preAuthorizedCode()).param("tx_code", "1234")).andReturn();
        JsonNode body = objectMapper.readTree(bound.getResponse().getContentAsString());
        assertEquals(200, bound.getResponse().getStatus(), body.toString());
        assertEquals("DPoP", body.get("token_type").asText());
        SignedJWT token = SignedJWT.parse(body.get("access_token").asText());
        Map<String, Object> cnf = token.getJWTClaimsSet().getJSONObjectClaim("cnf");
        assertEquals(walletKey.toPublicJWK().computeThumbprint().toString(), cnf.get("jkt"), "cnf.jkt is the proof key's thumbprint");

        MvcResult bearer = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code").param("pre-authorized_code", preAuthorizedCode()).param("tx_code", "1234")).andReturn();
        JsonNode bearerBody = objectMapper.readTree(bearer.getResponse().getContentAsString());
        assertEquals("Bearer", bearerBody.get("token_type").asText(), bearerBody.toString());
        assertFalse(SignedJWT.parse(bearerBody.get("access_token").asText()).getJWTClaimsSet().getClaims().containsKey("cnf"));

        MvcResult wrongHtu = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("DPoP", proof(walletKey, "POST", "https://other.example/oauth/token"))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code").param("pre-authorized_code", preAuthorizedCode()).param("tx_code", "1234")).andReturn();
        String refused = wrongHtu.getResponse().getContentAsString();
        assertFalse(refused.contains("access_token"), refused);
        assertTrue(refused.contains("invalid_dpop_proof"), refused);
    }

    private String preAuthorizedCode() throws Exception {
        MvcResult offer = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "subject", "2154189532", "expires_in", 600, "tx_code", "1234")))).andReturn();
        String uri = objectMapper.readTree(offer.getResponse().getContentAsString()).get("credential_offer_uri").asText();
        String offerUrl = URLDecoder.decode(uri.substring(uri.indexOf("credential_offer_uri=") + "credential_offer_uri=".length()), StandardCharsets.UTF_8);
        String path = offerUrl.substring(offerUrl.indexOf("/credential-offer-data/"));
        JsonNode doc = objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return doc.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code").get("pre-authorized_code").asText();
    }

    static String proof(ECKey key, String htm, String htu) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString()).claim("htm", htm).claim("htu", htu).issueTime(new Date()).build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
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
        dto.setScope("dpop_token_vc_ldp");
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
