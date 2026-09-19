package io.mosip.certify.as;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.api.spi.DataProviderPlugin;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Attestation-based client authentication at the PAR and token endpoints, required (HAIP). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.as.clients.wallet.redirect-uris[0]=https://wallet.example/cb",
        "certify.as.authorization.subject-mode=fixed",
        "certify.as.authorization.fixed-subject=2154189532",
        "certify.as.client-attestation.required=true",
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
class ClientAttestationTest {

    static final ECKey ATTESTER = generate("attester-1");
    static final ECKey INSTANCE = generate("instance-1");
    static final ECKey ROGUE = generate("rogue");
    static final String REDIRECT = "https://wallet.example/cb";
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @DynamicPropertySource
    static void attester(DynamicPropertyRegistry registry) {
        registry.add("certify.as.client-attestation.attesters.test.jwks", () -> new JWKSet(ATTESTER.toPublicJWK()).toString());
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired io.mosip.certify.core.spi.CredentialConfigurationService credentialConfigurationService;
    @Autowired io.mosip.certify.repository.CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.oauth.issuer}") String asIssuer;

    static final String CONFIG_ID = "ClientAttestationCredential";
    static final String SCOPE = "client_attestation_vc_ldp";

    @org.junit.jupiter.api.BeforeEach
    void setUp() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            io.mosip.certify.core.dto.CredentialConfigurationDTO dto = new io.mosip.certify.core.dto.CredentialConfigurationDTO();
            java.nio.file.Path path = java.nio.file.Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
            if (!java.nio.file.Files.exists(path)) {
                path = java.nio.file.Path.of("certify-service").resolve(path);
            }
            String template = java.nio.file.Files.readString(path, StandardCharsets.UTF_8).replace("GoldenCredential", CONFIG_ID);
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
            dto.setScope(SCOPE);
            io.mosip.certify.core.dto.MetaDataDisplayDTO display = new io.mosip.certify.core.dto.MetaDataDisplayDTO();
            display.setName(CONFIG_ID);
            display.setLocale("en");
            dto.setMetaDataDisplay(List.of(display));
            dto.setDisplayOrder(List.of("fullName"));
            dto.setClaims(Map.of("fullName", new io.mosip.certify.core.dto.ClaimsDTO()));
            credentialConfigurationService.addCredentialConfiguration(dto);
        }
    }

    @Test
    void attestedClientsPassUnattestedAndForgedOnesAreRefused() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals("attest_jwt_client_auth", metadata.get("token_endpoint_auth_methods_supported").get(0).asText(), metadata.toString());

        String attestation = attestation(ATTESTER, "wallet", INSTANCE);
        MvcResult par = mockMvc.perform(parRequest("wallet").header("OAuth-Client-Attestation", attestation).header("OAuth-Client-Attestation-PoP", pop(INSTANCE, "wallet", asIssuer, UUID.randomUUID().toString()))).andReturn();
        assertEquals(201, par.getResponse().getStatus(), par.getResponse().getContentAsString());
        String requestUri = objectMapper.readTree(par.getResponse().getContentAsString()).get("request_uri").asText();
        String location = mockMvc.perform(get("/oauth/authorize").param("client_id", "wallet").param("request_uri", requestUri)).andReturn().getResponse().getHeader("Location");
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");

        MvcResult token = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("OAuth-Client-Attestation", attestation).header("OAuth-Client-Attestation-PoP", pop(INSTANCE, "wallet", asIssuer, UUID.randomUUID().toString()))
                .param("grant_type", "authorization_code").param("code", code).param("code_verifier", VERIFIER).param("client_id", "wallet").param("redirect_uri", REDIRECT)).andReturn();
        assertEquals(200, token.getResponse().getStatus(), token.getResponse().getContentAsString());
        assertTrue(token.getResponse().getContentAsString().contains("access_token"));

        assertEquals("invalid_client", error(parRequest("wallet"), 401), "no attestation");
        assertEquals("invalid_client", error(parRequest("wallet").header("OAuth-Client-Attestation", attestation(ROGUE, "wallet", INSTANCE))
                .header("OAuth-Client-Attestation-PoP", pop(INSTANCE, "wallet", asIssuer, UUID.randomUUID().toString())), 401), "untrusted attester");
        assertEquals("invalid_client", error(parRequest("wallet").header("OAuth-Client-Attestation", attestation)
                .header("OAuth-Client-Attestation-PoP", pop(ROGUE, "wallet", asIssuer, UUID.randomUUID().toString())), 401), "PoP not by the attested key");
        assertEquals("invalid_client", error(parRequest("wallet").header("OAuth-Client-Attestation", attestation)
                .header("OAuth-Client-Attestation-PoP", pop(INSTANCE, "wallet", "https://other.example", UUID.randomUUID().toString())), 401), "wrong audience");
        assertEquals("invalid_client", error(parRequest("wallet").header("OAuth-Client-Attestation", attestation(ATTESTER, "someone-else", INSTANCE))
                .header("OAuth-Client-Attestation-PoP", pop(INSTANCE, "someone-else", asIssuer, UUID.randomUUID().toString())), 401), "sub is not the client_id");
        String jti = UUID.randomUUID().toString();
        String replayed = pop(INSTANCE, "wallet", asIssuer, jti);
        assertEquals(201, mockMvc.perform(parRequest("wallet").header("OAuth-Client-Attestation", attestation).header("OAuth-Client-Attestation-PoP", replayed)).andReturn().getResponse().getStatus());
        assertEquals("invalid_client", error(parRequest("wallet").header("OAuth-Client-Attestation", attestation).header("OAuth-Client-Attestation-PoP", replayed), 401), "replayed jti");
    }

    private MockHttpServletRequestBuilder parRequest(String clientId) throws Exception {
        return post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", clientId).param("response_type", "code").param("redirect_uri", REDIRECT).param("scope", SCOPE)
                .param("code_challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII))))
                .param("code_challenge_method", "S256");
    }

    private String error(MockHttpServletRequestBuilder request, int expectedStatus) throws Exception {
        MvcResult result = mockMvc.perform(request).andReturn();
        assertEquals(expectedStatus, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }

    static String attestation(ECKey attester, String clientId, ECKey instance) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("oauth-client-attestation+jwt")).keyID(attester.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer("https://attester.example").subject(clientId).issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                        .claim("cnf", Map.of("jwk", instance.toPublicJWK().toJSONObject())).build());
        jwt.sign(new ECDSASigner(attester));
        return jwt.serialize();
    }

    static String pop(ECKey instance, String clientId, String audience, String jti) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("oauth-client-attestation-pop+jwt")).build(),
                new JWTClaimsSet.Builder().issuer(clientId).audience(List.of(audience)).jwtID(jti).issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 300_000)).build());
        jwt.sign(new ECDSASigner(instance));
        return jwt.serialize();
    }

    private static ECKey generate(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
