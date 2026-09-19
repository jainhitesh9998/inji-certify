package io.mosip.certify.as;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The authorization code flow of Certify's own AS: PAR, authorization with the fixed subject, redirect with a code, token exchange with PKCE. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.as.clients.wallet.redirect-uris[0]=https://wallet.example/cb",
        "certify.as.authorization.subject-mode=fixed",
        "certify.as.authorization.fixed-subject=2154189532",
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
class AuthorizationCodeFlowTest {

    static final String CONFIG_ID = "AuthzCodeCredential";
    static final String SCOPE = "authz_code_vc_ldp";
    static final String REDIRECT = "https://wallet.example/cb";
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void setUp() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config());
        }
    }

    @Test
    void parAuthorizeRedirectAndTokenWithPkce() throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertTrue(metadata.get("authorization_endpoint").asText().endsWith("/oauth/authorize"), metadata.toString());
        assertTrue(metadata.get("pushed_authorization_request_endpoint").asText().endsWith("/oauth/par"));
        assertTrue(metadata.get("require_pushed_authorization_requests").asBoolean());
        assertTrue(metadata.get("code_challenge_methods_supported").toString().contains("S256"));

        MvcResult par = mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "wallet").param("response_type", "code").param("redirect_uri", REDIRECT)
                .param("scope", SCOPE).param("state", "xyz").param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256")).andReturn();
        JsonNode parBody = objectMapper.readTree(par.getResponse().getContentAsString());
        assertEquals(201, par.getResponse().getStatus(), parBody.toString());
        String requestUri = parBody.get("request_uri").asText();
        assertTrue(requestUri.startsWith("urn:ietf:params:oauth:request_uri:"));
        assertTrue(parBody.get("expires_in").asLong() > 0);

        MvcResult authorize = mockMvc.perform(get("/oauth/authorize").param("client_id", "wallet").param("request_uri", requestUri)).andReturn();
        assertEquals(302, authorize.getResponse().getStatus(), authorize.getResponse().getContentAsString());
        String location = authorize.getResponse().getHeader("Location");
        assertTrue(location.startsWith(REDIRECT + "?"), location);
        Map<String, String> query = query(location);
        assertEquals("xyz", query.get("state"));
        assertNotNull(query.get("code"));
        assertNotNull(query.get("iss"), "RFC 9207 issuer identifier in the response");
        assertNull(query.get("error"));

        // a request_uri is single use
        assertEquals(400, mockMvc.perform(get("/oauth/authorize").param("client_id", "wallet").param("request_uri", requestUri)).andReturn().getResponse().getStatus());

        MvcResult token = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("code", query.get("code")).param("code_verifier", VERIFIER)
                .param("client_id", "wallet").param("redirect_uri", REDIRECT)).andReturn();
        JsonNode tokenBody = objectMapper.readTree(token.getResponse().getContentAsString());
        assertEquals(200, token.getResponse().getStatus(), tokenBody.toString());
        assertEquals("Bearer", tokenBody.get("token_type").asText());
        assertEquals(SCOPE, tokenBody.get("scope").asText());
        SignedJWT jwt = SignedJWT.parse(tokenBody.get("access_token").asText());
        assertEquals("2154189532", jwt.getJWTClaimsSet().getSubject(), "the fixed subject is the token subject");
        assertEquals(SCOPE, jwt.getJWTClaimsSet().getStringClaim("scope"));

        // the code is single use
        MvcResult replay = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("code", query.get("code")).param("code_verifier", VERIFIER)
                .param("client_id", "wallet").param("redirect_uri", REDIRECT)).andReturn();
        assertTrue(!replay.getResponse().getContentAsString().contains("access_token"), replay.getResponse().getContentAsString());
    }

    @Test
    void authorizationDetailsSelectTheConfigurationAndErrorsAreOauthErrors() throws Exception {
        String details = objectMapper.writeValueAsString(List.of(Map.of("type", "openid_credential", "credential_configuration_id", CONFIG_ID)));
        MvcResult par = mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "wallet").param("response_type", "code").param("redirect_uri", REDIRECT)
                .param("authorization_details", details).param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256")).andReturn();
        assertEquals(201, par.getResponse().getStatus(), par.getResponse().getContentAsString());
        String requestUri = objectMapper.readTree(par.getResponse().getContentAsString()).get("request_uri").asText();
        String location = mockMvc.perform(get("/oauth/authorize").param("client_id", "wallet").param("request_uri", requestUri)).andReturn().getResponse().getHeader("Location");
        assertNotNull(query(location).get("code"), location);

        assertEquals("invalid_client", error(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "nobody").param("response_type", "code").param("redirect_uri", REDIRECT).param("scope", SCOPE)
                .param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256"), 401));
        assertEquals("invalid_request", error(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "wallet").param("response_type", "code").param("redirect_uri", "https://evil.example/cb").param("scope", SCOPE)
                .param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256"), 400));
        assertEquals("invalid_request", error(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "wallet").param("response_type", "code").param("redirect_uri", REDIRECT).param("scope", SCOPE), 400));
        assertEquals("invalid_scope", error(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "wallet").param("response_type", "code").param("redirect_uri", REDIRECT).param("scope", "no_such_scope")
                .param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256"), 400));
        assertEquals("invalid_request", error(get("/oauth/authorize").param("client_id", "wallet").param("request_uri", "urn:ietf:params:oauth:request_uri:nope"), 400));
        assertEquals("invalid_request", error(get("/oauth/authorize").param("client_id", "wallet"), 400));
    }

    private String error(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, int expectedStatus) throws Exception {
        MvcResult result = mockMvc.perform(request).andReturn();
        assertEquals(expectedStatus, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }

    private static Map<String, String> query(String url) {
        Map<String, String> out = new java.util.HashMap<>();
        UriComponentsBuilder.fromUriString(url).build().getQueryParams().forEach((k, v) -> out.put(k, java.net.URLDecoder.decode(v.get(0), StandardCharsets.UTF_8)));
        return out;
    }

    private static String challenge(String verifier) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
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
        dto.setScope(SCOPE);
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
