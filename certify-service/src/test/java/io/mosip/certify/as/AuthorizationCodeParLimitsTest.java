package io.mosip.certify.as;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.DataProviderPlugin;
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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * {@code POST /oauth/par} is unauthenticated and stores one entry per request, so it must not be able to hurt the offers
 * an issuer has minted, and it must not accept unbounded input (F-21 review round 1).
 *
 * <p>Both caches are two entries large here, so a handful of pushed requests is already past the capacity of the one
 * they live in: the pre-authorized code cached before the flood stays redeemable, which is the point of the separate
 * {@code parRequestCache}. With one shared cache the flood evicts the code and the token request below fails (the
 * negative control recorded with this work package).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.as.clients.demo-wallet.redirect-uris[0]=" + AuthorizationCodeParLimitsTest.REDIRECT,
        "mosip.certify.cache.size={'preAuthCodeCache': 2, 'parRequestCache': 2}",
        "mosip.certify.cache.expire-in-seconds={'preAuthCodeCache': 3600, 'parRequestCache': 300}",
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
class AuthorizationCodeParLimitsTest {

    static final String CONFIG_ID = "ParLimitsCredential";
    static final String SCOPE = "par_limits_vc";
    static final String REDIRECT = "https://wallet.example/cb";
    /** RFC 7636 appendix B. */
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /** How many pushed requests the flood sends: past the two-entry capacity of both caches. */
    static final int FLOOD = 6;

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void setUp() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(CONFIG_ID, SCOPE));
        }
    }

    @Test
    void aParFloodDoesNotEvictAPreAuthorizedCode() throws Exception {
        String code = offer();
        for (int i = 0; i < FLOOD; i++) {
            assertEquals(201, push(CONFIG_ID, SCOPE, Map.of("state", "state-" + i)).getResponse().getStatus(),
                    "a pushed authorization request is accepted");
        }
        MvcResult token = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", code)).andReturn();
        JsonNode body = objectMapper.readTree(token.getResponse().getContentAsString());
        assertEquals(200, token.getResponse().getStatus(), "the code minted before the flood is still redeemable: " + body);
        assertNotNull(body.get("access_token"), body.toString());
    }

    /** The caps of {@code state}, {@code issuer_state} and {@code authorization_details}: RFC 9126 {@code invalid_request}. */
    @Test
    void unboundedFieldsAreRefused() throws Exception {
        assertEquals(400, push(CONFIG_ID, SCOPE, Map.of("state", "s".repeat(513))).getResponse().getStatus());
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("state", "s".repeat(513))));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("issuer_state", "i".repeat(513))));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", details(5000, 1))));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", details(60, 21))));
        // the boundary itself is accepted, so the cap is a bound and not a guess
        assertEquals(201, push(CONFIG_ID, SCOPE, Map.of("state", "s".repeat(512))).getResponse().getStatus());
    }

    /** Structure is validated even when {@code scope} decides the effective scope: the value is stored and echoed. */
    @Test
    void authorizationDetailsAreValidatedEvenWhenAScopeIsGiven() throws Exception {
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", "[{\"type\": \"openid_credential\"}]")));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", "[{\"type\": \"other\", \"credential_configuration_id\": \""
                + CONFIG_ID + "\"}]")));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", "{\"type\": \"openid_credential\"}")));
        assertInvalidRequest(push(CONFIG_ID, SCOPE, Map.of("authorization_details", "not json")));
        // a well-formed value next to a valid scope is accepted
        assertEquals(201, push(CONFIG_ID, SCOPE, Map.of("authorization_details",
                "[{\"type\": \"openid_credential\", \"credential_configuration_id\": \"" + CONFIG_ID + "\"}]")).getResponse().getStatus());
    }

    /**
     * RFC 9396 section 2 and OpenID4VCI 1.0 section 5.1.1: an array of objects, {@code type} the string
     * {@code openid_credential}, {@code credential_configuration_id} a string. {@code null} and {@code [null]} were a
     * NullPointerException (500) and an object or number id was coerced through {@code toString()} (F-21 review round
     * 2); each is now {@code invalid_request}, also next to a valid scope, which alone would have decided the request.
     */
    @Test
    void malformedAuthorizationDetailsAreInvalidRequestsNextToAValidScope() throws Exception {
        String entry = "{\"type\": \"openid_credential\", \"credential_configuration_id\": \"" + CONFIG_ID + "\"}";
        for (String details : List.of("null", "[null]", "[1]", "[\"openid_credential\"]", "[[]]", "true", "\"x\"",
                "[" + entry + ", null]",
                "[{\"type\": \"openid_credential\", \"credential_configuration_id\": {\"id\": \"" + CONFIG_ID + "\"}}]",
                "[{\"type\": \"openid_credential\", \"credential_configuration_id\": 7}]",
                "[{\"type\": \"openid_credential\", \"credential_configuration_id\": [\"" + CONFIG_ID + "\"]}]",
                "[{\"type\": [\"openid_credential\"], \"credential_configuration_id\": \"" + CONFIG_ID + "\"}]",
                "[" + entry + "] trailing", "[" + entry + "]]")) {
            MvcResult result = push(CONFIG_ID, SCOPE, Map.of("authorization_details", details));
            assertInvalidRequest(result);
            assertTrue(result.getResponse().getContentAsString().contains("authorization_details"), details + ": "
                    + result.getResponse().getContentAsString());
        }
        // and alone, where the details decide the scope: the same answer, never a 500
        for (String details : List.of("null", "[null]", "[{\"type\": \"openid_credential\", \"credential_configuration_id\": 7}]")) {
            assertInvalidRequest(mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("client_id", "demo-wallet").param("response_type", "code").param("redirect_uri", REDIRECT)
                    .param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256")
                    .param("authorization_details", details)).andReturn());
        }
        // the well-formed value is still accepted on its own, with whitespace around it
        assertEquals(201, push(CONFIG_ID, null, Map.of()).getResponse().getStatus());
        assertEquals(201, push(CONFIG_ID, SCOPE, Map.of("authorization_details", "  [" + entry + "]\n")).getResponse().getStatus());
    }

    /**
     * The scopes a pushed request may name come from the cached issuer-metadata view, not from a query per request; a
     * configuration written after the context started is visible (the registry drops the view on every write).
     */
    @Test
    void aScopeOfAConfigurationWrittenAfterStartupIsAcceptedWithoutAQueryPerRequest() throws Exception {
        MvcResult unknown = push("LateCredential", "late_scope_vc", Map.of());
        assertEquals(400, unknown.getResponse().getStatus(), unknown.getResponse().getContentAsString());
        assertEquals("invalid_scope", objectMapper.readTree(unknown.getResponse().getContentAsString()).get("error").asText(),
                "a scope no active configuration declares is refused (RFC 6749 section 4.1.2.1)");
        credentialConfigurationService.addCredentialConfiguration(config("LateCredential", "late_scope_vc"));
        assertEquals(201, push("LateCredential", "late_scope_vc", Map.of()).getResponse().getStatus(),
                "the registry drops its cached view on the write, so the pushed request sees the new configuration");
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    /** A pushed authorization request for one entry; {@code scope} null asks by {@code authorization_details} instead. */
    private MvcResult push(String configuration, String scope, Map<String, String> extra) throws Exception {
        var request = post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "demo-wallet").param("response_type", "code").param("redirect_uri", REDIRECT)
                .param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256");
        if (scope != null) {
            request = request.param("scope", scope);
        } else {
            request = request.param("authorization_details",
                    "[{\"type\": \"openid_credential\", \"credential_configuration_id\": \"" + configuration + "\"}]");
        }
        for (Map.Entry<String, String> entry : extra.entrySet()) {
            request = request.param(entry.getKey(), entry.getValue());
        }
        return mockMvc.perform(request).andReturn();
    }

    private void assertInvalidRequest(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(400, result.getResponse().getStatus(), body.toString());
        assertEquals("invalid_request", body.get("error").asText(), body.toString());
        assertNull(result.getResponse().getHeader("Location"), "nothing is redirected for a refused pushed request");
    }

    private static String details(int length, int entries) {
        List<String> values = new ArrayList<>();
        String padding = "p".repeat(Math.max(0, length / Math.max(1, entries) - 60));
        for (int i = 0; i < entries; i++) {
            values.add("{\"type\": \"openid_credential\", \"credential_configuration_id\": \"" + CONFIG_ID
                    + "\", \"x\": \"" + padding + "\"}");
        }
        return "[" + String.join(",", values) + "]";
    }

    /** A pre-authorized offer's code: cached in {@code preAuthCodeCache} before the flood. */
    private String offer() throws Exception {
        MvcResult result = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID,
                        "subject", "par-demo-1", "expires_in", 600)))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String link = body.get("credential_offer_uri").asText();
        String url = URLDecoder.decode(link.substring(link.indexOf('=') + 1), StandardCharsets.UTF_8);
        JsonNode offer = objectMapper.readTree(mockMvc.perform(get("/credential-offer-data/" + url.substring(url.lastIndexOf('/') + 1)))
                .andReturn().getResponse().getContentAsString());
        return offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .get("pre-authorized_code").asText();
    }

    private static String challenge(String verifier) throws Exception {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    static CredentialConfigurationDTO config(String id, String scope) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8)
                .replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                        "\"" + id + "\": \"https://example.org/golden#" + id + "\"")
                .replace("\"GoldenCredential\"]", "\"" + id + "\"]");
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
        dto.setScope(scope);
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(id);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        return dto;
    }
}
