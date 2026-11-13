package io.mosip.certify.as;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.as.AsProperties;
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
import org.springframework.context.ApplicationContext;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The mDL demo stack's authorization server as a wallet sees it (F-21, gap G29, decision log 2026-11-13): the
 * pre-authorized grant the offer flow issues on, next to Certify's own authorization code flow. The document names the
 * endpoint a wallet looks for even on a pre-authorized offer (Talao refused the document that had none), and every
 * member says only what this stack serves: PAR is required, PKCE is `S256`, and the interactive authorization endpoint
 * of the farmer profiles stays out.
 *
 * <p>The pre-authorized grant is unchanged and anonymous - OpenID4VCI 1.0 sections 6.1 and 12.3 make it the point of
 * an offer - so it is redeemed by a wallet that has no client registration at all: with no {@code client_id}, and with
 * the identifier a wallet does have (a {@code did:key:...}) that this AS does not know. The code flow, by contrast,
 * serves only the one registered client ({@code demo-wallet}) and issues no code: the subject mode is {@code none}, so
 * a registered client's authorization request is refused with {@code access_denied} rather than signing one synthetic
 * holder's mDL for whoever completed the flow.
 *
 * <p>This mirrors {@code docker-compose/docker-compose-injistack/config/certify-mdl.properties}; that file itself is
 * held by {@link MdlAuthorizationServerPropertiesTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.oauth.interactive-authorization-endpoint=",
        "mosip.certify.oauth.require-interactive-authorization-request=false",
        "certify.as.pre-authorized-grant.advertise-anonymous-access=true",
        "certify.as.clients.demo-wallet.redirect-uris[0]=" + MdlDemoAuthorizationServerTest.REDIRECT,
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
class MdlDemoAuthorizationServerTest {

    static final String CONFIG_ID = "MdlPreAuthCredential";
    static final String SCOPE = "mdl_pre_auth_vc";
    static final String PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    static final String AUTHORIZATION_CODE = "authorization_code";
    /** The client the mDL profile registers: its redirect URI is the public offer page. */
    static final String CLIENT_ID = "demo-wallet";
    static final String REDIRECT = "https://credentials.example.org/v1/certify/offer/";
    /** A PKCE verifier and its S256 challenge (RFC 7636 appendix B). */
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /** What a wallet sends when it has no registered client: its own DID, not a client_id this AS knows. */
    static final String UNREGISTERED_CLIENT = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired ApplicationContext applicationContext;
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
    void theLiveDocumentNamesOnlyWhatTheStackServes() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/oauth-authorization-server")).andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        JsonNode document = objectMapper.readTree(result.getResponse().getContentAsString());

        assertEquals(List.of(AUTHORIZATION_CODE, PRE_AUTH),
                objectMapper.convertValue(document.get("grant_types_supported"), List.class));
        assertEquals(List.of("code"), objectMapper.convertValue(document.get("response_types_supported"), List.class),
                "RFC 8414 section 2: response_types_supported is REQUIRED");
        assertEquals(List.of("S256"), objectMapper.convertValue(document.get("code_challenge_methods_supported"), List.class),
                "RFC 7636: PKCE S256");
        assertTrue(document.get("pre-authorized_grant_anonymous_access_supported").asBoolean());
        // RFC 8414 section 2: the code grant is listed with the endpoint that issues a code, and PAR is required
        assertTrue(document.get("authorization_endpoint").asText().endsWith("/oauth/authorize"), document.toString());
        assertTrue(document.get("pushed_authorization_request_endpoint").asText().endsWith("/oauth/par"), document.toString());
        assertTrue(document.get("require_pushed_authorization_requests").asBoolean());

        Set<String> members = new TreeSet<>();
        document.fieldNames().forEachRemaining(members::add);
        assertEquals(new TreeSet<>(List.of("issuer", "token_endpoint", "jwks_uri", "grant_types_supported",
                        "response_types_supported", "code_challenge_methods_supported",
                        "dpop_signing_alg_values_supported", "authorization_endpoint",
                        "pushed_authorization_request_endpoint", "require_pushed_authorization_requests",
                        "pre-authorized_grant_anonymous_access_supported")),
                members, "only the members of the two flows this stack serves: " + document);
    }

    /** OID4VCI 1.0 section 12.3: a Token Request with a pre-authorized code and no client at all. */
    @Test
    void aPreAuthorizedCodeIsRedeemedWithoutAClientId() throws Exception {
        MvcResult token = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", PRE_AUTH)
                .param("pre-authorized_code", offer())).andReturn();
        assertAccessToken(token, "a Token Request without client_id");
    }

    /** A wallet that sends the only identifier it has (its DID) is not registered here, and is not refused either. */
    @Test
    void anUnregisteredClientIdDoesNotStopAPreAuthorizedCodeRedemption() throws Exception {
        MvcResult token = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", PRE_AUTH)
                .param("pre-authorized_code", offer())
                .param("client_id", UNREGISTERED_CLIENT)).andReturn();
        assertAccessToken(token, "a Token Request carrying an unregistered did:key client_id");
    }

    /** RFC 6749 section 5.2 and RFC 9126 section 2.3: only a registered client may push an authorization request. */
    @Test
    void anUnregisteredClientCannotPushAnAuthorizationRequest() throws Exception {
        MvcResult par = mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", UNREGISTERED_CLIENT).param("response_type", "code").param("redirect_uri", REDIRECT)
                .param("scope", SCOPE).param("code_challenge", challenge(VERIFIER)).param("code_challenge_method", "S256"))
                .andReturn();
        JsonNode body = objectMapper.readTree(par.getResponse().getContentAsString());
        assertEquals(401, par.getResponse().getStatus(), body.toString());
        assertEquals("invalid_client", body.get("error").asText(), body.toString());
    }

    /** RFC 9126 section 2.2: an unknown or expired {@code request_uri} is {@code invalid_request}. */
    @Test
    void anUnregisteredClientCannotUseTheAuthorizationEndpoint() throws Exception {
        MvcResult authorize = mockMvc.perform(get("/oauth/authorize").param("client_id", UNREGISTERED_CLIENT)
                .param("request_uri", "urn:ietf:params:oauth:request_uri:not-mine")).andReturn();
        JsonNode body = objectMapper.readTree(authorize.getResponse().getContentAsString());
        assertEquals(400, authorize.getResponse().getStatus(), body.toString());
        assertEquals("invalid_request", body.get("error").asText(), body.toString());
        assertNull(authorize.getResponse().getHeader("Location"), "nothing is redirected to a client this AS does not know");
        // and without a request_uri: PAR is required, so there is nothing to authorize
        MvcResult withoutRequest = mockMvc.perform(get("/oauth/authorize").param("client_id", UNREGISTERED_CLIENT)).andReturn();
        assertEquals(400, withoutRequest.getResponse().getStatus(), withoutRequest.getResponse().getContentAsString());
        assertEquals("invalid_request", objectMapper.readTree(withoutRequest.getResponse().getContentAsString()).get("error").asText());
    }

    /**
     * The registered client pushes its request, and the authorization endpoint refuses it: the demo's subject mode is
     * {@code none}, so no subject can be established. The answer is {@code access_denied} by redirect (RFC 6749
     * section 4.1.2.1), with no code and no fixed subject, and nothing is written to {@code iar_session} for it.
     */
    @Test
    void aRegisteredClientsAuthorizationRequestIssuesNoCodeWithoutASubject() throws Exception {
        MvcResult par = mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", CLIENT_ID).param("response_type", "code").param("redirect_uri", REDIRECT)
                .param("scope", SCOPE).param("state", "xyz").param("code_challenge", challenge(VERIFIER))
                .param("code_challenge_method", "S256")).andReturn();
        JsonNode parBody = objectMapper.readTree(par.getResponse().getContentAsString());
        assertEquals(201, par.getResponse().getStatus(), parBody.toString());
        String requestUri = parBody.get("request_uri").asText();
        assertTrue(parBody.get("expires_in").asLong() > 0);

        MvcResult authorize = mockMvc.perform(get("/oauth/authorize").param("client_id", CLIENT_ID)
                .param("request_uri", requestUri)).andReturn();
        assertEquals(302, authorize.getResponse().getStatus(), authorize.getResponse().getContentAsString());
        String location = authorize.getResponse().getHeader("Location");
        assertTrue(location.startsWith(REDIRECT + "?"), location);
        Map<String, String> query = query(location);
        assertEquals("access_denied", query.get("error"), "no subject can be established with subject-mode none: " + location);
        assertNull(query.get("code"), "no authorization code is issued: " + location);
        assertEquals("xyz", query.get("state"));
        assertNotNull(query.get("iss"), "RFC 9207 issuer identifier in the response");

        // the request_uri is single use even when refused
        assertEquals(400, mockMvc.perform(get("/oauth/authorize").param("client_id", CLIENT_ID)
                .param("request_uri", requestUri)).andReturn().getResponse().getStatus());
    }

    /** The subject mode the demo runs with is {@code none}, never {@code fixed}: one synthetic holder's mDL for anyone. */
    @Test
    void theSubjectModeIsNone() {
        AsProperties as = applicationContext.getBean(AsProperties.class);
        assertEquals(AsProperties.SUBJECT_MODE_NONE, as.authorization().subjectMode());
        assertNull(as.authorization().fixedSubject());
    }

    private static Map<String, String> query(String url) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        org.springframework.web.util.UriComponentsBuilder.fromUriString(url).build().getQueryParams()
                .forEach((k, v) -> out.put(k, URLDecoder.decode(v.get(0), StandardCharsets.UTF_8)));
        return out;
    }

    private static String challenge(String verifier) throws Exception {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    /** A pre-authorized offer for the configuration; its code is what the token endpoint redeems. */
    private String offer() throws Exception {
        MvcResult result = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID,
                        "subject", "mdl-demo-1", "expires_in", 600)))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String link = body.get("credential_offer_uri").asText();
        String url = URLDecoder.decode(link.substring(link.indexOf('=') + 1), StandardCharsets.UTF_8);
        JsonNode offer = objectMapper.readTree(mockMvc.perform(get("/credential-offer-data/" + url.substring(url.lastIndexOf('/') + 1)))
                .andReturn().getResponse().getContentAsString());
        return offer.get("grants").get(PRE_AUTH).get("pre-authorized_code").asText();
    }

    private void assertAccessToken(MvcResult result, String what) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), what + " must be accepted: " + body);
        assertNotNull(body.get("access_token"), what + " must be answered with a token: " + body);
        assertEquals("Bearer", body.get("token_type").asText());
    }

    private static CredentialConfigurationDTO config() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8)
                .replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                        "\"" + CONFIG_ID + "\": \"https://example.org/golden#" + CONFIG_ID + "\"")
                .replace("\"GoldenCredential\"]", "\"" + CONFIG_ID + "\"]");
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
        return dto;
    }
}
