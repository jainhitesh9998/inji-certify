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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The mDL demo stack's authorization server as a wallet sees it (gap G29): pre-authorized only. The document names the
 * one grant its token endpoint completes and no endpoint for a flow the stack does not serve, and the pre-authorized
 * grant is redeemed by a wallet that has no client registration at all - with no {@code client_id}, and with the
 * identifier a wallet does have (a {@code did:key:...}) that this AS does not know. OpenID4VCI 1.0 sections 6.1 and
 * 12.3 make that anonymous grant the point of an offer; registering no client must not change it.
 *
 * <p>This mirrors {@code docker-compose/docker-compose-injistack/config/certify-mdl.properties}; that file itself is
 * held by {@link MdlAuthorizationServerPropertiesTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.oauth.grant-types-supported=urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.oauth.interactive-authorization-endpoint=",
        "mosip.certify.oauth.require-interactive-authorization-request=false",
        "certify.as.pre-authorized-grant.advertise-anonymous-access=true",
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
class MdlPreAuthorizedOnlyTest {

    static final String CONFIG_ID = "MdlPreAuthCredential";
    static final String SCOPE = "mdl_pre_auth_vc";
    static final String PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    /** What a wallet sends when it has no registered client: its own DID, not a client_id this AS knows. */
    static final String UNREGISTERED_CLIENT = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

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
    void theLiveDocumentNamesOnlyWhatTheStackServes() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/oauth-authorization-server")).andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        JsonNode document = objectMapper.readTree(result.getResponse().getContentAsString());

        assertEquals(List.of(PRE_AUTH), objectMapper.convertValue(document.get("grant_types_supported"), List.class));
        assertEquals(List.of("code"), objectMapper.convertValue(document.get("response_types_supported"), List.class),
                "RFC 8414 section 2: response_types_supported is REQUIRED");
        assertTrue(document.get("pre-authorized_grant_anonymous_access_supported").asBoolean());

        Set<String> members = new TreeSet<>();
        document.fieldNames().forEachRemaining(members::add);
        assertEquals(new TreeSet<>(List.of("issuer", "token_endpoint", "jwks_uri", "grant_types_supported",
                        "response_types_supported", "dpop_signing_alg_values_supported",
                        "pre-authorized_grant_anonymous_access_supported")),
                members, "no endpoint of a flow this stack does not serve: " + document);
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
