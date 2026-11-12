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
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
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
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Offers on the OpenID4VCI 1.0 surface (M-09, gaps G17-G22): the offer names the surface in {@code credential_issuer},
 * the token it yields is addressed to that surface's credential endpoint and the real access-token filter accepts it,
 * and the offer can travel by value instead of by reference.
 *
 * <p>This is the only offer test that runs without the {@code local} profile, so the production
 * {@code Oid4vciAccessTokenFilter} validates the token rather than the TestBearer stand-in: issuer, signature and
 * audience are checked for real. The filter resolves its JWK Set over HTTP from this issuer's own
 * {@code /.well-known/jwks.json}; MockMvc has no listening socket, so a loopback server on an ephemeral port serves
 * exactly the bytes that endpoint publishes (a {@code file:} URI is refused by the JDK's HTTP client).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        // Certify's own AS: the token it mints carries this issuer, and the filter requires the same one
        "mosip.certify.authn.issuer-uri=http://localhost:8090/v1/certify",
        "mosip.certify.oauth.issuer=http://localhost:8090/v1/certify",
        // the in-memory cache the local profile selects; without it the default is Redis (spring.cache.type in
        // application-local.properties) and there is none in a unit-test JVM
        "spring.cache.type=simple",
        "mosip.certify.cache.names=userinfo,vcissuance,templatecache,certificatedatacache,credentialConfig,renderTemplate,jwks,preAuthCodeCache,credentialOfferCache,issuerMetadataCache,nonce,preAuthCacheTxn,dpopJti",
        "spring.cache.cache-names=${mosip.certify.cache.names}",
        "mosip.certify.cache.size={'userinfo': 200, 'vcissuance': 2000, 'templatecache': 20, 'jwks': 1, 'preAuthCodeCache': 1000, 'credentialOfferCache': 1000, 'issuerMetadataCache': 10, 'nonce': 1000, 'preAuthCacheTxn': 2000, 'dpopJti': 10000}",
        "mosip.certify.cache.expire-in-seconds={'userinfo': 3600, 'vcissuance': 3600, 'templatecache': 3600, 'certificatedatacache': 3600, 'credentialConfig': 3600, 'renderTemplate': 3600, 'jwks': 3600, 'preAuthCodeCache': 600, 'credentialOfferCache': 600, 'issuerMetadataCache': 3600, 'nonce': 300, 'preAuthCacheTxn': 3600, 'dpopJti': 120}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}",
        // Certify serves the authorization server metadata for its own AS (certify.as): only then does it publish the
        // OID4VCI pre-authorized grant flag
        "certify.as.clients.wallet.redirect-uris[0]=https://wallet.example/cb"
})
class Oid4vciOfferFlowTest {

    static final String CONFIG_ID = "OfferSurfaceCredential";
    static final String MDOC_ID = "OfferSurfaceMdl";
    static final String SCOPE = "offer_surface_vc";

    /** The bytes {@code /.well-known/jwks.json} answers with, served to the filter's JWK Set fetch. */
    private static volatile byte[] publishedJwks;
    private static final com.sun.net.httpserver.HttpServer JWKS_SERVER = startJwksServer();

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @DynamicPropertySource
    static void jwkSetUri(org.springframework.test.context.DynamicPropertyRegistry registry) {
        registry.add("mosip.certify.authn.jwk-set-uri",
                () -> "http://127.0.0.1:" + JWKS_SERVER.getAddress().getPort() + "/jwks.json");
    }

    /** Serves the issuer's published JWK Set to the filter's HTTP fetch of {@code mosip.certify.authn.jwk-set-uri}. */
    private static com.sun.net.httpserver.HttpServer startJwksServer() {
        try {
            com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/jwks.json", exchange -> {
                byte[] body = publishedJwks;
                exchange.sendResponseHeaders(body == null ? 503 : 200, body == null ? -1 : body.length);
                if (body != null) {
                    exchange.getResponseBody().write(body);
                }
                exchange.close();
            });
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(task -> {
                Thread thread = new Thread(task, "jwks-test-server");
                thread.setDaemon(true);
                return thread;
            }));
            server.start();
            return server;
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Could not start the JWK Set server", e);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        // the access-token filter fetches the JWK Set over HTTP: publish exactly what this issuer serves
        MvcResult jwks = mockMvc.perform(get("/.well-known/jwks.json")).andReturn();
        assertEquals(200, jwks.getResponse().getStatus(), jwks.getResponse().getContentAsString());
        publishedJwks = jwks.getResponse().getContentAsByteArray();
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Offer Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(mdocConfig());
        }
    }

    /** G17: an offer that names {@code oid4vci} carries exactly the identifier the surface's document publishes. */
    @Test
    void anOid4vciOfferNamesTheSurfaceIdentifierAndIssuesACredential() throws Exception {
        JsonNode metadata = getJson("/oid4vci/.well-known/openid-credential-issuer");
        String surfaceIdentifier = metadata.get("credential_issuer").asText();
        assertEquals(issuerIdentifier + "/oid4vci", surfaceIdentifier);

        JsonNode offer = createOffer(Map.of("issuer", "oid4vci"));
        assertEquals(surfaceIdentifier, offer.get("credential_issuer").asText(),
                "the offer's credential_issuer is the /oid4vci document's credential_issuer");
        assertTrue(offer.has("grants"), offer.toString());

        String code = offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code").get("pre-authorized_code").asText();
        MvcResult tokenResult = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", code)).andReturn();
        JsonNode token = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        assertEquals(200, tokenResult.getResponse().getStatus(), token.toString());

        // the token is addressed to the surface's credential endpoint and issued by the issuer the filter requires
        SignedJWT accessToken = SignedJWT.parse(token.get("access_token").asText());
        JWTClaimsSet claims = accessToken.getJWTClaimsSet();
        assertEquals(List.of(surfaceIdentifier + "/credential"), claims.getAudience(), "aud = the /oid4vci credential endpoint");
        assertEquals("http://localhost:8090/v1/certify", claims.getIssuer(), "iss = the issuer the /oid4vci filter validates");
        assertEquals(SCOPE, claims.getStringClaim("scope"));

        // the production filter accepts that token at /oid4vci/credential, and the ES256 proof names the surface
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String proof = proof(nonce, holder, surfaceIdentifier);
        MvcResult issued = mockMvc.perform(post("/oid4vci/credential")
                .header("Authorization", "Bearer " + token.get("access_token").asText())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "proofs", Map.of("jwt", List.of(proof))))))
                .andReturn();
        JsonNode issuedBody = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), issuedBody.toString());
        JsonNode credential = issuedBody.get("credentials").get(0).get("credential");
        assertEquals("Offer Farmer", credential.get("credentialSubject").get("fullName").asText(),
                "the credential carries the data provider's subject for the offer");
        assertTrue(credential.get("proof").isObject(), "and it is signed");
        assertNotNull(issuedBody.get("notification_id"));
    }

    /** The default stays by reference on the compatibility identifier, so an unchanged deployment sees no difference. */
    @Test
    void anOfferWithoutAnIssuerKeepsTheCompatibilityIdentifierAndComesByReference() throws Exception {
        MvcResult result = createOfferResult(Map.of());
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertTrue(body.has("credential_offer_uri"), body.toString());
        assertNull(body.get("credential_offer"), "by reference: no offer document in the answer");
        JsonNode offer = fetchOffer(body.get("credential_offer_uri").asText());
        assertEquals(issuerIdentifier, offer.get("credential_issuer").asText(), "the compatibility identifier, as before");
    }

    /** G18: {@code offer_by_value} returns the offer itself, and the deep link carries it URL-encoded. */
    @Test
    void anOfferCanBeReturnedByValue() throws Exception {
        MvcResult result = createOfferResult(Map.of("issuer", "oid4vci", "offer_by_value", true));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode byValue = body.get("credential_offer");
        assertNotNull(byValue, body.toString());
        String surfaceIdentifier = getJson("/oid4vci/.well-known/openid-credential-issuer").get("credential_issuer").asText();
        assertEquals(surfaceIdentifier, byValue.get("credential_issuer").asText());
        assertEquals(CONFIG_ID, byValue.get("credential_configuration_ids").get(0).asText());

        String deepLink = body.get("credential_offer_uri").asText();
        assertTrue(deepLink.startsWith("openid-credential-offer://?credential_offer="), deepLink);
        assertFalse(deepLink.contains("credential_offer_uri="), "by value the link carries the offer, not a pointer to it");
        JsonNode embedded = objectMapper.readTree(URLDecoder.decode(
                deepLink.substring("openid-credential-offer://?credential_offer=".length()), StandardCharsets.UTF_8));
        assertEquals(byValue, embedded, "the deep link carries exactly the offer document in the answer");
    }

    /** G19: the default tenant's /oid4vci document carries the deployment's display, as the compatibility document does. */
    @Test
    void theNewSurfaceDocumentCarriesTheIssuerDisplay() throws Exception {
        JsonNode legacy = getJson("/.well-known/openid-credential-issuer");
        JsonNode surface = getJson("/oid4vci/.well-known/openid-credential-issuer");
        assertNotNull(legacy.get("display"), "the compatibility document has the deployed display");
        assertEquals(legacy.get("display"), surface.get("display"));
    }

    /** G20: both metadata builders publish the one COSE map for mso_mdoc, as integers. */
    @Test
    void bothMetadataDocumentsPublishTheSameCoseAlgorithms() throws Exception {
        JsonNode legacy = getJson("/.well-known/openid-credential-issuer")
                .get("credential_configurations_supported").get(MDOC_ID).get("credential_signing_alg_values_supported");
        JsonNode surface = getJson("/oid4vci/.well-known/openid-credential-issuer")
                .get("credential_configurations_supported").get(MDOC_ID).get("credential_signing_alg_values_supported");
        assertEquals(objectMapper.createArrayNode().add(-7), legacy, "ES256 is COSE -7 (ISO/IEC 18013-5 A.2.2)");
        assertEquals(legacy, surface, "one map, both documents");
    }

    /** G22: the AS metadata advertises that the pre-authorized code grant needs no interaction, when Certify is the AS. */
    @Test
    void theAsMetadataAdvertisesAnonymousPreAuthorizedGrants() throws Exception {
        JsonNode metadata = getJson("/.well-known/oauth-authorization-server");
        assertTrue(metadata.get("pre-authorized_grant_anonymous_access_supported").asBoolean(), metadata.toString());
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    private JsonNode createOffer(Map<String, Object> extra) throws Exception {
        MvcResult result = createOfferResult(extra);
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        return fetchOffer(body.get("credential_offer_uri").asText());
    }

    private MvcResult createOfferResult(Map<String, Object> extra) throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("credential_configuration_id", CONFIG_ID);
        request.put("claims", Map.of("fullName", "Offer Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru"));
        request.put("expires_in", 600);
        request.putAll(extra);
        return mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))).andReturn();
    }

    private JsonNode fetchOffer(String deepLink) throws Exception {
        String url = URLDecoder.decode(deepLink.substring(deepLink.indexOf('=') + 1), StandardCharsets.UTF_8);
        return getJson("/credential-offer-data/" + url.substring(url.lastIndexOf('/') + 1));
    }

    private JsonNode getJson(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static String proof(String nonce, ECKey holder, String audience) throws Exception {
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(holder));
        return proof.serialize();
    }

    private CredentialConfigurationDTO ldpConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(CONFIG_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(template("golden-ldp.vm"));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "OfferSurfaceCredential"));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Offer surface credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth", "city"));
        dto.setClaims(Map.of("fullName", claim("Full name"), "dateOfBirth", claim("Date of birth"), "city", claim("City")));
        return dto;
    }

    private CredentialConfigurationDTO mdocConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(MDOC_ID);
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate(template("golden-mdoc.vm"));
        // a docType of its own: mso_mdoc configurations are unique per docType, and the golden tests own the mDL one
        dto.setDocType("org.iso.18013.5.1.mDL.offer-surface");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256");
        dto.setSignatureCryptoSuite("ES256");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Offer surface mDL")));
        dto.setDisplayOrder(List.of("family_name", "birth_date"));
        dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", new ClaimsDisplayFieldsConfigDTO())));
        return dto;
    }

    private static String template(String name) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates", name);
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Base64.getEncoder().encodeToString(Files.readString(path, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
    }

    private static MetaDataDisplayDTO display(String name) {
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(name);
        display.setLocale("en");
        return display;
    }

    private static ClaimsDTO claim(String name) {
        ClaimsDTO.Display display = new ClaimsDTO.Display();
        display.setName(name);
        display.setLocale("en");
        ClaimsDTO claims = new ClaimsDTO();
        claims.setDisplay(List.of(display));
        return claims;
    }
}
