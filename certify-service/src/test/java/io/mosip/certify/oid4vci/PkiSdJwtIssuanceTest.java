package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.api.spi.DataProviderPlugin;
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

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** An SD-JWT VC signed under the x509-file dev CA carries an anchor-free x5c that chains to the CA (HAIP). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.keyprovider.x509-file.enabled=true",
        "certify.keyprovider.x509-file.dev-mode=true",
        "certify.keyprovider.x509-file.path=target/pki-sdjwt-test.p12",
        "certify.keyprovider.x509-file.password=pki-test",
        "certify.keyprovider.x509-file.keys[0].alias=sdjwt-es256",
        "certify.keyprovider.x509-file.keys[0].algorithm=ES256",
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'jwk'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class PkiSdJwtIssuanceTest {

    static final String CONFIG_ID = "PkiSdJwtCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "PKI Farmer", "dateOfBirth", "1990-01-01", "address", Map.of("city", "Pune"))));
        MvcResult existing = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/v2/credential-configurations/" + CONFIG_ID)).andReturn();
        if (existing.getResponse().getStatus() == 404) {
            Path path = Path.of("src/test/resources/goldens/templates/golden-sdjwt.vm");
            if (!Files.exists(path)) {
                path = Path.of("certify-service").resolve(path);
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("id", CONFIG_ID);
            body.put("scope", "sample_vc_ldp"); // the local TestBearer token carries this scope
            body.put("format", "dc+sd-jwt");
            body.put("formatConfig", Map.of("vct", CONFIG_ID, "sdClaims", List.of("$.fullName"), "sdJwtClaims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
            body.put("signing", Map.of("provider", "x509-file", "alias", "sdjwt-es256", "alg", "ES256", "x5c", "without-anchor"));
            body.put("template", Map.of("content", Files.readString(path, StandardCharsets.UTF_8)));
            body.put("display", Map.of("display", List.of(Map.of("name", CONFIG_ID, "locale", "en")), "order", List.of("fullName")));
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }
    }

    @Test
    void theSdJwtCarriesAnAnchorFreeChainToTheDevCa() throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(holder));
        MvcResult issued = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "proofs", Map.of("jwt", List.of(proof.serialize())))))).andReturn();
        JsonNode body = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), body.toString());
        String sdJwt = body.get("credentials").get(0).get("credential").asText();
        SignedJWT jws = SignedJWT.parse(sdJwt.split("~")[0]);
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        List<com.nimbusds.jose.util.Base64> x5c = jws.getHeader().getX509CertChain();
        assertEquals(1, x5c.size(), "the leaf only; the trust anchor is not in x5c");
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(x5c.get(0).decode()));
        assertEquals("CN=Inji Certify Dev CA", leaf.getIssuerX500Principal().getName());
        assertTrue(jws.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())), "the JWS verifies with the leaf key");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        Path keystore = Files.exists(Path.of("target/pki-sdjwt-test.p12")) ? Path.of("target/pki-sdjwt-test.p12") : Path.of("certify-service/target/pki-sdjwt-test.p12");
        try (FileInputStream in = new FileInputStream(keystore.toFile())) {
            keyStore.load(in, "pki-test".toCharArray());
        }
        X509Certificate ca = (X509Certificate) keyStore.getCertificate("dev-ca");
        leaf.verify(ca.getPublicKey()); // the leaf chains to the CA the tester uploads as the trust anchor
        assertTrue(jws.getHeader().getX509CertSHA256Thumbprint() != null, "x5t#S256 present");
    }
}
