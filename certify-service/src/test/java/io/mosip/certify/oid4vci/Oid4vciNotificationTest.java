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
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.IssuanceTransaction;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuanceTransactionRepository;
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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Issuance transactions and the OpenID4VCI 1.0 notification endpoint on the new surface. */
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
        "mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:uuid:",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class Oid4vciNotificationTest {

    static final String CONFIG_ID = "NotificationLdpCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired IssuanceTransactionRepository transactions;
    @Autowired IssuanceTransactionHousekeeping housekeeping;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Notified Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config());
        }
    }

    @Test
    void issuanceRecordsATransactionAndTheWalletCanReportBack() throws Exception {
        MvcResult result = issue();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String notificationId = body.get("notification_id").asText();
        assertNotNull(notificationId);
        IssuanceTransaction row = transactions.findById(UUID.fromString(notificationId)).orElseThrow();
        assertEquals(IssuanceTransaction.STATE_ISSUED, row.getState());
        assertEquals(CONFIG_ID, row.getCredentialConfigId());
        assertEquals("OID4VCI_1_0", row.getProtocolVersion());
        assertEquals("default", row.getTenantId());
        assertNotNull(row.getAccessTokenHash());
        assertEquals(1, row.getHolderBindings().size());
        assertTrue(row.getHolderBindings().get(0).get("value").toString().startsWith("did:jwk:"));
        // H2 stores TEXT[] as VARCHAR and reads the list back with one bracketed element; PostgreSQL keeps the array
        assertTrue(String.join(",", row.getCredentialIds()).contains(body.get("credentials").get(0).get("credential").get("id").asText()));
        assertTrue(row.getExpiresAt().isAfter(row.getCreatedTimes()));

        MvcResult accepted = notify(Map.of("notification_id", notificationId, "event", "credential_accepted", "event_description", "stored"));
        assertEquals(204, accepted.getResponse().getStatus(), accepted.getResponse().getContentAsString());
        assertEquals(IssuanceTransaction.STATE_NOTIFIED, transactions.findById(UUID.fromString(notificationId)).orElseThrow().getState());

        MvcResult badEvent = notify(Map.of("notification_id", notificationId, "event", "credential_lost"));
        assertEquals(400, badEvent.getResponse().getStatus());
        assertEquals("invalid_notification_request", objectMapper.readTree(badEvent.getResponse().getContentAsString()).get("error").asText());
        MvcResult unknown = notify(Map.of("notification_id", UUID.randomUUID().toString(), "event", "credential_accepted"));
        assertEquals(400, unknown.getResponse().getStatus());
        assertEquals("invalid_notification_id", objectMapper.readTree(unknown.getResponse().getContentAsString()).get("error").asText());

        long purged = housekeeping.purgeExpired(row.getExpiresAt().plusSeconds(1));
        assertTrue(purged >= 1);
        assertTrue(transactions.findById(UUID.fromString(notificationId)).isEmpty());
        MvcResult gone = notify(Map.of("notification_id", notificationId, "event", "credential_deleted"));
        assertEquals(400, gone.getResponse().getStatus());

        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertEquals(issuerIdentifier + "/oid4vci/notification", metadata.get("notification_endpoint").asText());
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

    private MvcResult issue() throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID, "proofs", Map.of("jwt", List.of(jwt.serialize())))))).andReturn();
    }

    private MvcResult notify(Map<String, String> request) throws Exception {
        return mockMvc.perform(post("/oid4vci/notification").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))).andReturn();
    }
}
