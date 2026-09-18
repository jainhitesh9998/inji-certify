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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tenancy end to end with the host resolver: a request for the {@code acme} host sees only acme's configurations,
 * issues with acme's issuer DID and audience, and the default tenant keeps the deployment's values; a request without
 * a tenant host cannot see acme's configuration.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.tenancy.enabled=true",
        "certify.tenancy.resolver=host",
        "certify.tenancy.tenants.acme.hosts=acme.localhost",
        "certify.tenancy.tenants.acme.issuer-identifier=http://acme.localhost/v1/certify",
        "certify.tenancy.tenants.acme.issuer-did=did:web:acme.localhost",
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
class TenancyIssuanceTest {

    static final String ACME_ID = "AcmeTenantCredential";
    static final String DEFAULT_ID = "DefaultTenantCredential";
    static final String ACME_HOST = "acme.localhost";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Tenant Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        if (credentialConfigRepository.findByTenantIdAndCredentialConfigKeyId("default", DEFAULT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(DEFAULT_ID, "DefaultTenantCredential"));
        }
        if (credentialConfigRepository.findByTenantIdAndCredentialConfigKeyId("acme", ACME_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(ACME_ID, "AcmeCredential"));
            CredentialConfig row = credentialConfigRepository.findByCredentialConfigKeyId(ACME_ID).orElseThrow();
            row.setTenantId("acme"); // the v1 API writes the default tenant; a tenant's row is placed by hand until the v2 API
            credentialConfigRepository.save(row);
        }
    }

    @Test
    void theHostSelectsTheTenantItsConfigurationsAndItsIssuer() throws Exception {
        String acmeIdentifier = "http://acme.localhost/v1/certify/oid4vci";
        MvcResult acme = issue(ACME_ID, ACME_HOST, proofJwt(nonce(ACME_HOST), acmeIdentifier));
        JsonNode acmeBody = objectMapper.readTree(acme.getResponse().getContentAsString());
        assertEquals(200, acme.getResponse().getStatus(), acmeBody.toString());
        JsonNode credential = acmeBody.get("credentials").get(0).get("credential");
        assertEquals("did:web:acme.localhost", credential.get("issuer").asText(), "the tenant's issuer DID reaches the template");
        assertEquals("Tenant Farmer", credential.get("credentialSubject").get("fullName").asText());

        MvcResult wrongAudience = issue(ACME_ID, ACME_HOST, proofJwt(nonce(ACME_HOST), issuerIdentifier + "/oid4vci"));
        assertEquals(400, wrongAudience.getResponse().getStatus(), "a proof for the deployment's identifier is not a proof for acme");

        MvcResult invisible = issue(ACME_ID, null, proofJwt(nonce(null), issuerIdentifier + "/oid4vci"));
        assertEquals(400, invisible.getResponse().getStatus());
        assertEquals("invalid_credential_request", objectMapper.readTree(invisible.getResponse().getContentAsString()).get("error").asText(),
                "acme's configuration does not exist for the default tenant");

        MvcResult dflt = issue(DEFAULT_ID, null, proofJwt(nonce(null), issuerIdentifier + "/oid4vci"));
        JsonNode defaultBody = objectMapper.readTree(dflt.getResponse().getContentAsString());
        assertEquals(200, dflt.getResponse().getStatus(), defaultBody.toString());
        assertEquals("did:web:localhost:certify", defaultBody.get("credentials").get(0).get("credential").get("issuer").asText(), "the default tenant keeps the deployment's DID");
    }

    private MvcResult issue(String configurationId, String host, String proof) throws Exception {
        var request = post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", configurationId, "proofs", Map.of("jwt", List.of(proof)))));
        if (host != null) {
            request = request.header("Host", host);
        }
        return mockMvc.perform(request).andReturn();
    }

    private String nonce(String host) throws Exception {
        var request = post("/oid4vci/nonce");
        if (host != null) {
            request = request.header("Host", host);
        }
        return objectMapper.readTree(mockMvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private static String proofJwt(String nonce, String audience) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private static CredentialConfigurationDTO config(String id, String type) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + type + "\": \"https://example.org/golden#" + type + "\"").replace("\"GoldenCredential\"]", "\"" + type + "\"]");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", type));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(type);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        ClaimsDTO claim = new ClaimsDTO();
        dto.setClaims(Map.of("fullName", claim));
        return dto;
    }
}
