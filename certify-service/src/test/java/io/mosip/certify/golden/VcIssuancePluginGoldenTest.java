package io.mosip.certify.golden;

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
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Goldens for the VCIssuance plugin mode (the plugin builds and signs the credential): what the legacy
 * {@code VCIssuanceServiceImpl} answers for a mocked {@code VCIssuancePlugin}, recorded under
 * goldens/legacy-develop/vci-plugin; {@link VcIssuancePluginGoldenCoreTest} replays them through the core.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.plugin-mode=VCIssuance",
        "mosip.certify.integration.vci-plugin=none", // the mock below is the only VCIssuancePlugin
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'did:jwk'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class VcIssuancePluginGoldenTest {

    static final String LDP_ID = "PluginLdpCredential";
    static final String MDOC_ID = "PluginMdlCredential";
    static final String SDJWT_ID = "PluginSdJwtCredential";
    static final String SCOPE = "sample_vc_ldp";
    static final String MDOC_BYTES = "o2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETA";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean VCIssuancePlugin vcIssuancePlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(), anyString(), any())).thenAnswer(inv -> {
            VCRequestDto request = inv.getArgument(0);
            VCResult<JsonLDObject> result = new VCResult<>();
            result.setFormat("ldp_vc");
            result.setCredential(JsonLDObject.fromJson(objectMapper.writeValueAsString(Map.of(
                    "@context", request.getContext(), "type", request.getType(), "id", "urn:uuid:plugin-1",
                    "issuer", "did:web:plugin", "issuanceDate", "2026-09-19T00:00:00Z",
                    "credentialSubject", Map.of("id", inv.getArgument(1), "fullName", "Plugin Farmer"),
                    "proof", Map.of("type", "Ed25519Signature2020", "created", "2026-09-19T00:00:00Z", "proofPurpose", "assertionMethod",
                            "verificationMethod", "did:web:plugin#key-1", "proofValue", "z3pluginproof")))));
            return result;
        });
        when(vcIssuancePlugin.getVerifiableCredential(any(), anyString(), any())).thenAnswer(inv -> {
            VCResult<String> result = new VCResult<>();
            result.setFormat("mso_mdoc");
            result.setCredential(MDOC_BYTES);
            return result;
        });
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            CredentialConfigurationDTO ldp = IssuanceGoldenTest.ldpConfig(LDP_ID, "golden-ldp.vm", "https://www.w3.org/2018/credentials/v1",
                    "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2020");
            ldp.setCredentialTypes(List.of("VerifiableCredential", "PluginCredential"));
            credentialConfigurationService.addCredentialConfiguration(ldp);
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            CredentialConfigurationDTO mdoc = IssuanceGoldenTest.mdocConfig();
            mdoc.setCredentialConfigKeyId(MDOC_ID);
            mdoc.setDocType("org.iso.18013.5.1.mDL.plugin");
            credentialConfigurationService.addCredentialConfiguration(mdoc);
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(SDJWT_ID).isEmpty()) {
            CredentialConfigurationDTO sd = IssuanceGoldenTest.sdJwtConfig();
            sd.setCredentialConfigKeyId(SDJWT_ID);
            sd.setSdJwtVct("PluginCredential");
            credentialConfigurationService.addCredentialConfiguration(sd);
        }
    }

    @Test
    void ldpVcThroughThePluginGolden() throws Exception {
        MvcResult result = issue(LDP_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("Plugin Farmer", credential.get("credentialSubject").get("fullName").asText());
        assertTrue(credential.get("credentialSubject").get("id").asText().startsWith("did:jwk:"), "the holder from the proof reaches the plugin");
        @SuppressWarnings("unchecked") ArgumentCaptor<Map<String, Object>> identity = ArgumentCaptor.forClass(Map.class);
        verify(vcIssuancePlugin).getVerifiableCredentialWithLinkedDataProof(any(), anyString(), identity.capture());
        assertEquals(SCOPE, identity.getValue().get("scope"));
        assertTrue(identity.getValue().containsKey("accessTokenHash"), "the token hash travels with the identity details");
        Goldens.assertGolden("legacy-develop/vci-plugin/ldp_vc-response", body);
    }

    @Test
    void mdocThroughThePluginGolden() throws Exception {
        MvcResult result = issue(MDOC_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertEquals(MDOC_BYTES, body.get("credentials").get(0).get("credential").asText());
        Goldens.assertGolden("legacy-develop/vci-plugin/mso_mdoc-response", body);
    }

    @Test
    void sdJwtIsNotServedByThePluginModeGolden() throws Exception {
        Goldens.assertGolden("legacy-develop/vci-plugin/error-unsupported-format", statusAndBody(issue(SDJWT_ID, proofJwt(nonce()))));
    }

    @Test
    void pluginFailuresGolden() throws Exception {
        doThrow(new VCIExchangeException("vci_exchange_failed")).when(vcIssuancePlugin).getVerifiableCredentialWithLinkedDataProof(any(), anyString(), any());
        Goldens.assertGolden("legacy-develop/vci-plugin/error-plugin-exception", statusAndBody(issue(LDP_ID, proofJwt(nonce()))));
        doReturn(new VCResult<>()).when(vcIssuancePlugin).getVerifiableCredentialWithLinkedDataProof(any(), anyString(), any());
        Goldens.assertGolden("legacy-develop/vci-plugin/error-plugin-empty", statusAndBody(issue(LDP_ID, proofJwt(nonce()))));
    }

    @Test
    void didDocumentIsNotServedInPluginModeGolden() throws Exception {
        Goldens.assertGolden("legacy-develop/vci-plugin/error-did-unsupported", statusAndBody(mockMvc.perform(get("/.well-known/did.json")).andReturn()));
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private MvcResult issue(String configurationId, String proof) throws Exception {
        return mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", configurationId, "proofs", Map.of("jwt", List.of(proof)))))).andReturn();
    }

    private JsonNode statusAndBody(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        JsonNode body = content.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(content);
        return objectMapper.createObjectNode().put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body));
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private String proofJwt(String nonce) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }
}
