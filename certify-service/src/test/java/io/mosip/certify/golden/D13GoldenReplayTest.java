package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBORObject;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
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
 * Replays the draft-13 goldens recorded from 0.14.0 (goldens/legacy-0.14.0, P0-02) against the oid4vci-d13 adapter: the same
 * configurations and mock data as the recorder, the 0.14.0 request bodies on {@code /issuance/credential},
 * {@code /issuance/vd12/credential} and {@code /issuance/vd11/credential}, and the 0.14.0 error answers. Credentials
 * are verified with libraries Certify did not write. The two documented deviations (P0-02-notes.md, decision log) are
 * asserted explicitly: the MSO carries {@code signed} and the tag-24 wrapper ISO/IEC 18013-5 requires.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        // the issuer-level display and authorization server list are deployment settings; 0.14.0 recorded these values
        "mosip.certify.credential-config.issuer.display={{'name': 'Test Issuer', 'locale': 'en'}}",
        "mosip.certify.authorization.url=http://localhost:8090",
        "mosip.certify.authn.filter-urls={'/issuance/credential','/issuance/vd11/credential','/issuance/vd12/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class D13GoldenReplayTest {

    static final String LDP_ID = IssuanceGoldenTest.LDP_ID;
    static final String SDJWT_ID = IssuanceGoldenTest.SDJWT_ID;
    static final String MDOC_ID = IssuanceGoldenTest.MDOC_ID;
    static final List<String> LDP_CONTEXT = List.of("https://www.w3.org/2018/credentials/v1");
    static final List<String> LDP_TYPES = List.of("VerifiableCredential", "GoldenCredential");

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired StaticContextLoader staticContextLoader;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            CredentialConfigurationDTO ldp = IssuanceGoldenTest.ldpConfig(LDP_ID, "golden-ldp.vm", LDP_CONTEXT.get(0),
                    "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2020");
            credentialConfigurationService.addCredentialConfiguration(ldp);
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(SDJWT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(IssuanceGoldenTest.sdJwtConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(IssuanceGoldenTest.mdocConfig());
        }
    }

    @Test
    void ldpVcReplayAndIndependentVerification() throws Exception {
        MvcResult result = issue("/issuance/credential", ldpRequest(LDP_TYPES, proofJwt(nonce())));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertNotNull(result.getResponse().getHeader("Deprecation"), "draft-13 answers are deprecated from day one");
        assertTrue(result.getResponse().getHeader("Link").contains("rel=\"deprecation\""));
        JsonNode credential = body.get("credential");
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new Ed25519Signature2020LdVerifier(publicKey).verify(jsonLd), "ldp_vc through the d13 adapter must verify with danubetech");
        Goldens.assertGolden("legacy-0.14.0/issuance/ldp_vc-response", body);
    }

    @Test
    void versionedPathsReplay() throws Exception {
        MvcResult vd12 = issue("/issuance/vd12/credential", ldpRequest(LDP_TYPES, proofJwt(nonce())));
        JsonNode vd12Body = objectMapper.readTree(vd12.getResponse().getContentAsString());
        assertEquals(200, vd12.getResponse().getStatus(), vd12Body.toString());
        Goldens.assertGolden("legacy-0.14.0/issuance/vd12-ldp_vc-response", vd12Body);
        MvcResult vd11 = issue("/issuance/vd11/credential", ldpRequest(LDP_TYPES, proofJwt(nonce())));
        JsonNode vd11Body = objectMapper.readTree(vd11.getResponse().getContentAsString());
        assertEquals(200, vd11.getResponse().getStatus(), vd11Body.toString());
        Goldens.assertGolden("legacy-0.14.0/issuance/vd11-ldp_vc-response", vd11Body);
    }

    @Test
    void sdJwtReplayAndIndependentVerification() throws Exception {
        MvcResult result = issue("/issuance/credential", Map.of("format", "vc+sd-jwt", "vct", "GoldenCredential", "proof", proof(proofJwt(nonce()))));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String[] parts = body.get("credential").asText().split("~");
        JWSObject jws = JWSObject.parse(parts[0]);
        assertEquals("vc+sd-jwt", jws.getHeader().getType().getType(), "a draft-13 vc+sd-jwt request keeps the 0.14.0 typ");
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK key = jwks.getKeyByKeyId(jws.getHeader().getKeyID());
        assertNotNull(key, "kid must be in jwks.json");
        assertTrue(jws.verify(new ECDSAVerifier(key.toECKey())), "SD-JWT through the d13 adapter must verify with Nimbus");
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-header", objectMapper.readTree(jws.getHeader().toString()));
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-payload", objectMapper.readTree(jws.getPayload().toString()));
        ObjectNode shape = body.deepCopy();
        shape.put("credential", "<vc+sd-jwt>");
        shape.put("disclosures", parts.length - 1);
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-response", shape);
    }

    @Test
    void mdocReplayWithTheDocumentedDeviations() throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        MvcResult result = issue("/issuance/credential", Map.of("format", "mso_mdoc", "doctype", "org.iso.18013.5.1.mDL", "proof", proof(proofJwt(nonce(), holder))));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        CBORObject decoded = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(body.get("credential").asText()));
        CBORObject issuerSigned = decoded.get("issuerSigned");
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        assertTrue(issuerAuth.isTagged() && issuerAuth.getMostOuterTag().ToInt32Checked() == 18, "0.14.0 tagged issuerAuth as COSE_Sign1");
        CBORObject untagged = issuerAuth.Untag();
        byte[] protectedBytes = untagged.get(0).GetByteString();
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(protectedBytes);
        byte[] payloadBytes = untagged.get(2).GetByteString();
        CBORObject payload = CBORObject.DecodeFromBytes(payloadBytes);
        CBORObject mso = payload.HasMostOuterTag(24) ? CBORObject.DecodeFromBytes(payload.Untag().GetByteString()) : payload;
        // the signature verifies with JCA against the leaf certificate in x5chain
        CBORObject x5chain = untagged.get(1).get(CBORObject.FromObject(33));
        byte[] leafDer = x5chain.getType() == com.upokecenter.cbor.CBORType.Array ? x5chain.get(0).GetByteString() : x5chain.GetByteString();
        java.security.cert.X509Certificate leaf = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(leafDer));
        byte[] sigStructure = CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(payloadBytes).EncodeToBytes();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(sigStructure);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(untagged.get(3).GetByteString())), "IssuerAuth verifies with JCA");

        ObjectNode summary = objectMapper.createObjectNode();
        summary.put("topLevelKeys", decoded.getKeys().toString());
        summary.put("docType", mso.get("docType").AsString());
        summary.put("version", mso.get("version").AsString());
        summary.put("digestAlgorithm", mso.get("digestAlgorithm").AsString());
        summary.put("digests", mso.get("valueDigests").get("org.iso.18013.5.1").size());
        summary.put("issuerSignedItems", issuerSigned.get("nameSpaces").get("org.iso.18013.5.1").size());
        summary.put("issuerAuthTagged", issuerAuth.isTagged());
        summary.put("protectedAlg", protectedHeader.get(CBORObject.FromObject(1)).AsInt32());
        summary.put("protectedLabels", protectedHeader.getKeys().toString());
        summary.put("unprotectedHeaderLabels", untagged.get(1).getKeys().toString());
        summary.put("msoTaggedCbor", payload.HasMostOuterTag(24));
        CBORObject deviceKey = mso.get("deviceKeyInfo").get("deviceKey");
        summary.put("deviceKeyKty", deviceKey.get(CBORObject.FromObject(1)).AsInt32());
        summary.put("deviceKeyCrv", deviceKey.get(CBORObject.FromObject(-1)).AsInt32());
        summary.put("validityInfoKeys", mso.get("validityInfo").getKeys().toString());
        // Documented deviations from 0.14.0 (P0-02-notes.md, decision log): ISO/IEC 18013-5 requires the tag-24 MSO
        // wrapper and validityInfo.signed; the adapter keeps both and the golden is compared with them folded back.
        assertTrue(summary.get("msoTaggedCbor").asBoolean(), "MSO payload wrapped in tag 24");
        assertEquals("[\"signed\", \"validFrom\", \"validUntil\"]", summary.get("validityInfoKeys").asText());
        summary.put("msoTaggedCbor", false);
        summary.put("validityInfoKeys", "[\"validFrom\", \"validUntil\"]");
        ObjectNode shape = body.deepCopy();
        shape.put("credential", "<mso_mdoc>");
        Goldens.assertGolden("legacy-0.14.0/issuance/mso_mdoc-response", shape);
        Goldens.assertGolden("legacy-0.14.0/issuance/mso_mdoc-summary", summary);
    }

    @Test
    void errorAnswersReplay() throws Exception {
        MvcResult wrongNonce = issue("/issuance/credential", ldpRequest(LDP_TYPES, proofJwt("not-the-nonce")));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-invalid-nonce", statusAndBody(wrongNonce));
        String fresh = objectMapper.readTree(wrongNonce.getResponse().getContentAsString()).get("c_nonce").asText();
        MvcResult retry = issue("/issuance/credential", ldpRequest(LDP_TYPES, proofJwt(fresh)));
        assertEquals(200, retry.getResponse().getStatus(), "the c_nonce handed out in the error is the one to use next: " + retry.getResponse().getContentAsString());

        Goldens.assertGolden("legacy-0.14.0/issuance/error-unknown-type", statusAndBody(issue("/issuance/credential",
                ldpRequest(List.of("VerifiableCredential", "NoSuchCredential"), proofJwt(nonce())))));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-unsupported-format", statusAndBody(issue("/issuance/credential", Map.of("format", "jwt_vc_json",
                "credential_definition", Map.of("@context", LDP_CONTEXT, "type", LDP_TYPES), "proof", proof(proofJwt(nonce()))))));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-missing-proof", statusAndBody(issue("/issuance/credential", Map.of("format", "ldp_vc",
                "credential_definition", Map.of("@context", LDP_CONTEXT, "type", LDP_TYPES)))));
    }

    @Test
    void compatibilitySurfaceOnTheSamePathIsUntouched() throws Exception {
        MvcResult result = issue("/issuance/credential", Map.of("credential_configuration_id", LDP_ID, "proofs", Map.of("jwt", List.of(proofJwt(nonce())))));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertTrue(body.has("credentials"), "the 1.0 body is answered by the 1.0 controller");
        org.junit.jupiter.api.Assertions.assertNotNull(result.getResponse().getHeader("Deprecation"), "the 1.0 handler is deprecated from 1.1.0 (P1-11f)");
        assertFalse(body.has("credential"));
    }

    @Test
    void versionedMetadataReplay() throws Exception {
        MvcResult latest = mockMvc.perform(get("/.well-known/openid-credential-issuer?version=latest")).andReturn();
        assertEquals(200, latest.getResponse().getStatus(), latest.getResponse().getContentAsString());
        assertNotNull(latest.getResponse().getHeader("Deprecation"), "versioned metadata is deprecated from day one");
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-latest", onlyGoldenConfigurations(objectMapper.readTree(latest.getResponse().getContentAsString())));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-vd12", onlyGoldenConfigurations(getJson("/.well-known/openid-credential-issuer?version=vd12")));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-vd11", onlyGoldenConfigurations(getJson("/.well-known/openid-credential-issuer?version=vd11")));
        Goldens.assertGolden("legacy-0.14.0/well-known/issuance-openid-credential-issuer", onlyGoldenConfigurations(getJson("/issuance/.well-known/openid-credential-issuer")));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-unknown-version",
                statusAndBody(mockMvc.perform(get("/.well-known/openid-credential-issuer?version=vd10")).andReturn()));
        // without a version the current (OpenID4VCI 1.0) document keeps answering
        JsonNode current = getJson("/.well-known/openid-credential-issuer");
        assertTrue(current.has("nonce_endpoint") && current.get("credential_configurations_supported").get(LDP_ID).has("credential_metadata"));
        assertFalse(current.get("credential_configurations_supported").get(LDP_ID).has("order"));
    }

    @Test
    void issuanceDidAliasServesTheCurrentDocument() throws Exception {
        MvcResult alias = mockMvc.perform(get("/issuance/.well-known/did.json")).andReturn();
        assertEquals(200, alias.getResponse().getStatus());
        assertNotNull(alias.getResponse().getHeader("Deprecation"));
        assertEquals(getJson("/.well-known/did.json"), objectMapper.readTree(alias.getResponse().getContentAsString()), "the alias and the root path publish the same DID document");
    }

    // ---- helpers -------------------------------------------------------------------------------------

    /** The golden tests share one H2 database per JVM; only the three configurations 0.14.0 recorded are compared. */
    private JsonNode onlyGoldenConfigurations(JsonNode document) {
        ObjectNode copy = document.deepCopy();
        List<String> keep = List.of(LDP_ID, SDJWT_ID, MDOC_ID);
        for (String field : List.of("credential_configurations_supported", "credentials_supported")) {
            JsonNode configurations = copy.get(field);
            if (configurations instanceof ObjectNode map) {
                map.retain(keep);
            } else if (configurations instanceof com.fasterxml.jackson.databind.node.ArrayNode list) {
                com.fasterxml.jackson.databind.node.ArrayNode kept = objectMapper.createArrayNode();
                list.forEach(item -> { if (item.hasNonNull("id") && keep.contains(item.get("id").asText())) kept.add(item); });
                copy.set(field, kept);
            }
        }
        return copy;
    }

    private MvcResult issue(String path, Map<String, Object> request) throws Exception {
        return mockMvc.perform(post(path).header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(request))).andReturn();
    }

    private static Map<String, Object> ldpRequest(List<String> types, String proofJwt) {
        return Map.of("format", "ldp_vc", "credential_definition", Map.of("@context", LDP_CONTEXT, "type", types), "proof", proof(proofJwt));
    }

    private static Map<String, Object> proof(String jwt) {
        return Map.of("proof_type", "jwt", "jwt", jwt);
    }

    private JsonNode statusAndBody(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        JsonNode body = content.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(content);
        return objectMapper.createObjectNode().put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body));
    }

    private JsonNode getJson(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private String proofJwt(String nonce) throws Exception {
        return proofJwt(nonce, new ECKeyGenerator(Curve.P_256).generate());
    }

    /** A draft-13 wallet's proof: ES256, typ openid4vci-proof+jwt, jwk in the header, aud = today's issuer identifier. */
    private String proofJwt(String nonce, ECKey holder) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private byte[] ed25519PublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                byte[] decoded = Multibase.decode(method.get("publicKeyMultibase").asText());
                return Arrays.copyOfRange(decoded, 2, decoded.length);
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }
}
