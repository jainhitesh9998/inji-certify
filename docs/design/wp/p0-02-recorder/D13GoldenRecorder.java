package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBORObject;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialSubjectParametersDTO;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Records the draft-13 goldens from release 0.14.0 (this tree, e54539a): the real service on H2 with the PKCS#12
 * keymanager, Velocity and the TestBearer filter, driven through MockMvc with the same mock data and the same
 * configurations as develop's v1 goldens. Output goes to src/test/resources/goldens/legacy-0.14.0 and is copied into the
 * rebuild branch, where the oid4vci-d13 adapter must reproduce it. Runs in this tree only.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.sql.init.schema-locations=classpath:schema.sql,classpath:d13-schema-patch.sql", // 0.14.0's H2 schema predates its entity
        "mosip.certify.authn.filter-urls={'/issuance/credential','/issuance/vd11/credential','/issuance/vd12/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'vc+sd-jwt': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class D13GoldenRecorder {

    static final String LDP_ID = "GoldenLdpCredential";
    static final String SDJWT_ID = "GoldenSdJwtCredential";
    static final String MDOC_ID = "GoldenMdlCredential";
    static final String SCOPE = "sample_vc_ldp"; // the scope the 0.14.0 TestBearer fake token carries
    static final List<String> LDP_CONTEXT = List.of("https://www.w3.org/2018/credentials/v1");
    static final List<String> LDP_TYPES = List.of("VerifiableCredential", "GoldenCredential");

    /** The fake token's c_nonce; every response (success or invalid_nonce) that names a c_nonce replaces it. */
    static String cNonce = "nZEA28AFIrUsYD8o5vDG";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(SDJWT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(sdJwtConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(mdocConfig());
        }
    }

    // ---- discovery -----------------------------------------------------------------------------------

    @Test
    void wellKnownGoldens() throws Exception {
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-latest", getJson("/.well-known/openid-credential-issuer"));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-vd12", getJson("/.well-known/openid-credential-issuer?version=vd12"));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-vd11", getJson("/.well-known/openid-credential-issuer?version=vd11"));
        Goldens.assertGolden("legacy-0.14.0/well-known/issuance-openid-credential-issuer", getJson("/issuance/.well-known/openid-credential-issuer"));
        Goldens.assertGolden("legacy-0.14.0/well-known/did", getJson("/.well-known/did.json"));
        Goldens.assertGolden("legacy-0.14.0/well-known/issuance-did", getJson("/issuance/.well-known/did.json"));
        Goldens.assertGolden("legacy-0.14.0/well-known/jwks", getJson("/.well-known/jwks.json"));
        Goldens.assertGolden("legacy-0.14.0/well-known/oauth-authorization-server", getJson("/.well-known/oauth-authorization-server"));
        Goldens.assertGolden("legacy-0.14.0/well-known/openid-credential-issuer-unknown-version", statusAndBody(mockMvc.perform(get("/.well-known/openid-credential-issuer?version=vd10")).andReturn()));
    }

    // ---- POST /issuance/credential (draft-13 body) ---------------------------------------------------

    @Test
    void ldpVcGolden() throws Exception {
        MvcResult result = issue("/issuance/credential", ldpRequest(LDP_TYPES, proofJwt(cNonce)));
        JsonNode body = remember(result);
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        assertEquals("Ed25519Signature2020", body.get("credential").get("proof").get("type").asText());
        Goldens.assertGolden("legacy-0.14.0/issuance/ldp_vc-response", body);
    }

    @Test
    void vd12AndVd11LdpVcGoldens() throws Exception {
        MvcResult vd12 = issue("/issuance/vd12/credential", ldpRequest(LDP_TYPES, proofJwt(cNonce)));
        JsonNode vd12Body = remember(vd12);
        assertEquals(200, vd12.getResponse().getStatus(), vd12Body.toString());
        assertEquals("ldp_vc", vd12Body.get("format").asText(), "draft 12 echoes the format");
        Goldens.assertGolden("legacy-0.14.0/issuance/vd12-ldp_vc-response", vd12Body);

        MvcResult vd11 = issue("/issuance/vd11/credential", ldpRequest(LDP_TYPES, proofJwt(cNonce)));
        JsonNode vd11Body = remember(vd11);
        assertEquals(200, vd11.getResponse().getStatus(), vd11Body.toString());
        Goldens.assertGolden("legacy-0.14.0/issuance/vd11-ldp_vc-response", vd11Body);
    }

    @Test
    void sdJwtGolden() throws Exception {
        MvcResult result = issue("/issuance/credential", Map.of("format", "vc+sd-jwt", "vct", "GoldenCredential", "proof", proof(proofJwt(cNonce))));
        JsonNode body = remember(result);
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String sdJwt = body.get("credential").asText();
        String[] parts = sdJwt.split("~");
        assertTrue(parts.length >= 3, "issuer JWS plus disclosures: " + parts.length);
        JWSObject jws = JWSObject.parse(parts[0]);
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-header", objectMapper.readTree(jws.getHeader().toString()));
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-payload", objectMapper.readTree(jws.getPayload().toString()));
        ObjectNode shape = body.deepCopy();
        shape.put("credential", "<vc+sd-jwt>");
        shape.put("disclosures", parts.length - 1);
        Goldens.assertGolden("legacy-0.14.0/issuance/vc+sd-jwt-response", shape);
    }

    @Test
    void mdocGolden() throws Exception {
        MvcResult result = issue("/issuance/credential", Map.of("format", "mso_mdoc", "doctype", "org.iso.18013.5.1.mDL", "proof", proof(proofJwt(cNonce))));
        JsonNode body = remember(result);
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String credential = body.get("credential").asText();
        CBORObject decoded = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(credential));
        CBORObject issuerSigned = decoded.ContainsKey("issuerSigned") ? decoded.get("issuerSigned") : decoded;
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(issuerAuth.get(0).GetByteString());
        CBORObject payload = CBORObject.DecodeFromBytes(issuerAuth.get(2).GetByteString());
        CBORObject mso = payload.HasMostOuterTag(24) ? CBORObject.DecodeFromBytes(payload.Untag().GetByteString()) : payload;
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
        summary.put("unprotectedHeaderLabels", issuerAuth.get(1).getKeys().toString());
        summary.put("msoTaggedCbor", payload.HasMostOuterTag(24));
        CBORObject deviceKey = mso.get("deviceKeyInfo").get("deviceKey");
        summary.put("deviceKeyKty", deviceKey.get(CBORObject.FromObject(1)).AsInt32());
        summary.put("deviceKeyCrv", deviceKey.get(CBORObject.FromObject(-1)).AsInt32());
        summary.put("validityInfoKeys", mso.get("validityInfo").getKeys().toString());
        ObjectNode shape = body.deepCopy();
        shape.put("credential", "<mso_mdoc>");
        Goldens.assertGolden("legacy-0.14.0/issuance/mso_mdoc-response", shape);
        Goldens.assertGolden("legacy-0.14.0/issuance/mso_mdoc-summary", summary);
    }

    @Test
    void errorGoldens() throws Exception {
        MvcResult wrongNonce = issue("/issuance/credential", ldpRequest(LDP_TYPES, proofJwt("not-the-nonce")));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-invalid-nonce", statusAndBody(wrongNonce));
        remember(wrongNonce); // the error carries the c_nonce the wallet must use next
        MvcResult unknownType = issue("/issuance/credential", ldpRequest(List.of("VerifiableCredential", "NoSuchCredential"), proofJwt(cNonce)));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-unknown-type", statusAndBody(unknownType));
        remember(unknownType);
        MvcResult unsupportedFormat = issue("/issuance/credential", Map.of("format", "jwt_vc_json",
                "credential_definition", Map.of("@context", LDP_CONTEXT, "type", LDP_TYPES), "proof", proof(proofJwt(cNonce))));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-unsupported-format", statusAndBody(unsupportedFormat));
        remember(unsupportedFormat);
        MvcResult noProof = issue("/issuance/credential", Map.of("format", "ldp_vc", "credential_definition", Map.of("@context", LDP_CONTEXT, "type", LDP_TYPES)));
        Goldens.assertGolden("legacy-0.14.0/issuance/error-missing-proof", statusAndBody(noProof));
        remember(noProof);
    }

    // ---- pre-authorized code flow ---------------------------------------------------------------------

    @Test
    void preAuthorizedCodeFlowGoldens() throws Exception {
        MvcResult offerResult = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", LDP_ID,
                        "claims", Map.of("fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru"),
                        "expires_in", 600, "tx_code", "1234")))).andReturn();
        JsonNode offerBody = objectMapper.readTree(offerResult.getResponse().getContentAsString());
        assertEquals(200, offerResult.getResponse().getStatus(), offerBody.toString());
        Goldens.assertGolden("legacy-0.14.0/pre-authorized/offer-uri", offerBody);
        String offerUri = offerBody.get("credential_offer_uri").asText();
        String offerUrl = java.net.URLDecoder.decode(offerUri.substring(offerUri.indexOf("credential_offer_uri=") + "credential_offer_uri=".length()), StandardCharsets.UTF_8);
        JsonNode offer = getJson("/credential-offer-data/" + offerUrl.substring(offerUrl.lastIndexOf('/') + 1));
        Goldens.assertGolden("legacy-0.14.0/pre-authorized/credential-offer", offer);
        String code = offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code").get("pre-authorized_code").asText();
        MvcResult tokenResult = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", code).param("tx_code", "1234")).andReturn();
        JsonNode token = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        assertEquals(200, tokenResult.getResponse().getStatus(), token.toString());
        Goldens.assertGolden("legacy-0.14.0/pre-authorized/token-response", token);
        SignedJWT accessToken = SignedJWT.parse(token.get("access_token").asText());
        ObjectNode claims = (ObjectNode) objectMapper.readTree(accessToken.getJWTClaimsSet().toString());
        if (claims.get("sub") != null && claims.get("sub").asText().startsWith("{")) {
            claims.set("sub", objectMapper.readTree(claims.get("sub").asText())); // develop's finding: claims JSON inside sub
        }
        Goldens.assertGolden("legacy-0.14.0/pre-authorized/access-token-claims", claims);
        Goldens.assertGolden("legacy-0.14.0/pre-authorized/access-token-header", objectMapper.readTree(accessToken.getHeader().toString()));
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private JsonNode getJson(String path) throws Exception {
        MvcResult result = mockMvc.perform(get(path)).andReturn();
        assertEquals(200, result.getResponse().getStatus(), path + ": " + result.getResponse().getContentAsString());
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode statusAndBody(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        JsonNode body = content.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(content);
        return objectMapper.createObjectNode().put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body));
    }

    /** Parses the body and adopts the c_nonce it names, if any (success bodies name none in 0.14.0; invalid_nonce errors do). */
    private JsonNode remember(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        JsonNode body = content.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(content);
        if (body.hasNonNull("c_nonce")) {
            cNonce = body.get("c_nonce").asText();
        }
        return body;
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

    /** A holder proof as a draft-13 wallet builds it: ES256, typ openid4vci-proof+jwt, jwk in the header, aud = identifier. */
    private String proofJwt(String nonce) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
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

    private static CredentialSubjectParametersDTO subject(String name) {
        CredentialSubjectParametersDTO.Display display = new CredentialSubjectParametersDTO.Display();
        display.setName(name);
        display.setLocale("en");
        CredentialSubjectParametersDTO dto = new CredentialSubjectParametersDTO();
        dto.setDisplay(List.of(display));
        return dto;
    }

    private static CredentialConfigurationDTO ldpConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(LDP_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(template("golden-ldp.vm"));
        dto.setContextURLs(LDP_CONTEXT);
        dto.setCredentialTypes(LDP_TYPES);
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth", "city"));
        dto.setCredentialSubjectDefinition(Map.of("fullName", subject("Full name"), "dateOfBirth", subject("Date of birth"), "city", subject("City")));
        return dto;
    }

    private static CredentialConfigurationDTO sdJwtConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(SDJWT_ID);
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate(template("golden-sdjwt.vm"));
        dto.setSdJwtVct("GoldenCredential");
        dto.setSdClaim("$.fullName,$.address.city");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden SD-JWT Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth"));
        dto.setSdJwtClaims(Map.of("fullName", new ClaimsDisplayFieldsConfigDTO()));
        return dto;
    }

    private static CredentialConfigurationDTO mdocConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(MDOC_ID);
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate(template("golden-mdoc.vm"));
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256");
        dto.setSignatureCryptoSuite("ES256");
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden mDL")));
        dto.setDisplayOrder(List.of("family_name", "birth_date"));
        dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", new ClaimsDisplayFieldsConfigDTO())));
        return dto;
    }
}
