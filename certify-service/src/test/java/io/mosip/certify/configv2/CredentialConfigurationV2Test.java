package io.mosip.certify.configv2;

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
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.CredentialTemplateRepository;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The v2 configuration API end to end: write, mirror, issue through the core, preview, version, refuse, delete. */
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
class CredentialConfigurationV2Test {

    static final String ID = "V2FarmerCredential";
    static final String PATH = "/v2/credential-configurations";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigRepository configurations;
    @Autowired CredentialTemplateRepository templates;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Issued Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        configurations.findByTenantIdAndCredentialConfigKeyId("default", ID).ifPresent(configurations::delete);
    }

    @Test
    void theV2ModelIsWrittenMirroredIssuedPreviewedVersionedAndDeleted() throws Exception {
        Map<String, Object> body = body(ID, template(ID));
        MvcResult created = call(post(PATH), body);
        JsonNode json = objectMapper.readTree(created.getResponse().getContentAsString());
        assertEquals(201, created.getResponse().getStatus(), json.toString());
        assertEquals(ID, json.get("id").asText());
        assertEquals(2, json.get("configVersion").asInt());
        assertEquals(1, json.get("template").get("version").asInt());
        assertEquals("velocity", json.get("template").get("engine").asText());
        assertEquals("TEMPLATE", json.get("issuanceStrategy").asText());
        assertTrue(json.get("active").asBoolean());
        assertEquals("keymanager", json.get("signing").get("provider").asText());
        assertFalse(json.has("sampleClaims"));

        // the legacy columns are mirrored, so the v1 API, the compatibility surfaces and the metadata builders see the row
        CredentialConfig row = configurations.findByTenantIdAndCredentialConfigKeyId("default", ID).orElseThrow();
        assertEquals("https://www.w3.org/2018/credentials/v1", row.getContext());
        assertEquals("VerifiableCredential," + ID, row.getCredentialType());
        assertEquals("CERTIFY_VC_SIGN_ED25519", row.getKeyManagerAppId());
        assertEquals("ED25519_SIGN", row.getKeyManagerRefId());
        assertEquals("Ed25519Signature2020", row.getSignatureCryptoSuite());
        assertEquals("EdDSA", row.getSignatureAlgo());
        assertEquals(template(ID), new String(Base64.getDecoder().decode(row.getVcTemplate()), StandardCharsets.UTF_8));
        assertEquals(row.getConfigId(), row.getTemplateId());
        assertNotNull(row.getCryptographicBindingMethodsSupported());
        assertNotNull(row.getProofTypesSupported());
        assertTrue(row.getClaims().containsKey("fullName"));
        MvcResult v1 = mockMvc.perform(get("/credential-configurations/" + ID)).andReturn();
        assertEquals(200, v1.getResponse().getStatus());
        assertEquals(ID, objectMapper.readTree(v1.getResponse().getContentAsString()).get("credentialConfigKeyId").asText());
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(get("/oid4vci/.well-known/openid-credential-issuer")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertTrue(metadata.get("credential_configurations_supported").has(ID));

        // the new core issues from the row
        MvcResult issued = issue();
        JsonNode credential = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), credential.toString());
        JsonNode vc = credential.get("credentials").get(0).get("credential");
        assertEquals("Issued Farmer", vc.get("credentialSubject").get("fullName").asText());
        assertTrue(vc.has("proof"));

        // preview renders without signing
        MvcResult preview = call(post(PATH + "/" + ID + "/preview"), Map.of("claims", Map.of("fullName", "Preview Person", "dateOfBirth", "2000-02-02", "city", "Delhi")));
        JsonNode previewed = objectMapper.readTree(preview.getResponse().getContentAsString());
        assertEquals(200, preview.getResponse().getStatus(), previewed.toString());
        assertEquals("ldp_vc", previewed.get("format").asText());
        assertEquals("Preview Person", previewed.get("credential").get("credentialSubject").get("fullName").asText());
        assertEquals("did:example:preview-holder", previewed.get("credential").get("credentialSubject").get("id").asText());
        assertFalse(previewed.get("credential").has("proof"));

        // a changed template becomes version 2; the same content keeps it
        Map<String, Object> updated = body(ID, template(ID).replace("\"city\": \"${city}\"", "\"city\": \"${city}\", \"country\": \"IN\""));
        JsonNode afterUpdate = objectMapper.readTree(call(put(PATH + "/" + ID), updated).getResponse().getContentAsString());
        assertEquals(2, afterUpdate.get("template").get("version").asInt(), afterUpdate.toString());
        assertEquals(2, templates.findFirstByIdOrderByVersionDesc(row.getConfigId()).orElseThrow().getVersion());
        JsonNode again = objectMapper.readTree(call(put(PATH + "/" + ID), updated).getResponse().getContentAsString());
        assertEquals(2, again.get("template").get("version").asInt());
        JsonNode previewedAgain = objectMapper.readTree(call(post(PATH + "/" + ID + "/preview"), Map.of("claims", Map.of("fullName", "P", "dateOfBirth", "d", "city", "c"))).getResponse().getContentAsString());
        assertEquals("IN", previewedAgain.get("credential").get("credentialSubject").get("country").asText());

        // the list and the tenant scope
        JsonNode list = objectMapper.readTree(mockMvc.perform(get(PATH)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertTrue(list.findValuesAsText("id").contains(ID));

        MvcResult deleted = mockMvc.perform(delete(PATH + "/" + ID)).andReturn();
        assertEquals(204, deleted.getResponse().getStatus());
        assertEquals(404, mockMvc.perform(get(PATH + "/" + ID)).andReturn().getResponse().getStatus());
        assertEquals("configuration_not_found", objectMapper.readTree(mockMvc.perform(get(PATH + "/" + ID)).andReturn().getResponse().getContentAsString()).get("error").asText());
    }

    /**
     * An mso_mdoc configuration previews through the same dry run, with a device key the MSO can carry, and a document
     * that breaks ISO/IEC 18013-5 7.2.1 Table 5 is refused with the format's own code rather than a naked 400.
     */
    @Test
    void mdocPreviewCarriesTheDeviceKeyAndSurfacesTheDataModelRule() throws Exception {
        String id = "V2MdlCredential";
        configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
        // the golden mDL fixture may already hold org.iso.18013.5.1.mDL in the shared H2 database; this test needs the
        // doctype to itself, and the golden classes recreate their fixture in @BeforeEach whenever it is absent
        configurations.findByTenantIdAndCredentialFormatAndDocType("default", "mso_mdoc", "org.iso.18013.5.1.mDL")
                .ifPresent(configurations::delete);
        MvcResult created = call(post(PATH), mdocBody(id, mdocTemplate()));
        JsonNode json = objectMapper.readTree(created.getResponse().getContentAsString());
        assertEquals(201, created.getResponse().getStatus(), json.toString());

        MvcResult preview = call(post(PATH + "/" + id + "/preview"),
                Map.of("claims", Map.of("fullName", "Preview Person", "dateOfBirth", "2000-02-02", "city", "Delhi")));
        JsonNode previewed = objectMapper.readTree(preview.getResponse().getContentAsString());
        assertEquals(200, preview.getResponse().getStatus(), previewed.toString());
        assertEquals("mso_mdoc", previewed.get("format").asText());
        assertEquals("org.iso.18013.5.1.mDL", previewed.get("credential").get("docType").asText());
        assertEquals(2, previewed.get("credential").get("deviceKeyInfo").get("deviceKey").get("1").asInt(), "kty EC2");
        assertTrue(previewed.get("credential").get("valueDigests").has("org.iso.18013.5.1"));

        // the same configuration with an element removed is refused by the data model validator, and the row keeps its
        // template (the dry run runs inside the update's transaction)
        Map<String, Object> incomplete = mdocBody(id, mdocTemplate().replace(
                "{\"digestID\": 1, \"elementIdentifier\": \"given_name\", \"elementValue\": \"Jane\"},", ""));
        MvcResult refused = call(put(PATH + "/" + id), incomplete);
        assertEquals(400, refused.getResponse().getStatus(), refused.getResponse().getContentAsString());
        assertEquals("template_render_failed", error(refused));
        String description = objectMapper.readTree(refused.getResponse().getContentAsString()).get("error_description").asText();
        assertTrue(description.contains("mdoc_data_model_invalid") && description.contains("given_name"), description);
        assertEquals(1, objectMapper.readTree(mockMvc.perform(get(PATH + "/" + id)).andReturn().getResponse().getContentAsString())
                .get("template").get("version").asInt(), "the refused update stored nothing");
        configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
    }

    /**
     * ISO/IEC 18013-5 9.1.2.4 requires the document signer certificate in the IssuerAuth {@code x5chain}: an mso_mdoc
     * configuration that would leave the chain out ({@code signing.x5c: none}) is refused when it is saved.
     */
    @Test
    void mdocConfigurationWithoutX5chainIsRefused() throws Exception {
        String id = "V2MdlNoChainCredential";
        configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
        Map<String, Object> body = mdocBody(id, mdocTemplate());
        @SuppressWarnings("unchecked")
        Map<String, Object> signing = new LinkedHashMap<>((Map<String, Object>) body.get("signing"));
        signing.put("x5c", "none");
        body.put("signing", signing);
        MvcResult refused = call(post(PATH), body);
        assertEquals(400, refused.getResponse().getStatus(), refused.getResponse().getContentAsString());
        assertEquals("invalid_configuration", error(refused));
        String description = objectMapper.readTree(refused.getResponse().getContentAsString()).get("error_description").asText();
        assertTrue(description.contains("x5c") && description.contains("9.1.2.4"), description);
        assertTrue(configurations.findByTenantIdAndCredentialConfigKeyId("default", id).isEmpty(), "nothing was saved");
    }

    /**
     * The v2 save runs the format's element typing rule (D6): an override for a new identifier is accepted and reaches
     * the CBOR preview with the declared type, while an override that would change a Table 5 element is refused.
     */
    @Test
    void mdocElementTypesOverrideIsValidatedAndTypedOnTheWire() throws Exception {
        String id = "V2MdlTypedCredential";
        configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
        // the shared H2 database may hold the golden mDL row; this test needs the mDL doctype to itself
        configurations.findByTenantIdAndCredentialFormatAndDocType("default", "mso_mdoc", "org.iso.18013.5.1.mDL")
                .ifPresent(configurations::delete);
        String template = mdocTemplate();
        int insertion = template.lastIndexOf("]");
        String extra = ",\n            {\"digestID\": 12, \"elementIdentifier\": \"custom_score\", \"elementValue\": \"${score}\"},"
                + "\n            {\"digestID\": 13, \"elementIdentifier\": \"custom_text\", \"elementValue\": \"${code}\"}";
        template = template.substring(0, insertion) + extra + template.substring(insertion);

        Map<String, Object> body = mdocBody(id, template);
        @SuppressWarnings("unchecked")
        Map<String, Object> formatConfig = (Map<String, Object>) body.get("formatConfig");
        formatConfig.put("elementTypes", Map.of("org.iso.18013.5.1", Map.of(
                "custom_score", "uint", "custom_text", "tstr")));
        body.put("sampleClaims", Map.of("fullName", "Sample Person", "dateOfBirth", "1999-09-09", "city", "Sample City",
                "score", "7", "code", "2024-01-01"));
        MvcResult created = call(post(PATH), body);
        assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());

        MvcResult preview = call(post(PATH + "/" + id + "/preview"),
                Map.of("claims", Map.of("fullName", "Preview Person", "dateOfBirth", "2000-02-02", "city", "Delhi",
                        "score", "9", "code", "2024-01-01")));
        JsonNode previewed = objectMapper.readTree(preview.getResponse().getContentAsString());
        assertEquals(200, preview.getResponse().getStatus(), previewed.toString());
        Map<String, com.upokecenter.cbor.CBORObject> items = new LinkedHashMap<>();
        for (JsonNode encoded : previewed.get("attributes").get("taggedNamespaces").get("org.iso.18013.5.1")) {
            com.upokecenter.cbor.CBORObject item = com.upokecenter.cbor.CBORObject
                    .DecodeFromBytes(Base64.getDecoder().decode(encoded.asText()));
            items.put(item.get("elementIdentifier").AsString(), item);
        }
        com.upokecenter.cbor.CBORObject customScore = items.get("custom_score").get("elementValue");
        assertEquals(0, customScore.EncodeToBytes()[0] >> 5, "custom_score is a CBOR uint (major type 0)");
        assertEquals(9, customScore.AsInt32());
        com.upokecenter.cbor.CBORObject customText = items.get("custom_text").get("elementValue");
        assertEquals(3, customText.EncodeToBytes()[0] >> 5, "custom_text is a CBOR tstr (major type 3)");
        assertFalse(customText.HasMostOuterTag(1004), "a typed tstr is not guessed to be a full-date");

        // a configuration that changes a Table 5 element is refused at save, not at issuance
        Map<String, Object> changed = mdocBody("V2MdlChangedTable5", template);
        @SuppressWarnings("unchecked")
        Map<String, Object> changedConfig = (Map<String, Object>) changed.get("formatConfig");
        changedConfig.put("elementTypes", Map.of("org.iso.18013.5.1", Map.of("document_number", "uint")));
        MvcResult refused = call(post(PATH), changed);
        assertEquals(400, refused.getResponse().getStatus(), refused.getResponse().getContentAsString());
        assertTrue(refused.getResponse().getContentAsString().contains("document_number"),
                refused.getResponse().getContentAsString());
        configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
    }

    @Test
    void refusedBodiesAreNotSaved() throws Exception {
        call(post(PATH), body(ID, template(ID)));
        MvcResult duplicate = call(post(PATH), body(ID, template(ID)));
        assertEquals(409, duplicate.getResponse().getStatus());
        assertEquals("configuration_exists", error(duplicate));

        Map<String, Object> unknownFormat = body("V2Unknown", template("V2Unknown"));
        unknownFormat.put("format", "xyz");
        MvcResult format = call(post(PATH), unknownFormat);
        assertEquals(400, format.getResponse().getStatus());
        assertEquals("unsupported_format", error(format));

        Map<String, Object> badAlg = body("V2BadAlg", template("V2BadAlg"));
        ((Map<String, Object>) badAlg.get("signing")).put("alg", "HS256");
        assertEquals("unsupported_signature_algorithm", error(call(post(PATH), badAlg)));

        Map<String, Object> badEngine = body("V2BadEngine", template("V2BadEngine"));
        ((Map<String, Object>) badEngine.get("template")).put("engine", "mustache");
        assertEquals("unknown_template_engine", error(call(post(PATH), badEngine)));

        // a template that does not render against the sample claims is refused and the row is rolled back
        Map<String, Object> broken = body("V2Broken", "{ \"issuer\": \"${_issuer}\", #if( }");
        MvcResult render = call(post(PATH), broken);
        assertEquals(400, render.getResponse().getStatus());
        assertEquals("template_render_failed", error(render));
        assertTrue(configurations.findByTenantIdAndCredentialConfigKeyId("default", "V2Broken").isEmpty());
        assertEquals(404, mockMvc.perform(get(PATH + "/V2Broken")).andReturn().getResponse().getStatus());

        Map<String, Object> noTemplate = body("V2NoTemplate", template("V2NoTemplate"));
        noTemplate.remove("template");
        assertEquals("invalid_configuration", error(call(post(PATH), noTemplate)));

        assertEquals(404, mockMvc.perform(put(PATH + "/NoSuchConfig").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body("NoSuchConfig", template("NoSuchConfig"))))).andReturn().getResponse().getStatus());
    }

    private String error(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }

    /** F-10: a missing required field is a 400 naming it, decided before the database, and nothing is stored. */
    @Test
    void requiredFieldsAreRefusedUpFrontWithTheFieldNamed() throws Exception {
        String id = "V2RequiredFields";
        Map<String, Map<String, Object>> cases = new LinkedHashMap<>();
        Map<String, Object> noOrder = body(id, template(id));
        noOrder.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en"))));
        cases.put("display.order", noOrder);
        Map<String, Object> noScope = body(id, template(id));
        noScope.remove("scope");
        cases.put("scope", noScope);
        Map<String, Object> noDisplay = body(id, template(id));
        noDisplay.remove("display");
        cases.put("display is required", noDisplay);
        Map<String, Object> noDisplayEntries = body(id, template(id));
        noDisplayEntries.put("display", Map.of("order", List.of("fullName")));
        cases.put("display.display", noDisplayEntries);
        for (Map.Entry<String, Map<String, Object>> c : cases.entrySet()) {
            MvcResult refused = call(post(PATH), c.getValue());
            JsonNode error = objectMapper.readTree(refused.getResponse().getContentAsString());
            assertEquals(400, refused.getResponse().getStatus(), c.getKey() + ": " + error);
            assertEquals("invalid_configuration", error.get("error").asText(), c.getKey());
            assertTrue(error.get("error_description").asText().contains(c.getKey()), c.getKey() + ": " + error);
            assertTrue(configurations.findByTenantIdAndCredentialConfigKeyId("default", id).isEmpty(), c.getKey() + ": nothing stored");
        }
        // the same rule on update
        assertEquals(201, call(post(PATH), body(id, template(id))).getResponse().getStatus());
        try {
            MvcResult update = call(put(PATH + "/" + id), noOrder);
            assertEquals(400, update.getResponse().getStatus(), update.getResponse().getContentAsString());
            assertTrue(objectMapper.readTree(update.getResponse().getContentAsString()).get("error_description").asText().contains("display.order"));
        } finally {
            configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
        }
    }

    /** F-10: what only the database refuses (here a scope longer than its column) is a 400 without SQL, never a 200. */
    @Test
    void aDatabaseConstraintIsA400WithoutSqlText() throws Exception {
        String id = "V2TooLongScope";
        Map<String, Object> body = body(id, template(id));
        body.put("scope", "s".repeat(300));
        MvcResult refused = call(post(PATH), body);
        String text = refused.getResponse().getContentAsString();
        assertEquals(400, refused.getResponse().getStatus(), text);
        JsonNode error = objectMapper.readTree(text);
        assertEquals("invalid_configuration", error.get("error").asText(), text);
        for (String leak : List.of("SQL", "sql", "insert", "INSERT", "credential_config", "VARCHAR", "jdbc", "Exception")) {
            assertFalse(text.contains(leak), "no database internals in the answer: " + text);
        }
        assertTrue(configurations.findByTenantIdAndCredentialConfigKeyId("default", id).isEmpty());
    }

    /** F-10: the v2 surface never answers 200 to an error, whatever fails. */
    @Test
    void malformedBodiesAndUnexpectedErrorsAreNeverA200() throws Exception {
        MvcResult notJson = mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"id\": ")).andReturn();
        assertEquals(400, notJson.getResponse().getStatus(), notJson.getResponse().getContentAsString());
        assertEquals("invalid_configuration", objectMapper.readTree(notJson.getResponse().getContentAsString()).get("error").asText());

        Map<String, Object> wrongShape = body("V2WrongShape", template("V2WrongShape"));
        wrongShape.put("display", Map.of("display", List.of("not an object"), "order", List.of("fullName")));
        MvcResult shape = call(post(PATH), wrongShape);
        assertEquals(400, shape.getResponse().getStatus(), shape.getResponse().getContentAsString());

        CredentialConfigurationV2Controller controller = new CredentialConfigurationV2Controller(null);
        var duplicate = controller.constraint(new org.springframework.dao.DataIntegrityViolationException("could not execute statement",
                new java.sql.SQLException("duplicate key value violates unique constraint \"credential_config_pkey\"", "23505")));
        assertEquals(409, duplicate.getStatusCode().value());
        assertEquals("configuration_exists", duplicate.getBody().get("error"));
        assertFalse(duplicate.getBody().get("error_description").contains("credential_config_pkey"));
        var notNull = controller.constraint(new org.springframework.dao.DataIntegrityViolationException("could not execute statement",
                new java.sql.SQLException("null value in column \"display_order\" violates not-null constraint", "23502")));
        assertEquals(400, notNull.getStatusCode().value());
        assertFalse(notNull.getBody().get("error_description").contains("display_order"));
        assertEquals(500, controller.unexpected(new IllegalStateException("boom")).getStatusCode().value());
    }

    private MvcResult call(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, Object body) throws Exception {
        return mockMvc.perform(request.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
    }

    static Map<String, Object> body(String id, String template) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "ldp_vc");
        Map<String, Object> formatConfig = new LinkedHashMap<>();
        formatConfig.put("context", List.of("https://www.w3.org/2018/credentials/v1"));
        formatConfig.put("types", List.of("VerifiableCredential", id));
        formatConfig.put("claims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en")), "mandatory", true)));
        body.put("formatConfig", formatConfig);
        Map<String, Object> signing = new LinkedHashMap<>();
        signing.put("alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN");
        signing.put("alg", "EdDSA");
        signing.put("cryptosuite", "Ed25519Signature2020");
        signing.put("didUrl", "did:web:localhost:certify");
        body.put("signing", signing);
        Map<String, Object> templateBody = new LinkedHashMap<>();
        templateBody.put("content", template);
        body.put("template", templateBody);
        body.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en")), "order", List.of("fullName")));
        body.put("sampleClaims", Map.of("fullName", "Sample Person", "dateOfBirth", "1999-09-09", "city", "Sample City"));
        return body;
    }

    /** An mso_mdoc body: the mDL doctype, EdDSA signing and the golden mDL template as sample claims. */
    static Map<String, Object> mdocBody(String id, String template) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("scope", "sample_vc_mdl");
        body.put("format", "mso_mdoc");
        Map<String, Object> formatConfig = new LinkedHashMap<>();
        formatConfig.put("doctype", "org.iso.18013.5.1.mDL");
        formatConfig.put("mdocClaims", Map.of("org.iso.18013.5.1", Map.of("family_name", Map.of("display", List.of()))));
        body.put("formatConfig", formatConfig);
        Map<String, Object> signing = new LinkedHashMap<>();
        signing.put("alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN");
        signing.put("alg", "EdDSA");
        signing.put("didUrl", "did:web:localhost:certify");
        body.put("signing", signing);
        body.put("template", Map.of("content", template));
        body.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en")), "order", List.of("family_name")));
        body.put("sampleClaims", Map.of("fullName", "Sample Person", "dateOfBirth", "1999-09-09", "city", "Sample City"));
        return body;
    }

    static String mdocTemplate() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-mdoc.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    static String template(String type) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + type + "\": \"https://example.org/golden#" + type + "\"").replace("\"GoldenCredential\"]", "\"" + type + "\"]");
    }

    private MvcResult issue() throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", ID, "proofs", Map.of("jwt", List.of(jwt.serialize())))))).andReturn();
    }
}
