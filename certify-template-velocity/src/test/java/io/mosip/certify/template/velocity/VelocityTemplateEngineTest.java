package io.mosip.certify.template.velocity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VelocityTemplateEngineTest {

    static final String TEMPLATE = """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              "issuer": "${_issuer}",
              "type": ["VerifiableCredential", "FarmerCredential"],
              "issuanceDate": "${validFrom}",
              "expirationDate": "${_validUntil}",
              "credentialSubject": {"id": "${_holderId}", "fullName": "${fullName}", "name": "$_esc.java($fullName)", "year": "$_dateTool.format('yyyy', $_dateTool.getDate())"}
            }
            """;

    final VelocityTemplateEngine engine = new VelocityTemplateEngine(new VelocityRenderer(), new ObjectMapper());
    final CredentialConfiguration configuration = new CredentialConfiguration(null, "farmer", "farmer_vc", "ldp_vc", null, null,
            SigningConfig.of(KeyRef.parse("jca:dev-es256"), SignatureAlgorithm.ES256), null, null, null, null, null);

    TemplateEngine.TemplateModel model(String name) {
        return new TemplateEngine.TemplateModel(ClaimSet.of(Map.of("fullName", name)), TenantContext.defaultTenant("https://issuer.example", "did:web:issuer.example"),
                HolderBinding.did("did:jwk:abc", "jwt"), new TemplateEngine.Validity(Instant.parse("2026-09-18T10:00:00Z"), Instant.parse("2027-09-18T10:00:00Z")),
                configuration, Map.of());
    }

    @Test
    void rendersTheModelTheWayTodaysTemplatesExpect() {
        Map<String, Object> doc = engine.render(TemplateRef.inline("velocity", TEMPLATE, TemplateRef.Mode.FULL_DOCUMENT), model("Golden Farmer")).document();

        assertEquals("did:web:issuer.example", doc.get("issuer"));
        assertEquals("2026-09-18T10:00:00Z", doc.get("issuanceDate"));
        assertEquals("2027-09-18T10:00:00Z", doc.get("expirationDate"));
        Map<?, ?> subject = (Map<?, ?>) doc.get("credentialSubject");
        assertEquals("did:jwk:abc", subject.get("id"));
        assertEquals("Golden Farmer", subject.get("fullName"));
        assertEquals("Golden Farmer", subject.get("name"), "EscapeTool available as _esc");
        assertTrue(((String) subject.get("year")).matches("\\d{4}"), "DateTool available as _dateTool");
        assertEquals(List.of("VerifiableCredential", "FarmerCredential"), doc.get("type"));
    }

    @Test
    void acceptsBase64EncodedTemplatesAsStoredInConfigurations() {
        String encoded = Base64.getEncoder().encodeToString(TEMPLATE.getBytes());
        Map<String, Object> doc = engine.render(new TemplateRef("velocity", "farmer-v1", 1, TemplateRef.Mode.FULL_DOCUMENT, encoded, Map.of()), model("A")).document();
        assertEquals("did:web:issuer.example", doc.get("issuer"));
    }

    @Test
    void templateParamsAndEscapingReachTheTemplate() {
        TemplateEngine.TemplateModel m = new TemplateEngine.TemplateModel(ClaimSet.of(Map.of("fullName", "O\"Brien")), TenantContext.DEFAULT, HolderBinding.NONE, null, configuration, Map.of("extra", "x"));
        Map<String, Object> doc = engine.render(TemplateRef.inline("velocity", "{\"n\": \"$_esc.java($fullName)\", \"e\": \"${extra}\"}", TemplateRef.Mode.CLAIMS_ONLY), m).document();
        assertEquals("O\"Brien", doc.get("n"));
        assertEquals("x", doc.get("e"));
    }

    @Test
    void nonJsonOutputAndMissingContentAreReported() {
        FormatException e = assertThrows(FormatException.class, () -> engine.render(TemplateRef.inline("velocity", "not json ${fullName}", TemplateRef.Mode.FULL_DOCUMENT), model("A")));
        assertEquals(VelocityTemplateEngine.ERROR_TEMPLATE_RENDER, e.getErrorCode());
        assertThrows(FormatException.class, () -> engine.render(TemplateRef.NONE, model("A")));
    }

    @Test
    void rendererDoesNotOverrideCallerSuppliedTools() {
        VelocityRenderer renderer = new VelocityRenderer();
        Map<String, Object> params = new HashMap<>(Map.of("_esc", "mine", "v", "1"));
        assertEquals("mine 1", renderer.evaluate("$_esc $v", params, "t"));
        assertTrue(params.containsKey(VelocityRenderer.DATE_TOOL));
    }
}
