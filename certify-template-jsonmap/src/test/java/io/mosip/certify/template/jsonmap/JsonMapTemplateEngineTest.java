package io.mosip.certify.template.jsonmap;

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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonMapTemplateEngineTest {

    final JsonMapTemplateEngine engine = new JsonMapTemplateEngine(new ObjectMapper());
    final CredentialConfiguration configuration = new CredentialConfiguration(null, "farmer", "farmer_vc", "ldp_vc", null, null,
            SigningConfig.of(KeyRef.parse("jca:dev-es256"), SignatureAlgorithm.ES256), null, null, null, null, null);
    final Map<String, Object> claims = Map.of("fullName", "Golden Farmer", "age", 34, "verified", true,
            "address", Map.of("city", "Bengaluru", "pin", "560001"), "crops", List.of("Maize", "Rice"));

    TemplateEngine.TemplateModel model(Map<String, Object> params) {
        return new TemplateEngine.TemplateModel(ClaimSet.of(claims), TenantContext.defaultTenant("https://issuer.example", "did:web:issuer.example"),
                HolderBinding.did("did:jwk:abc", "jwt"), new TemplateEngine.Validity(Instant.parse("2026-09-18T10:00:00Z"), Instant.parse("2027-09-18T10:00:00Z")),
                configuration, params);
    }

    Map<String, Object> render(String template) {
        return engine.render(TemplateRef.inline("jsonmap", template, TemplateRef.Mode.FULL_DOCUMENT), model(Map.of("vct", "FarmerCredential"))).document();
    }

    @Test
    void substitutesWithTypesAndInterpolatesText() {
        Map<String, Object> doc = render("""
                {"issuer": "${_issuer}", "holder": "${_holderId}", "validFrom": "${_validFrom}", "validUntil": "${_validUntil}",
                 "name": "${fullName}", "age": "${age}", "verified": "${verified}", "address": "${address}", "crops": "${crops}",
                 "city": "${address.city}", "label": "${fullName} (${age})", "vct": "${param:vct}", "fixed": 7}
                """);
        assertEquals("did:web:issuer.example", doc.get("issuer"));
        assertEquals("did:jwk:abc", doc.get("holder"));
        assertEquals("2026-09-18T10:00:00Z", doc.get("validFrom"));
        assertEquals("2027-09-18T10:00:00Z", doc.get("validUntil"));
        assertEquals("Golden Farmer", doc.get("name"));
        assertEquals(34, doc.get("age"), "a lone placeholder keeps the number");
        assertEquals(true, doc.get("verified"));
        assertEquals(Map.of("city", "Bengaluru", "pin", "560001"), doc.get("address"));
        assertEquals(List.of("Maize", "Rice"), doc.get("crops"));
        assertEquals("Bengaluru", doc.get("city"));
        assertEquals("Golden Farmer (34)", doc.get("label"));
        assertEquals("FarmerCredential", doc.get("vct"));
        assertEquals(7, doc.get("fixed"));
    }

    @Test
    void spreadsClaimsIntoAnObject() {
        Map<String, Object> all = render("{\"credentialSubject\": {\"id\": \"${_holderId}\", \"$claims\": true}}");
        Map<?, ?> subject = (Map<?, ?>) all.get("credentialSubject");
        assertEquals("did:jwk:abc", subject.get("id"));
        assertEquals("Golden Farmer", subject.get("fullName"));
        assertEquals(6, subject.size());

        Map<String, Object> some = render("{\"credentialSubject\": {\"$claims\": [\"fullName\", \"age\"]}}");
        assertEquals(Map.of("fullName", "Golden Farmer", "age", 34), some.get("credentialSubject"));
        assertFalse(((Map<?, ?>) some.get("credentialSubject")).containsKey("crops"));
    }

    @Test
    void missingClaimsFailUnlessAFallbackIsGiven() {
        FormatException e = assertThrows(FormatException.class, () -> render("{\"x\": \"${nope}\"}"));
        assertEquals(JsonMapTemplateEngine.ERROR_MISSING_CLAIM, e.getErrorCode());
        assertEquals("n/a", render("{\"x\": \"${nope|n/a}\"}").get("x"));
        assertEquals("", render("{\"x\": \"${nope|}\"}").get("x"));
        assertThrows(FormatException.class, () -> render("{\"s\": {\"$claims\": [\"nope\"]}}"));
    }

    @Test
    void nothingIsExecutedAndPlainTextStaysPlain() {
        Map<String, Object> doc = render("{\"t\": \"#set($x = 1) $x ${fullName}\", \"u\": \"no placeholders here\"}");
        assertEquals("#set($x = 1) $x Golden Farmer", doc.get("t"), "Velocity directives are plain text to this engine");
        assertEquals("no placeholders here", doc.get("u"));
    }

    @Test
    void acceptsBase64ContentAndRejectsNonObjects() {
        String encoded = Base64.getEncoder().encodeToString("{\"n\": \"${fullName}\"}".getBytes());
        assertEquals("Golden Farmer", engine.render(new TemplateRef("jsonmap", "t", 1, TemplateRef.Mode.CLAIMS_ONLY, encoded, Map.of()), model(Map.of())).document().get("n"));
        FormatException e = assertThrows(FormatException.class, () -> render("[1, 2]"));
        assertEquals(JsonMapTemplateEngine.ERROR_TEMPLATE_RENDER, e.getErrorCode());
        assertTrue(engine.modes().contains(TemplateRef.Mode.CLAIMS_ONLY));
        assertEquals("jsonmap", engine.id());
    }
}
