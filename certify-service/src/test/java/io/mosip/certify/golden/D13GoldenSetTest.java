package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The draft-13 golden set recorded from release 0.14.0 (docs/design/wp/p0-02-recorder). Until the oid4vci-d13 adapter
 * exists (P1-12) nothing can replay it; this test keeps the set complete, parseable and free of unmasked volatile values.
 */
class D13GoldenSetTest {

    static final List<String> EXPECTED = List.of(
            "well-known/openid-credential-issuer-latest", "well-known/openid-credential-issuer-vd12", "well-known/openid-credential-issuer-vd11",
            "well-known/openid-credential-issuer-unknown-version", "well-known/issuance-openid-credential-issuer",
            "well-known/did", "well-known/issuance-did", "well-known/jwks", "well-known/oauth-authorization-server",
            "issuance/ldp_vc-response", "issuance/vd12-ldp_vc-response", "issuance/vd11-ldp_vc-response",
            "issuance/vc+sd-jwt-header", "issuance/vc+sd-jwt-payload", "issuance/vc+sd-jwt-response",
            "issuance/mso_mdoc-response", "issuance/mso_mdoc-summary",
            "issuance/error-invalid-nonce", "issuance/error-unknown-type", "issuance/error-unsupported-format", "issuance/error-missing-proof",
            "pre-authorized/offer-uri", "pre-authorized/credential-offer", "pre-authorized/token-response",
            "pre-authorized/access-token-claims", "pre-authorized/access-token-header");

    @Test
    void goldenSetIsCompleteAndNormalized() throws Exception {
        for (String name : EXPECTED) {
            Path file = Goldens.goldenPath("d13/" + name);
            assertTrue(Files.exists(file), "missing golden " + file);
            String content = Files.readString(file, StandardCharsets.UTF_8);
            JsonNode node = Goldens.mapper().readTree(content);
            assertTrue(node.isObject(), name + " is a JSON object");
            assertFalse(content.contains("\"responseTime\" : \"20"), name + " carries an unmasked timestamp");
            assertTrue(Goldens.mapper().writeValueAsString(Goldens.normalize(node)).equals(Goldens.mapper().writeValueAsString(node)),
                    name + " must already be in normalized form");
        }
        try (var files = Files.walk(Goldens.goldenPath("d13").getParent().resolve("d13"))) {
            long count = files.filter(p -> p.toString().endsWith(".json")).count();
            assertTrue(count == EXPECTED.size(), "unexpected golden files under d13: " + count + " vs " + EXPECTED.size());
        }
    }

    @Test
    @Disabled("replayed against the oid4vci-d13 adapter once P1-12 lands")
    void replayAgainstTheD13Adapter() {
    }
}
