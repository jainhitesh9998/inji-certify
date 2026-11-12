package io.mosip.certify.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.issuance.KeyProviderRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M-05 review blocker, end to end: the expiry report used to read keymanager while beans were created, before
 * {@code KeymanagerKeyInitializer} provisioned {@code CERTIFY_SERVICE}, and the empty answer stayed cached, so the
 * JWKS omitted the service key and token signing failed. In a fresh context (the property below is unique to this
 * class), the JWKS carries the service key at once and the startup report has measured it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "certify.signing.key-expiry.warn-days=29"
})
class SigningKeyExpiryStartupTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired KeyProviderRegistry keyProviders;
    @Autowired SigningKeyExpiry expiry;
    @Autowired MeterRegistry meterRegistry;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void theJwksCarriesTheServiceKeyAsSoonAsTheApplicationIsReady() throws Exception {
        JsonNode jwks = objectMapper.readTree(mockMvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        List<String> kids = new ArrayList<>();
        jwks.get("keys").forEach(key -> kids.add(key.get("kid").asText()));

        KeyRef service = KeyRef.parse("keymanager:CERTIFY_SERVICE");
        String kid = keyProviders.provider("keymanager").resolve(service).kid();
        assertTrue(kids.contains(kid), "the CERTIFY_SERVICE key " + kid + " is in the JWKS: " + kids);

        String tag = "keymanager:CERTIFY_SERVICE@" + kid;
        assertTrue(expiry.gauged().contains(tag), "the ready-time report measured the service key: " + expiry.gauged());
        double days = meterRegistry.get(SigningKeyExpiry.METRIC).tag("keyRef", tag).gauge().value();
        assertTrue(days > 0, "days left on the service certificate: " + days);
    }
}
