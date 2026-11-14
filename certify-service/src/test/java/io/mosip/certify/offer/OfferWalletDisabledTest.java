package io.mosip.certify.offer;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * P5-03a (I4): the demo wallet is a switch of its own, {@code certify.offer-page.wallet.enabled}, false by default.
 * With it off the offer page is served exactly as before, no wallet page or config exists, and nothing in the browser is
 * kept: the page shows no Keep box and opens no store until {@code /offer/wallet/config} answers 200
 * ({@code docs/design/tools/check-offer-wallet.mjs}, "the wallet switch gates storage").
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "certify.offer-page.enabled=true"
})
class OfferWalletDisabledTest {

    @Autowired MockMvc mockMvc;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void theWalletPageDoesNotExist() throws Exception {
        var answer = mockMvc.perform(get("/offer/wallet")).andReturn().getResponse();
        assertEquals(404, answer.getStatus(), "the wallet page is gated separately from the offer page");
        assertEquals(0, answer.getContentAsByteArray().length, "a disabled page answers with no bytes at all");
        assertNull(answer.getHeader("Content-Security-Policy"), "and with no headers of a page it does not serve");
        assertNull(answer.getHeader("Permissions-Policy"));
    }

    @Test
    void theWalletConfigDoesNotExist() throws Exception {
        var answer = mockMvc.perform(get("/offer/wallet/config")).andReturn().getResponse();
        assertEquals(404, answer.getStatus(), "the config endpoint is gated with the wallet");
        assertEquals(0, answer.getContentAsByteArray().length, "no relay list is published while the wallet is off");
        assertNull(answer.getContentType(), "and nothing claims to be JSON");
    }

    @Test
    void theOfferPageIsStillServedWithTheSecurityHeaders() throws Exception {
        var answer = mockMvc.perform(get("/offer/")).andReturn().getResponse();
        assertEquals(200, answer.getStatus());
        assertEquals("camera=()", answer.getHeader("Permissions-Policy"));
        assertEquals("no-referrer", answer.getHeader("Referrer-Policy"));
        assertNull(answer.getHeader("Set-Cookie"), "the offer page sets no cookie");
        // The wallet's modules are ordinary static resources under the same chain, so they stay reachable with the
        // wallet off. That is harmless: a script writes nothing by being served, the page keeps nothing while the switch
        // is off, and no path but the two above is gated. The guard (check-public-guard.sh) tests what nginx exposes.
        var script = mockMvc.perform(get("/offer/wallet-store.js")).andReturn().getResponse();
        assertEquals(200, script.getStatus());
        assertTrue(new String(script.getContentAsByteArray(), StandardCharsets.UTF_8).contains("deleteEverything"),
                "the store's module is still the bundled file");
    }
}
