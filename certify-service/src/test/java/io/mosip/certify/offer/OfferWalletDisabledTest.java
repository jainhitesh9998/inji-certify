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
    void theWalletPageHasNoStaticSpelling() throws Exception {
        // P5-03a review round 2: static/offer/wallet.html is an ordinary classpath resource, so without a mapping of its
        // own the resource handler served it at /offer/wallet.html - with the wallet switched off, and without the
        // headers of plan 4.13. The controller answers that spelling 404 whatever the switch says.
        var answer = mockMvc.perform(get("/offer/wallet.html")).andReturn().getResponse();
        assertEquals(404, answer.getStatus(), "the wallet page's file name is not a second way to the page");
        assertEquals(0, answer.getContentAsByteArray().length, "and it answers no bytes of the page");
        assertNull(answer.getHeader("Content-Security-Policy"));
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
        // wallet off. That is harmless: a script writes nothing by being served, and neither page opens a store until
        // /offer/wallet/config answers 200 (check-offer-wallet.mjs sections 10 and 15). Only the wallet page, under
        // both spellings, and its config are gated. The guard (check-public-guard.sh) tests what nginx exposes.
        var script = mockMvc.perform(get("/offer/wallet-store.js")).andReturn().getResponse();
        assertEquals(200, script.getStatus());
        assertTrue(new String(script.getContentAsByteArray(), StandardCharsets.UTF_8).contains("deleteEverything"),
                "the store's module is still the bundled file");
    }
}
