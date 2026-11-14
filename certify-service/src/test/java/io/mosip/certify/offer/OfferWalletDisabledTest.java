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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * P5-03a (I4): the demo wallet is a switch of its own, {@code certify.offer-page.wallet.enabled}, false by default.
 * With it off the offer page is served exactly as before, and the wallet's paths answer 404: nothing in the browser can
 * be kept or presented.
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
    void theWalletPageAndItsConfigDoNotExist() throws Exception {
        assertEquals(404, mockMvc.perform(get("/offer/wallet")).andReturn().getResponse().getStatus(),
                "the wallet page is gated separately from the offer page");
        assertEquals(404, mockMvc.perform(get("/offer/wallet/config")).andReturn().getResponse().getStatus(),
                "the config endpoint is gated with the wallet");
    }

    @Test
    void theOfferPageIsStillServedWithTheSecurityHeaders() throws Exception {
        var answer = mockMvc.perform(get("/offer/")).andReturn().getResponse();
        assertEquals(200, answer.getStatus());
        assertEquals("camera=()", answer.getHeader("Permissions-Policy"));
        assertEquals("no-referrer", answer.getHeader("Referrer-Policy"));
        // the wallet's own store and reader exist as files but are not reachable through any controller path
        assertNull(answer.getHeader("Set-Cookie"));
    }
}
