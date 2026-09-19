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
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** The offer page and its QR library are bundled and served under the servlet path; {@code /offer/} forwards to the page. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "certify.offer-page.enabled=true"
})
class OfferPageTest {

    @Autowired MockMvc mockMvc;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void thePageAndItsScriptAreServed() throws Exception {
        MvcResult page = mockMvc.perform(get("/offer/index.html")).andReturn();
        assertEquals(200, page.getResponse().getStatus());
        String html = page.getResponse().getContentAsString();
        assertTrue(html.contains("<title>Credential offer</title>") && html.contains("/pre-authorized-data") && html.contains("openid4vci-proof+jwt"), "the page creates offers and plays the wallet");
        MvcResult script = mockMvc.perform(get("/offer/qrcode.min.js")).andReturn();
        assertEquals(200, script.getResponse().getStatus());
        assertTrue(script.getResponse().getContentAsString().startsWith("var QRCode;"));
        MvcResult directory = mockMvc.perform(get("/offer/")).andReturn();
        assertEquals(200, directory.getResponse().getStatus());
        assertTrue(directory.getResponse().getContentType().startsWith("text/html") && directory.getResponse().getContentAsString().equals(html), "the directory path answers the same page");
    }
}
