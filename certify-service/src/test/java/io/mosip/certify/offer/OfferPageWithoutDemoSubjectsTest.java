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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * A deployment that configures no {@code certify.offer-page.demo-subjects} (every deployment before F-15, and most
 * after it): the page answers an empty list and keeps its typed field, with no dropdown and no error.
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
class OfferPageWithoutDemoSubjectsTest {

    @Autowired MockMvc mockMvc;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void noDemoSubjectsIsAnEmptyListAndThePageAsItWas() throws Exception {
        var answer = mockMvc.perform(get("/offer/demo-subjects")).andReturn();
        assertEquals(200, answer.getResponse().getStatus());
        assertEquals("no-store", answer.getResponse().getHeader("Cache-Control"));
        assertEquals("{\"subjects\":[]}", answer.getResponse().getContentAsString(),
                "an empty configuration is an empty list, not an error");
        String html = mockMvc.perform(get("/offer/")).andReturn().getResponse().getContentAsString();
        assertTrue(html.contains("<select id=\"subjectChoice\" hidden></select>"),
                "the dropdown ships hidden, so a deployment without subjects shows the typed field exactly as before");
        assertTrue(html.contains("<input id=\"subject\" placeholder=\"2154189532\">"), "the typed subject input is there");
    }
}
