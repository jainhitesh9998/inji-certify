package io.mosip.certify.offer;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * With {@code certify.offer-page.enabled} false (the default, and the whole path's switch) neither the page nor the
 * demo-subject endpoint exists: nothing new is exposed by a deployment that did not ask for the page.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "certify.offer-page.enabled=false"
})
class OfferPageDisabledTest {

    @Autowired MockMvc mockMvc;
    @Autowired ApplicationContext context;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void theDemoSubjectsEndpointDoesNotExist() throws Exception {
        assertTrue(context.getBeansOfType(OfferPageController.class).isEmpty(), "the controller is absent");
        assertEquals(404, mockMvc.perform(get("/offer/demo-subjects")).andReturn().getResponse().getStatus(),
                "the endpoint is gated with the page");
    }
}
