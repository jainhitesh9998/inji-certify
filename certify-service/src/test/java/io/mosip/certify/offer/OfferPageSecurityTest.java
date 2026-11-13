package io.mosip.certify.offer;

import io.mosip.certify.config.SecurityConfig;
import io.mosip.certify.core.config.LocalAuthenticationEntryPoint;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * F-15: the demo-subject endpoint is served by the page's own chain ({@code securityMatcher("/offer/**")}), with the
 * service's real chain in front, so it needs no entry in the security URL lists (CLAUDE.md rule 9) and no
 * authentication. The {@code test} profile every {@code @SpringBootTest} here runs with drops {@code SecurityConfig}
 * (and so every chain), so this context is built without it, as {@code IacaPublicationSecurityTest} does.
 */
class OfferPageSecurityTest {

    static final String NEIGHBOUR = "neighbouring route reached";

    /**
     * Routes next to the page that the page's chain must not open. The chain matches {@code /offer/**}, so everything
     * below {@code /offer/} is in it by design ({@code /offer/} itself, its scripts and this endpoint); what must stay
     * protected is anything whose path only looks like the page's.
     */
    @RestController
    static class Neighbours {
        @RequestMapping({"/offers", "/offer-admin", "/v2/credential-configurations-beside-the-page"})
        String reached() {
            return NEIGHBOUR;
        }
    }

    /**
     * The service's entry point hands an authentication failure to the MVC advice, which this slice does not load, so
     * nothing would set a status — the deployment's advice answers 200 with an error envelope for this exception today
     * (G28), not 401. The stand-in answers 401, so the test can assert the refusal by status as well as by body:
     * without the page's chain the path is never served, whatever the entry point writes.
     */
    static class UnauthenticatedIsRefused extends LocalAuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                throws IOException {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class,
                    WebMvcAutoConfiguration.class))
            .withUserConfiguration(UnauthenticatedIsRefused.class, SecurityConfig.class, Neighbours.class)
            .withPropertyValues(
                    "certify.offer-page.enabled=true",
                    "certify.offer-page.demo-subjects[0].id=mdl-demo-1",
                    "certify.offer-page.demo-subjects[0].label=Asha Demo",
                    "server.servlet.path=/v1/certify",
                    // the endpoint is in none of the security lists; {:} is SpEL's empty map, which the shipped {} becomes
                    // only through the full application's conversion service (SecurityConfig never reads them)
                    "mosip.certify.security.auth.post-urls={:}",
                    "mosip.certify.security.auth.put-urls={:}",
                    "mosip.certify.security.auth.get-urls={:}",
                    "mosip.certify.authn.jwk-set-uri=http://localhost:1/v1/certify/oauth/.well-known/jwks.json",
                    "mosip.certify.security.ignore-csrf-urls=**/actuator/**,/favicon.ico,**/error",
                    "mosip.certify.security.ignore-auth-urls=/actuator/**,**/error,**/swagger-ui/**,**/v3/api-docs/**");

    private MockMvc mockMvc(WebApplicationContext context) {
        Filter chains = context.getBean("springSecurityFilterChain", Filter.class);
        return MockMvcBuilders.webAppContextSetup(context).addFilters(chains).build();
    }

    @Test
    void withThePageOnTheChainItNeedsNoAuthentication() {
        runner.withUserConfiguration(OfferPageSecurityConfiguration.class, OfferPageController.class).run(context -> {
            assertThat(context).hasNotFailed();
            MockMvc mockMvc = mockMvc((WebApplicationContext) context.getSourceApplicationContext());
            assertEquals(200, mockMvc.perform(get("/offer/")).andReturn().getResponse().getStatus(), "the page itself");
            MvcResult subjects = mockMvc.perform(get("/offer/demo-subjects")).andReturn();
            assertEquals(200, subjects.getResponse().getStatus(), subjects.getResponse().getContentAsString());
            assertTrue(subjects.getResponse().getContentAsString().contains("\"mdl-demo-1\""), "the configured subject is served");
            assertEquals("no-store", subjects.getResponse().getHeader("Cache-Control"));
        });
    }

    @Test
    void withThePageOffThePathStaysBehindAuthentication() {
        // the controller without its chain: the service's own chain refuses the path, which is what rule 9 asks for:
        // the page's chain is the only thing that opens it, never an entry in the security URL lists
        runner.withUserConfiguration(OfferPageController.class).run(context -> {
            assertThat(context).hasNotFailed();
            MockMvc mockMvc = mockMvc((WebApplicationContext) context.getSourceApplicationContext());
            MvcResult subjects = mockMvc.perform(get("/offer/demo-subjects")).andReturn();
            assertTrue(List.of(401, 403).contains(subjects.getResponse().getStatus()),
                    "unauthenticated, the service's chain refuses the path: " + subjects.getResponse().getStatus());
            assertFalse(subjects.getResponse().getContentAsString().contains("\"subjects\""),
                    "unauthenticated, the endpoint answers nothing: " + subjects.getResponse().getStatus() + " "
                            + subjects.getResponse().getContentAsString());
        });
    }

    @Test
    void theRoutesNextToThePageStayProtected() {
        runner.withUserConfiguration(OfferPageSecurityConfiguration.class, OfferPageController.class).run(context -> {
            assertThat(context).hasNotFailed();
            MockMvc mockMvc = mockMvc((WebApplicationContext) context.getSourceApplicationContext());
            // the stand-in entry point answers 401, so a GET next to the page is refused with exactly that status; a CSRF
            // refusal (403) is only possible on the POSTs below
            for (String path : List.of("/offers", "/offer-admin", "/v2/credential-configurations-beside-the-page")) {
                MvcResult result = mockMvc.perform(get(path)).andReturn();
                int status = result.getResponse().getStatus();
                assertEquals(401, status, "GET " + path + " answered " + status + ", not 401");
                assertFalse(result.getResponse().getContentAsString().contains(NEIGHBOUR),
                        path + " reached its controller without authentication (" + status + ")");
                MvcResult posted = mockMvc.perform(post(path)).andReturn();
                int postedStatus = posted.getResponse().getStatus();
                assertTrue(List.of(401, 403).contains(postedStatus), "POST " + path + " answered " + postedStatus
                        + ", not 401/403");
                assertFalse(posted.getResponse().getContentAsString().contains(NEIGHBOUR), "POST " + path);
            }
        });
    }
}
