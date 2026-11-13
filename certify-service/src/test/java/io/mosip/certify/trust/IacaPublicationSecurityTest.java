package io.mosip.certify.trust;

import io.mosip.certify.config.SecurityConfig;
import io.mosip.certify.core.config.LocalAuthenticationEntryPoint;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.signing.TrustAnchorRegistry;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * M-08 review round 1, item 6: the publication's security chain with the real chains active. The {@code test} profile
 * every {@code @SpringBootTest} here runs with drops {@code SecurityConfig} (and so every chain), so this context is
 * built without it: the service's {@code SecurityConfig} (everything authenticated but its ignore list), the
 * publication's chain ({@code GET}/{@code HEAD} only) and Spring Security's firewall, in front of the real controller
 * and a stand-in for the routes next to it.
 */
class IacaPublicationSecurityTest {

    static final String NEIGHBOUR = "neighbouring route reached";

    /** Routes next to the publication that the service's chain must keep protected. */
    @RestController
    static class Neighbours {
        @RequestMapping({"/mdoc", "/mdoc/other", "/mdoc/iaca-admin", "/mdoc/iacax.pem", "/v2/credential-configurations-admin"})
        String reached() {
            return NEIGHBOUR;
        }
    }

    @Configuration
    static class Anchors {
        @Bean
        TrustAnchorRegistry trustAnchorRegistry() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keys = generator.generateKeyPair();
            X509Certificate iaca = IsoMdocProfiles.iaca(keys).country("IN").commonName("Lorem Ipsum Security Test IACA")
                    .issuerAltUri("https://credentials.example.test").notBefore(Instant.now().minus(1, ChronoUnit.HOURS))
                    .crlDistributionPoint("https://credentials.example.test/v1/certify/mdoc/iaca/security-iaca.crl").build();
            List<TrustAnchorRegistry.Anchor> anchors = List.of(new TrustAnchorRegistry.Anchor("security-iaca", TrustAnchorRegistry.MDOC_IACA, iaca));
            return new TrustAnchorRegistry() {
                @Override
                public List<Anchor> entries(String purpose) {
                    return MDOC_IACA.equals(purpose) ? anchors : List.of();
                }

                @Override
                public Optional<X509CRL> crl(String anchorId) {
                    return Optional.empty();
                }
            };
        }
    }

    final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class,
                    WebMvcAutoConfiguration.class))
            .withUserConfiguration(Anchors.class, LocalAuthenticationEntryPoint.class, SecurityConfig.class,
                    IacaPublicationSecurityConfiguration.class, IacaPublicationController.class, Neighbours.class)
            .withPropertyValues(
                    "certify.pki.publication.enabled=true",
                    "server.servlet.path=/v1/certify",
                    // the publication is in none of the security lists (CLAUDE.md rule 9); {:} is SpEL's empty map, which the
                    // shipped {} becomes only through the full application's conversion service (SecurityConfig never reads them)
                    "mosip.certify.security.auth.post-urls={:}",
                    "mosip.certify.security.auth.put-urls={:}",
                    "mosip.certify.security.auth.get-urls={:}",
                    "mosip.certify.authn.jwk-set-uri=http://localhost:1/v1/certify/oauth/.well-known/jwks.json",
                    "mosip.certify.security.ignore-csrf-urls=**/actuator/**,/favicon.ico,**/error",
                    "mosip.certify.security.ignore-auth-urls=/actuator/**,**/error,**/swagger-ui/**,**/v3/api-docs/**");

    private void withMockMvc(ThrowingConsumer<MockMvc> test) {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            Filter chains = context.getBean("springSecurityFilterChain", Filter.class);
            MockMvc mockMvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context.getSourceApplicationContext())
                    .addFilters(chains).build();
            test.accept(mockMvc);
        });
    }

    interface ThrowingConsumer<T> {
        void accept(T value) throws Exception;
    }

    @Test
    void getAndHeadAreServedWithoutAuthentication() {
        withMockMvc(mockMvc -> {
            MvcResult list = mockMvc.perform(get("/mdoc/iaca")).andReturn();
            assertEquals(200, list.getResponse().getStatus(), list.getResponse().getContentAsString());
            assertTrue(list.getResponse().getContentAsString().contains("\"security-iaca\""));
            assertEquals(200, mockMvc.perform(get("/mdoc/iaca/security-iaca.pem")).andReturn().getResponse().getStatus());
            assertEquals(200, mockMvc.perform(get("/mdoc/iaca/security-iaca.der")).andReturn().getResponse().getStatus());
            assertEquals(200, mockMvc.perform(head("/mdoc/iaca")).andReturn().getResponse().getStatus());
            assertEquals(200, mockMvc.perform(head("/mdoc/iaca/security-iaca.pem")).andReturn().getResponse().getStatus());
            assertEquals(404, mockMvc.perform(get("/mdoc/iaca/security-iaca.crl")).andReturn().getResponse().getStatus(),
                    "no CRL: 404 from the controller, not a security refusal");
        });
    }

    @Test
    void everyOtherMethodIsRefused() {
        withMockMvc(mockMvc -> {
            for (MvcResult result : List.of(
                    mockMvc.perform(post("/mdoc/iaca")).andReturn(),
                    mockMvc.perform(post("/mdoc/iaca/security-iaca.pem")).andReturn(),
                    mockMvc.perform(put("/mdoc/iaca/security-iaca.pem")).andReturn(),
                    mockMvc.perform(delete("/mdoc/iaca/security-iaca.pem")).andReturn(),
                    mockMvc.perform(delete("/mdoc/iaca")).andReturn())) {
                // 403 from the publication's chain (denyAll), before Spring MVC could answer 405 for a GET-only mapping
                assertEquals(403, result.getResponse().getStatus(), result.getRequest().getMethod() + " "
                        + result.getRequest().getRequestURI());
            }
        });
    }

    @Test
    void pathTricksAreRefusedBeforeAnyController() {
        withMockMvc(mockMvc -> {
            for (String path : List.of("/mdoc/iaca/..%2f..%2fv2%2fcredential-configurations-admin",
                    "/mdoc/iaca/..%2Fsecurity-iaca.pem", "/mdoc/iaca/security-iaca.pem;jsessionid=x",
                    "/mdoc/iaca;x/security-iaca.pem", "/mdoc/iaca/%2e%2e/iaca-admin", "/mdoc/iaca/../iaca-admin")) {
                MvcResult result = mockMvc.perform(get(URI.create(path))).andReturn();
                assertEquals(400, result.getResponse().getStatus(), path + " answered " + result.getResponse().getStatus());
                assertFalse(result.getResponse().getContentAsString().contains(NEIGHBOUR), path);
            }
        });
    }

    @Test
    void theRoutesNextToThePublicationStayProtected() {
        withMockMvc(mockMvc -> {
            for (String path : List.of("/mdoc", "/mdoc/other", "/mdoc/iaca-admin", "/mdoc/iacax.pem", "/v2/credential-configurations-admin")) {
                MvcResult result = mockMvc.perform(get(path)).andReturn();
                assertFalse(result.getResponse().getContentAsString().contains(NEIGHBOUR),
                        path + " reached its controller without authentication (" + result.getResponse().getStatus() + ")");
                MvcResult posted = mockMvc.perform(post(path)).andReturn();
                assertFalse(posted.getResponse().getContentAsString().contains(NEIGHBOUR), "POST " + path);
            }
        });
    }
}
