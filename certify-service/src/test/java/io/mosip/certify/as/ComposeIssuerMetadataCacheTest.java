package io.mosip.certify.as;

import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cache.CacheManager;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mockingDetails;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The compose stack's caches, as the container configures them, keep pushed authorization requests off the database
 * (F-21 review round 2, GPT major 3): {@code AuthorizationCodeService} reads the scopes from the cached issuer-metadata
 * view ({@code CredentialRegistry}), and that view is only cached when {@code issuerMetadataCache} is configured. The
 * compose stack named no such cache, so every PAR ran {@code credential_config} {@code findAll()} and rebuilt the
 * metadata - 40 PARs, 40 loads.
 *
 * <p>{@code mosip.certify.cache.names}, {@code cache.size} and {@code cache.expire-in-seconds} come from the committed
 * compose files, merged and resolved the way the container loads them ({@link ComposeProperties}: default,
 * csvdp-farmer, rebuild, mdl, mdl-dev); everything else is the local test profile.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.as.clients.demo-wallet.redirect-uris[0]=" + ComposeIssuerMetadataCacheTest.REDIRECT,
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class ComposeIssuerMetadataCacheTest {

    static final String REDIRECT = "https://wallet.example/cb";
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    static final int PARS = 40;

    @DynamicPropertySource
    static void composeCaches(DynamicPropertyRegistry registry) throws Exception {
        Binder binder = ComposeProperties.binder(ComposeProperties.sources(Map.of("mosip.certify.domain.url", "https://example.org"),
                "default", "csvdp-farmer", "rebuild", "mdl", "mdl-dev"));
        for (String key : List.of("mosip.certify.cache.names", "mosip.certify.cache.size", "mosip.certify.cache.expire-in-seconds")) {
            String value = ComposeProperties.get(binder, key);
            assertNotNull(value, key);
            registry.add(key, () -> value);
        }
        registry.add("spring.cache.cache-names", () -> ComposeProperties.get(binder, "mosip.certify.cache.names"));
    }

    @Autowired MockMvc mockMvc;
    @Autowired CacheManager cacheManager;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @SpyBean CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @Test
    void repeatedPushedRequestsDoNotQueryTheConfigurations() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(AuthorizationCodeParLimitsTest.CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(
                    AuthorizationCodeParLimitsTest.config(AuthorizationCodeParLimitsTest.CONFIG_ID, AuthorizationCodeParLimitsTest.SCOPE));
        }
        assertEquals(201, push(), "warm-up: the first pushed request loads the view once");
        clearInvocations(credentialConfigRepository);

        for (int i = 0; i < PARS; i++) {
            assertEquals(201, push(), "pushed request " + i);
        }

        assertEquals(List.of(), mockingDetails(credentialConfigRepository).getInvocations().stream()
                        .map(invocation -> invocation.getMethod().getName()).toList(),
                PARS + " pushed requests made no credential_config query: the view came from issuerMetadataCache");
        assertNotNull(cacheManager.getCache("issuerMetadataCache"), "the compose stack names issuerMetadataCache");
    }

    private int push() throws Exception {
        return mockMvc.perform(post("/oauth/par").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", "demo-wallet").param("response_type", "code").param("redirect_uri", REDIRECT)
                        .param("code_challenge", challenge()).param("code_challenge_method", "S256")
                        .param("scope", AuthorizationCodeParLimitsTest.SCOPE))
                .andReturn().getResponse().getStatus();
    }

    private static String challenge() throws Exception {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
    }
}
