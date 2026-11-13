package io.mosip.certify.configv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.oid4vci.TenantIssuerMetadata;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.services.CredentialRegistryImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * F-10 review round 2, items 1 and 5: every configuration write, v1 and v2, add, update and delete, clears both entries
 * the issuer-metadata cache holds (the compatibility metadata and the default tenant's {@code /oid4vci} claim orders), so
 * the next read of either document shows the write; and it clears them again once the transaction has committed, so a
 * reader that cached the rows the transaction was replacing does not keep them. Same context as
 * {@link CredentialConfigurationV2Test} (same annotations, same mock), so no second application context is started.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:uuid:",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class CredentialConfigurationCacheEvictionTest {

    static final String V1_ID = "V1CacheCredential";
    static final String V2_ID = "V2CacheCredential";
    static final String V2_PATH = "/v2/credential-configurations";
    static final String OID4VCI = "/oid4vci/.well-known/openid-credential-issuer";
    static final String LEGACY = "/.well-known/openid-credential-issuer";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigRepository configurations;
    @Autowired CredentialConfigurationService v1;
    @Autowired CacheManager cacheManager;
    @Autowired PlatformTransactionManager transactions;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    @AfterEach
    void clean() {
        for (String id : List.of(V1_ID, V2_ID)) {
            configurations.findByTenantIdAndCredentialConfigKeyId("default", id).ifPresent(configurations::delete);
        }
        cache().clear();
    }

    @Test
    void v1AddUpdateAndDeleteEachClearBothEntries() throws Exception {
        warm();
        v1.addCredentialConfiguration(v1Config("V1 Cache Credential", List.of("fullName", "dateOfBirth", "city")));
        assertCleared("v1 add");
        assertEquals("V1 Cache Credential", legacyName(V1_ID));
        assertEquals(List.of("fullName", "dateOfBirth", "city"), oid4vciClaimOrder(V1_ID));

        warm();
        v1.updateCredentialConfiguration(V1_ID, v1Config("V1 Cache Credential, renamed", List.of("city", "fullName", "dateOfBirth")));
        assertCleared("v1 update");
        assertEquals("V1 Cache Credential, renamed", legacyName(V1_ID), "the compatibility metadata shows the update");
        assertEquals("V1 Cache Credential, renamed", oid4vciName(V1_ID), "the /oid4vci metadata shows the update");
        assertEquals(List.of("city", "fullName", "dateOfBirth"), oid4vciClaimOrder(V1_ID), "the /oid4vci claim order shows the update");

        warm();
        v1.deleteCredentialConfigurationById(V1_ID);
        assertCleared("v1 delete");
        assertFalse(document(LEGACY).path("credential_configurations_supported").has(V1_ID));
        assertFalse(document(OID4VCI).path("credential_configurations_supported").has(V1_ID));
    }

    @Test
    void v2AddUpdateAndDeleteEachClearBothEntries() throws Exception {
        warm();
        assertEquals(201, call(post(V2_PATH), v2Body("V2 Cache Credential", List.of("fullName", "dateOfBirth", "city"))).getResponse().getStatus());
        assertCleared("v2 add");
        assertEquals("V2 Cache Credential", legacyName(V2_ID));
        assertEquals(List.of("fullName", "dateOfBirth", "city"), oid4vciClaimOrder(V2_ID));

        warm();
        MvcResult updated = call(put(V2_PATH + "/" + V2_ID), v2Body("V2 Cache Credential, renamed", List.of("city", "dateOfBirth", "fullName")));
        assertEquals(200, updated.getResponse().getStatus(), updated.getResponse().getContentAsString());
        assertCleared("v2 update");
        assertEquals("V2 Cache Credential, renamed", legacyName(V2_ID));
        assertEquals("V2 Cache Credential, renamed", oid4vciName(V2_ID));
        assertEquals(List.of("city", "dateOfBirth", "fullName"), oid4vciClaimOrder(V2_ID));

        warm();
        assertEquals(204, mockMvc.perform(delete(V2_PATH + "/" + V2_ID)).andReturn().getResponse().getStatus());
        assertCleared("v2 delete");
        assertFalse(document(LEGACY).path("credential_configurations_supported").has(V2_ID));
        assertFalse(document(OID4VCI).path("credential_configurations_supported").has(V2_ID));
    }

    /**
     * Item 5: a reader that runs between the write's own eviction and its commit caches what the transaction is replacing;
     * the eviction after commit removes it.
     */
    @Test
    void entriesCachedBeforeTheCommitAreClearedAfterIt() throws Exception {
        v1.addCredentialConfiguration(v1Config("V1 Cache Credential", List.of("fullName", "dateOfBirth", "city")));
        CredentialConfigurationDTO renamed = v1Config("V1 Cache Credential, renamed", List.of("city", "fullName", "dateOfBirth"));
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            try {
                v1.updateCredentialConfiguration(V1_ID, renamed);
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
            assertCleared("evicted at once");
            // a concurrent reader, which still sees the committed rows, caches the documents built from them
            cache().put(CredentialRegistryImpl.KEY, "metadata built from the rows before the commit");
            cache().put(TenantIssuerMetadata.DEFAULT_CLAIM_ORDERS_KEY, Map.of(V1_ID, List.of("fullName", "dateOfBirth", "city")));
        });
        assertCleared("evicted again after the commit");
        assertEquals(List.of("city", "fullName", "dateOfBirth"), oid4vciClaimOrder(V1_ID));
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private Cache cache() {
        Cache cache = cacheManager.getCache(CredentialRegistry.CACHE_NAME);
        assertNotNull(cache, "the issuer-metadata cache is configured in the local profile");
        return cache;
    }

    /** Reads both documents, so both cache entries are present. */
    private void warm() throws Exception {
        document(LEGACY);
        document(OID4VCI);
        assertNotNull(cache().get(CredentialRegistryImpl.KEY), "compatibility metadata cached");
        assertNotNull(cache().get(TenantIssuerMetadata.DEFAULT_CLAIM_ORDERS_KEY), "/oid4vci claim orders cached");
    }

    private void assertCleared(String after) {
        assertNull(cache().get(CredentialRegistryImpl.KEY), after + ": compatibility metadata evicted");
        assertNull(cache().get(TenantIssuerMetadata.DEFAULT_CLAIM_ORDERS_KEY), after + ": /oid4vci claim orders evicted");
    }

    private JsonNode document(String path) throws Exception {
        MvcResult result = mockMvc.perform(get(path)).andReturn();
        assertEquals(200, result.getResponse().getStatus(), path);
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String legacyName(String id) throws Exception {
        JsonNode configuration = document(LEGACY).path("credential_configurations_supported").path(id);
        assertTrue(configuration.isObject(), id + " in the compatibility metadata");
        return configuration.path("credential_metadata").path("display").path(0).path("name").asText();
    }

    private String oid4vciName(String id) throws Exception {
        return document(OID4VCI).path("credential_configurations_supported").path(id)
                .path("credential_metadata").path("display").path(0).path("name").asText();
    }

    /** The claim names of {@code credential_metadata.claims} in the order served. */
    private List<String> oid4vciClaimOrder(String id) throws Exception {
        JsonNode claims = document(OID4VCI).path("credential_configurations_supported").path(id).path("credential_metadata").path("claims");
        assertTrue(claims.isArray() && !claims.isEmpty(), id + " has claims in the /oid4vci metadata: " + claims);
        List<String> names = new ArrayList<>();
        claims.forEach(claim -> names.add(claim.path("path").path(claim.path("path").size() - 1).asText()));
        return names;
    }

    private MvcResult call(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, Object body) throws Exception {
        return mockMvc.perform(request.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
    }

    private static CredentialConfigurationDTO v1Config(String name, List<String> order) throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(V1_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(CredentialConfigurationV2Test.template(V1_ID).getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", V1_ID));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("cache_v1_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(name);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(order);
        dto.setClaims(Map.of("fullName", claim("Full name"), "dateOfBirth", claim("Date of birth"), "city", claim("City")));
        return dto;
    }

    private static ClaimsDTO claim(String name) {
        ClaimsDTO.Display display = new ClaimsDTO.Display();
        display.setName(name);
        display.setLocale("en");
        ClaimsDTO claims = new ClaimsDTO();
        claims.setDisplay(List.of(display));
        return claims;
    }

    private static Map<String, Object> v2Body(String name, List<String> order) throws Exception {
        Map<String, Object> body = CredentialConfigurationV2Test.body(V2_ID, CredentialConfigurationV2Test.template(V2_ID));
        body.put("scope", "cache_v2_ldp");
        @SuppressWarnings("unchecked")
        Map<String, Object> formatConfig = (Map<String, Object>) body.get("formatConfig");
        Map<String, Object> claims = new LinkedHashMap<>();
        for (String claim : List.of("fullName", "dateOfBirth", "city")) {
            claims.put(claim, Map.of("display", List.of(Map.of("name", claim, "locale", "en"))));
        }
        formatConfig.put("claims", claims);
        body.put("display", Map.of("display", List.of(Map.of("name", name, "locale", "en")), "order", order));
        return body;
    }
}
