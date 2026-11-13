package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;

/**
 * The root-mapped OpenID4VCI 1.0 metadata (section 12.2.2 places it by inserting the well-known segment between host
 * and path) answers {@code application/json} for every {@code Accept}, GET and HEAD alike (G30, F-17 review round 2,
 * m4).
 *
 * <p>Certify is mounted under its servlet path and cannot answer a host-root URL itself; the proxy maps
 * {@code /.well-known/openid-credential-issuer/v1/certify/oid4vci} (and the {@code /t/<tenant>/} form) to the 1.0
 * handler ({@code docker-compose-injistack/certify-nginx.conf}, docs/design/15-deployment.md). This context therefore
 * serves those requests exactly as the proxy forwards them: the production servlet path {@code /v1/certify}
 * ({@code spring.mvc.servlet.path}, and requests dispatched with that servlet path rather than at the root as the other
 * MockMvc tests do), the forwarded {@code Host}, {@code X-Forwarded-Proto} and {@code X-Forwarded-For}, and the
 * request's method and {@code Accept} unchanged. That the proxy keeps the method and {@code Accept} and targets this path
 * is held by {@code docs/design/tools/check-public-guard.sh} on the real nginx file, and the whole chain by
 * {@code smoke.py --mdl} on a running stack.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        // a database of this class's own, and the mount point a deployment uses
        "spring.datasource.url=jdbc:h2:mem:accept-root-mapped-f17",
        "spring.mvc.servlet.path=/v1/certify",
        "certify.tenancy.enabled=true",
        "certify.tenancy.resolver=path",
        "certify.tenancy.tenants.beta.issuer-did=did:web:beta.example",
        "certify.tenancy.tenants.beta.display[0].name=Beta Issuer",
        "certify.tenancy.tenants.beta.display[0].locale=en",
        "certify.tenancy.tenants.beta.authorization-servers[0]=http://beta.example/as",
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/v1/certify/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class Oid4vciMetadataAcceptRootMappedTest {

    static final String SERVLET_PATH = "/v1/certify";
    static final String MDOC_ID = "RootMappedMdlCredential";

    /** The {@code Accept} values a wallet or a browser may send; {@code null} is no {@code Accept} header at all. */
    static final List<String> ACCEPTS = java.util.Arrays.asList(null, "application/jwt", "text/html", "application/json", "*/*");

    /**
     * Where the proxy sends each root-mapped URL ({@code certify-nginx.conf}): the root-mapped form of the default
     * tenant's identifier and of a path tenant's.
     */
    static final Map<String, String> ROOT_MAPPED = Map.of(
            "/.well-known/openid-credential-issuer/v1/certify/oid4vci", SERVLET_PATH + "/oid4vci/.well-known/openid-credential-issuer",
            "/.well-known/openid-credential-issuer/v1/certify/t/beta/oid4vci", SERVLET_PATH + "/t/beta/oid4vci/.well-known/openid-credential-issuer");

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void seed() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(mdoc());
        }
    }

    @Test
    void getIsTheSameJsonDocumentForEveryAccept() throws Exception {
        for (Map.Entry<String, String> mapping : ROOT_MAPPED.entrySet()) {
            MvcResult reference = mockMvc.perform(forwarded(get(mapping.getValue()), MediaType.APPLICATION_JSON_VALUE)).andReturn();
            JsonNode document = objectMapper.readTree(reference.getResponse().getContentAsByteArray());
            assertTrue(document.path("credential_issuer").asText().endsWith("/oid4vci"), mapping.getKey() + ": " + document);
            if (!mapping.getKey().contains("/t/")) {
                assertTrue(document.path("credential_configurations_supported").has(MDOC_ID),
                        "the test's own mso_mdoc row is in the document: " + document);
            }
            for (String accept : ACCEPTS) {
                MvcResult result = mockMvc.perform(forwarded(get(mapping.getValue()), accept)).andReturn();
                String where = "GET " + mapping.getKey() + " with Accept " + (accept == null ? "(absent)" : accept);
                assertEquals(200, result.getResponse().getStatus(), where + ": " + result.getResponse().getContentAsString());
                assertJson(where, result.getResponse().getContentType());
                assertArrayEquals(reference.getResponse().getContentAsByteArray(), result.getResponse().getContentAsByteArray(),
                        where + " must return exactly the application/json bytes");
            }
        }
    }

    /**
     * HEAD is answered by the GET handler with the GET representation's status and {@code Content-Type} (RFC 9110
     * section 9.3.2). MockMvc does not drop a HEAD body (the servlet container does), so the representation it shows is
     * compared with the GET one: the same document, not a different answer for HEAD.
     */
    @Test
    void headIsTheGetRepresentationForEveryAccept() throws Exception {
        for (Map.Entry<String, String> mapping : ROOT_MAPPED.entrySet()) {
            byte[] getBody = mockMvc.perform(forwarded(get(mapping.getValue()), MediaType.APPLICATION_JSON_VALUE))
                    .andReturn().getResponse().getContentAsByteArray();
            for (String accept : ACCEPTS) {
                MvcResult result = mockMvc.perform(forwarded(head(mapping.getValue()), accept)).andReturn();
                String where = "HEAD " + mapping.getKey() + " with Accept " + (accept == null ? "(absent)" : accept);
                assertEquals(200, result.getResponse().getStatus(), where);
                assertJson(where, result.getResponse().getContentType());
                assertArrayEquals(getBody, result.getResponse().getContentAsByteArray(), where + " is the GET representation");
            }
        }
    }

    private static void assertJson(String where, String contentType) {
        assertTrue(contentType != null && contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE),
                where + ": Content-Type is " + contentType);
    }

    /** The request as the proxy forwards it: servlet path, forwarded headers, method and {@code Accept} untouched. */
    private static MockHttpServletRequestBuilder forwarded(MockHttpServletRequestBuilder request, String accept) {
        request.servletPath(SERVLET_PATH)
                .header("Host", "credentials.example.org")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-For", "198.51.100.7");
        return accept == null ? request : request.accept(MediaType.parseMediaType(accept));
    }

    private static CredentialConfigurationDTO mdoc() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(MDOC_ID);
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("dGVzdA==");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("root_mapped_scope");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(MDOC_ID);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("family_name"));
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", new ClaimsDisplayFieldsConfigDTO())));
        return dto;
    }
}
