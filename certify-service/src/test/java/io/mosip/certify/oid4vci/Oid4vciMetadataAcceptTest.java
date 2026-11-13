package io.mosip.certify.oid4vci;

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
 * Credential Issuer Metadata and the media type it is returned with (OpenID4VCI 1.0 section 12.2.2): "The Credential
 * Issuer MUST support returning metadata in an unsigned form {@code application/json} and MAY support returning it in a
 * signed form {@code application/jwt}. In all cases the Credential Issuer MUST indicate the media type of the returned
 * Metadata using the HTTP Content-Type header."
 *
 * <p>This issuer has no signed form, so the one document is answered with {@code Content-Type: application/json} for
 * every {@code Accept} value - including the {@code application/jwt} a wallet may prefer (Talao asks for it) and
 * {@code text/html} - instead of a 406. The declarations used to be {@code produces = application/json} on the
 * mappings, which content negotiation turned into 406 on the {@code /oid4vci} surface and, on the
 * {@code /issuance/.well-known/...} alias (whose path routes errors through the {@code /issuance/} advice), into a 500.
 *
 * <p>The test runs on a database of its own. It used to share {@code jdbc:h2:mem:mosip_esignet} with every other test in
 * the JVM, and a row another test had seeded made the first and later responses differ (G32: the H2 test schema declares
 * the {@code TEXT[]} columns as {@code VARCHAR}, and the metadata read used to flush that representation back one
 * bracket level deeper). The read path is a read-only transaction now, but the test still owns its rows and its database,
 * so it cannot depend on what another test class wrote or on its order.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        // a database of this class's own: no row seeded by another test class can reach the document
        "spring.datasource.url=jdbc:h2:mem:accept-f17",
        // the path-tenant form of the same document: /t/{tenant}/oid4vci/.well-known/openid-credential-issuer
        "certify.tenancy.enabled=true",
        "certify.tenancy.resolver=path",
        "certify.tenancy.tenants.beta.issuer-did=did:web:beta.example",
        "certify.tenancy.tenants.beta.display[0].name=Beta Issuer",
        "certify.tenancy.tenants.beta.display[0].locale=en",
        "certify.tenancy.tenants.beta.authorization-servers[0]=http://beta.example/as",
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class Oid4vciMetadataAcceptTest {

    /** The {@code Accept} values a wallet or a browser may send; {@code null} is no {@code Accept} header at all. */
    static final List<String> ACCEPTS = java.util.Arrays.asList(null, "application/jwt", "text/html",
            "application/json", "*/*");

    static final String LDP_ID = "AcceptLdpCredential";
    static final String MDOC_ID = "AcceptMdlCredential";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;

    @BeforeEach
    void seed() throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(LDP_ID, "ldp_vc"));
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(MDOC_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config(MDOC_ID, "mso_mdoc"));
        }
    }

    @Test
    void theOneZeroDocumentIsJsonForEveryAccept() throws Exception {
        assertJsonForEveryAccept("/oid4vci/.well-known/openid-credential-issuer", "credential_issuer", true);
    }

    @Test
    void thePathTenantDocumentIsJsonForEveryAccept() throws Exception {
        assertJsonForEveryAccept("/t/beta/oid4vci/.well-known/openid-credential-issuer", "credential_issuer", true);
    }

    @Test
    void theDeprecatedIssuanceAliasIsJsonForEveryAcceptInsteadOfA500() throws Exception {
        // /issuance/.well-known/openid-credential-issuer used to answer 500 to application/jwt and text/html: the 406
        // raised by content negotiation was routed by ExceptionHandlerAdvice through the /issuance/ advice, whose
        // fallback is 500. It is the 0.14.0 document (the latest version) and now answers it like the root path does.
        assertJsonForEveryAccept("/issuance/.well-known/openid-credential-issuer", "credential_issuer", true);
    }

    /** HEAD is answered by the same handler with the same media type; it carries no body to compare. */
    @Test
    void headOnTheOneZeroDocumentIsJsonForEveryAccept() throws Exception {
        for (String path : List.of("/oid4vci/.well-known/openid-credential-issuer",
                "/t/beta/oid4vci/.well-known/openid-credential-issuer",
                "/issuance/.well-known/openid-credential-issuer")) {
            for (String accept : ACCEPTS) {
                MvcResult result = mockMvc.perform(headRequest(path, accept)).andReturn();
                String where = "HEAD " + path + " with Accept " + (accept == null ? "(absent)" : accept);
                assertEquals(200, result.getResponse().getStatus(), where);
                String contentType = result.getResponse().getContentType();
                assertTrue(contentType != null && contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE),
                        where + ": Content-Type is " + contentType);
            }
        }
    }

    /**
     * Asserts one document for all five {@code Accept} values: 200, {@code Content-Type: application/json}, a JSON
     * object carrying {@code requiredMember}, the same document as the {@code Accept: application/json} answer and, for
     * the metadata documents, byte-identical bodies.
     */
    private void assertJsonForEveryAccept(String path, String requiredMember, boolean byteIdentical) throws Exception {
        MvcResult jsonAccepted = mockMvc.perform(request(path, MediaType.APPLICATION_JSON_VALUE)).andReturn();
        if (!path.startsWith("/t/")) {
            assertTrue(jsonAccepted.getResponse().getContentAsString().contains(MDOC_ID),
                    "the test's own mso_mdoc row is in the document: " + path);
        }
        for (String accept : ACCEPTS) {
            MvcResult result = mockMvc.perform(request(path, accept)).andReturn();
            String where = path + " with Accept " + (accept == null ? "(absent)" : accept);
            assertEquals(200, result.getResponse().getStatus(), where + ": " + result.getResponse().getContentAsString());
            String contentType = result.getResponse().getContentType();
            assertTrue(contentType != null && contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE),
                    where + ": Content-Type is " + contentType);
            assertTrue(objectMapper.readTree(result.getResponse().getContentAsByteArray()).has(requiredMember),
                    where + " must be the document, not an error body: " + result.getResponse().getContentAsString());
            assertEquals(jsonAccepted.getResponse().getContentAsString(), result.getResponse().getContentAsString(),
                    where + " must return the document the application/json answer returns");
            if (byteIdentical) {
                assertArrayEquals(jsonAccepted.getResponse().getContentAsByteArray(), result.getResponse().getContentAsByteArray(),
                        where + " must return exactly the application/json bytes");
            }
        }
    }

    private static MockHttpServletRequestBuilder request(String path, String accept) {
        return withAccept(get(path), accept);
    }

    private static MockHttpServletRequestBuilder headRequest(String path, String accept) {
        return withAccept(head(path), accept);
    }

    private static MockHttpServletRequestBuilder withAccept(MockHttpServletRequestBuilder request, String accept) {
        return accept == null ? request : request.accept(MediaType.parseMediaType(accept));
    }

    private static CredentialConfigurationDTO config(String id, String format) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat(format);
        dto.setVcTemplate("dGVzdA==");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("accept_scope");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(id);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("family_name", "birth_date"));
        if ("mso_mdoc".equals(format)) {
            dto.setDocType("org.iso.18013.5.1.mDL");
            ClaimsDisplayFieldsConfigDTO claim = new ClaimsDisplayFieldsConfigDTO();
            dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1", Map.of("family_name", claim)));
        } else {
            dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
            dto.setCredentialTypes(List.of("VerifiableCredential", id));
            dto.setDisplayOrder(List.of("fullName"));
        }
        return dto;
    }
}
