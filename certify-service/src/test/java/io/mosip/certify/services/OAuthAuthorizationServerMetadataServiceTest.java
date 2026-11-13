package io.mosip.certify.services;

import io.mosip.certify.as.AsProperties;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuthAuthorizationServerMetadataServiceTest {

    @InjectMocks
    private OAuthAuthorizationServerMetadataService oAuthAuthorizationServerMetadataService;

    private static final String TEST_ISSUER = "http://localhost:8090";
    private static final String TEST_TOKEN_ENDPOINT = "http://localhost:8090/v1/certify/oauth/token";
    private static final String TEST_JWKS_URI = "http://localhost:8090/v1/certify/oauth/.well-known/jwks.json";
    private static final String TEST_RESPONSE_TYPES = "code";
    private static final String TEST_GRANT_TYPES = "authorization_code";
    private static final String TEST_CODE_CHALLENGE_METHODS = "S256";
    private static final String TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT = "http://localhost:8090/v1/certify/oauth/iae";

    @Before
    public void setup() {
        // Set up the properties using ReflectionTestUtils
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "issuer", TEST_ISSUER);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", TEST_TOKEN_ENDPOINT);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "jwksUri", TEST_JWKS_URI);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", TEST_RESPONSE_TYPES);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", TEST_GRANT_TYPES);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", TEST_CODE_CHALLENGE_METHODS);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "requireInteractiveAuthorizationRequest", true);
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ShouldReturnCompleteMetadata() {
        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("OAuth Authorization Server metadata should not be null", result);
        assertEquals("Issuer should match", TEST_ISSUER, result.getIssuer());
        assertEquals("Token endpoint should match", TEST_TOKEN_ENDPOINT, result.getTokenEndpoint());
        assertEquals("Jwks Uri should match", TEST_JWKS_URI, result.getJwksUri());
        assertEquals("Interactive authorization endpoint should match", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT, result.getInteractiveAuthorizationEndpoint());
        assertTrue("Interactive authorization request should be required",
                Boolean.TRUE.equals(result.getRequireInteractiveAuthorizationRequest()));
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ShouldReturnCorrectArrayFields() {
        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedResponseTypes = List.of("code");
        assertEquals("Response types should match", expectedResponseTypes, result.getResponseTypesSupported());
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code");
        assertEquals("Grant types should match", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList("S256");
        assertEquals("Code challenge methods should match", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
        
        // Token endpoint auth methods are not implemented, so they should not be present in the DTO
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithEmptyProperties_ShouldReturnEmptyLists() {
        // Arrange - set empty properties
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Code challenge methods should be empty", result.getCodeChallengeMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithNullProperties_ShouldReturnEmptyLists() {
        // Arrange - set null properties
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", null);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", null);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", null);

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Code challenge methods should be empty", result.getCodeChallengeMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithSingleValues_ShouldReturnSingleItemLists() {
        // Arrange - set single values
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "S256");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Response types should have one item", 1, result.getResponseTypesSupported().size());
        assertEquals("Response type should be code", "code", result.getResponseTypesSupported().get(0));
        assertEquals("Grant types should have one item", 1, result.getGrantTypesSupported().size());
        assertEquals("Grant type should be authorization_code", "authorization_code", result.getGrantTypesSupported().get(0));
        assertEquals("Code challenge methods should have one item", 1, result.getCodeChallengeMethodsSupported().size());
        assertEquals("Code challenge method should be S256", "S256", result.getCodeChallengeMethodsSupported().get(0));
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithWhitespaceInCommaSeparatedValues_ShouldTrimValues() {
        // Arrange - set values with whitespace
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", " authorization_code ");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", " S256 ");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        // Note: The current implementation doesn't trim values, so we test the actual behavior
        List<String> expectedGrantTypes = Arrays.asList(" authorization_code ");
        assertEquals("Grant types should match (with whitespace)", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList(" S256 ");
        assertEquals("Code challenge methods should match (with whitespace)", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
    }

    /**
     * OID4VCI 1.0 section 12.3: the flag is about a Token Request that carries a pre-authorized code and no
     * {@code client_id}, so it does not depend on an authorization-code client being registered - but it is opt-in
     * ({@code certify.as.pre-authorized-grant.advertise-anonymous-access}, default off), because an unchanged deployment
     * has never published the field and its document must keep its exact bytes (goldens/legacy-0.14.0).
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_AnonymousGrantsAreNotAdvertisedByDefault() {
        asProperties(as(Map.of("wallet", new AsProperties.Client(List.of("https://wallet.example/cb"))), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertNull("the field is new: an unchanged deployment must not grow it",
                result.getPreAuthorizedGrantAnonymousAccessSupported());
        assertEquals("the rest of the document is unaffected", "http://localhost:8090/v1/certify/oauth/authorize",
                result.getAuthorizationEndpoint());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_PreAuthOnlyDeploymentAdvertisesAnonymousGrantsWhenEnabled() {
        asProperties(as(Map.of(), false, true));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertTrue("a deployment with no authorization-code clients still serves the pre-authorized grant",
                Boolean.TRUE.equals(result.getPreAuthorizedGrantAnonymousAccessSupported()));
        assertNull("the authorization code flow is still not advertised without a client", result.getAuthorizationEndpoint());
        assertNull(result.getPushedAuthorizationRequestEndpoint());
        assertNull(result.getRequirePushedAuthorizationRequests());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ClientAttestationDeploymentOmitsAnonymousGrants() {
        asProperties(as(Map.of(), true, true));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertNull("an anonymous token request is refused once attestation is required",
                result.getPreAuthorizedGrantAnonymousAccessSupported());
    }

    /** The pre-authorized grant is not in {@code grant_types_supported}, so there is nothing anonymous to advertise. */
    @Test
    public void getOAuthAuthorizationServerMetadata_GrantNotListedOmitsAnonymousGrants() {
        asProperties(as(Map.of(), false, true));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertNull(result.getPreAuthorizedGrantAnonymousAccessSupported());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ClientsAndAttestationAdvertiseBothFlows() {
        asProperties(as(Map.of("wallet", new AsProperties.Client(List.of("https://wallet.example/cb"))), false, true));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertTrue(Boolean.TRUE.equals(result.getPreAuthorizedGrantAnonymousAccessSupported()));
        assertEquals("http://localhost:8090/v1/certify/oauth/authorize", result.getAuthorizationEndpoint());
    }

    /**
     * Gap G29 (RFC 8414 section 2): the document advertises only what this server can complete. With Certify's own
     * token endpoint (an exact match against the URL built from its identity), {@code authorization_code} stays only
     * when a code can be obtained - the own authorization endpoint (a registered client) or the Interactive
     * Authorization Endpoint of the OpenID4VCI 1.1 editor's draft (docs/design/16-iae-audit.md) - and is removed
     * otherwise; the pre-authorized code grant takes its place rather than leaving an empty list (RFC 8414 gives an
     * absent list the default {@code authorization_code, implicit}).
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_ExternalAuthorizationServerIsUnchanged() throws Exception {
        // none of these is Certify's own token URL, so none of the grant rules applies - not even the exact-match test
        // with an identity configured, which is what makes eSignet's document safe
        for (String tokenEndpoint : List.of("https://esignet.example/v1/esignet/oauth/token", "https://idp.example/oauth/token")) {
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", tokenEndpoint);
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "authorizationUrl", "https://esignet.example");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", "https://idp.example");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", "/v1/certify");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                    "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "requireInteractiveAuthorizationRequest", true);
            asProperties(as(Map.of(), false, true));

            OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

            // exactly what a deployment configured: grants, PKCE and the IAE requirement are the deployment's, and the
            // endpoint it names nothing of is left out (@JsonInclude NON_EMPTY)
            String expected = "{\"issuer\":\"http://localhost:8090\","
                    + "\"token_endpoint\":\"" + tokenEndpoint + "\","
                    + "\"jwks_uri\":\"http://localhost:8090/v1/certify/oauth/.well-known/jwks.json\","
                    + "\"grant_types_supported\":[\"authorization_code\",\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],"
                    + "\"response_types_supported\":[\"code\"],"
                    + "\"code_challenge_methods_supported\":[\"S256\"],"
                    + "\"require_interactive_authorization_request\":true,"
                    + "\"pre-authorized_grant_anonymous_access_supported\":true}";
            assertEquals("an external AS's document must stay byte-identical: " + tokenEndpoint,
                    expected, new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result));
        }
    }

    /** The untrimmed reading of the external path stays, so an existing document keeps its exact bytes. */
    @Test
    public void getOAuthAuthorizationServerMetadata_ExternalGrantListKeepsItsWhitespace() {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", "https://idp.example/oauth/token");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals("the historical parser is unchanged for an external AS",
                Arrays.asList("authorization_code", " urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                result.getGrantTypesSupported());
    }

    /** The own token URL is an exact match; one trailing slash on either side is the same URL. */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnTokenEndpointIsMatchedExactly() {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", "http://localhost:8090/v1/certify/oauth/token/");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ownIdentity("http://localhost:8090/");
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals("the trailing slashes are the same own endpoint, so the grant rule applied",
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"), result.getGrantTypesSupported());
    }

    /** IAE-only deployments keep authorization_code: a code is obtainable at the IAE (compatibility interpretation). */
    @Test
    public void getOAuthAuthorizationServerMetadata_InteractiveAuthorizationEndpointKeepsAuthorizationCode() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(Arrays.asList("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                result.getGrantTypesSupported());
        assertNull("the code comes from the IAE, not from an authorization endpoint", result.getAuthorizationEndpoint());
        assertEquals(TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT, result.getInteractiveAuthorizationEndpoint());
        assertEquals(Boolean.TRUE, result.getRequireInteractiveAuthorizationRequest());
        assertEquals(Arrays.asList("S256"), result.getCodeChallengeMethodsSupported());
    }

    /** A registered client is the own authorization endpoint; authorization_code stays and is completable. */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnClientKeepsAuthorizationCodeWithItsEndpoint() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of("wallet", new AsProperties.Client(List.of("https://wallet.example/cb"))), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(Arrays.asList("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                result.getGrantTypesSupported());
        assertEquals("http://localhost:8090/v1/certify/oauth/authorize", result.getAuthorizationEndpoint());
        assertEquals(Arrays.asList("S256"), result.getCodeChallengeMethodsSupported());
    }

    /** Nothing can issue an authorization code: the grant is removed, and the pre-authorized grant stays. */
    @Test
    public void getOAuthAuthorizationServerMetadata_UncompletableAuthorizationCodeIsRemoved() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"), result.getGrantTypesSupported());
        assertNull("PKCE is only about the authorization code grant", result.getCodeChallengeMethodsSupported());
        assertNull(result.getAuthorizationEndpoint());
        assertNull(result.getInteractiveAuthorizationEndpoint());
    }

    /** The configured list is trimmed on the own path: a stray space must not keep an uncompletable grant. */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnGrantListIsTrimmed() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                " urn:ietf:params:oauth:grant-type:pre-authorized_code , authorization_code ");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"), result.getGrantTypesSupported());
    }

    /** Removing the only configured grant must not leave the list empty: an absent list means authorization_code+implicit. */
    @Test
    public void getOAuthAuthorizationServerMetadata_NeverEmitsAnEmptyGrantList() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"), result.getGrantTypesSupported());

        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "");
        assertEquals("an own token endpoint never publishes an empty (and therefore omitted) list",
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata().getGrantTypesSupported());
    }

    /** The requirement means nothing without the endpoint, so the two members are written together. */
    @Test
    public void getOAuthAuthorizationServerMetadata_InteractiveAuthorizationMembersArePaired() {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, false));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "requireInteractiveAuthorizationRequest", true);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code");

        OAuthAuthorizationServerMetadataDTO withoutEndpoint = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();
        assertNull(withoutEndpoint.getInteractiveAuthorizationEndpoint());
        assertNull("a requirement naming no endpoint is not published", withoutEndpoint.getRequireInteractiveAuthorizationRequest());

        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT);
        OAuthAuthorizationServerMetadataDTO withEndpoint = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();
        assertEquals(TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT, withEndpoint.getInteractiveAuthorizationEndpoint());
        assertEquals(Boolean.TRUE, withEndpoint.getRequireInteractiveAuthorizationRequest());
    }

    /**
     * The mDL demo stack ({@code certify-mdl.properties}): pre-authorized only, no registered client, no IAE. Its live
     * document is the issuer, token and JWKS endpoints, one grant, the response types, the DPoP algorithms and the
     * anonymous pre-authorized grant - and nothing that names a flow it does not serve.
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_MdlDemoIsPreAuthorizedOnly() throws Exception {
        ownIdentity(TEST_ISSUER);
        asProperties(as(Map.of(), false, true));
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "requireInteractiveAuthorizationRequest", false);

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals(List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"), result.getGrantTypesSupported());
        assertNull(result.getAuthorizationEndpoint());
        assertNull(result.getPushedAuthorizationRequestEndpoint());
        assertNull(result.getRequirePushedAuthorizationRequests());
        assertNull(result.getInteractiveAuthorizationEndpoint());
        assertNull(result.getRequireInteractiveAuthorizationRequest());
        assertNull(result.getCodeChallengeMethodsSupported());
        assertEquals(Boolean.TRUE, result.getPreAuthorizedGrantAnonymousAccessSupported());
        assertEquals("RFC 8414 section 2: REQUIRED", Arrays.asList("code"), result.getResponseTypesSupported());

        com.fasterxml.jackson.databind.JsonNode document = new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(result);
        java.util.Set<String> members = new java.util.TreeSet<>();
        document.fieldNames().forEachRemaining(members::add);
        assertEquals("nothing advertises a flow this stack does not serve: " + document,
                new java.util.TreeSet<>(List.of("issuer", "token_endpoint", "jwks_uri", "grant_types_supported",
                        "response_types_supported", "pre-authorized_grant_anonymous_access_supported")),
                members);
    }

    /**
     * F-17 review round 2, M2: the own token URL is matched under every servlet path Spring Boot accepts, normalised as
     * Boot does ({@code DispatcherServletPath#getPrefix}): {@code /} is the empty prefix and a trailing slash is dropped.
     * Each pair is a deployment whose token endpoint is its own; the grant rule must apply (the uncompletable
     * {@code authorization_code} goes), as it did not before for {@code /} and {@code /v1/certify/}.
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnEndpointUnderEveryServletPathForm() {
        String[][] cases = {
                {"", "https://credentials.example.org/oauth/token"},
                {"/", "https://credentials.example.org/oauth/token"},
                {"/v1/certify", "https://credentials.example.org/v1/certify/oauth/token"},
                {"/v1/certify/", "https://credentials.example.org/v1/certify/oauth/token"},
                {" /v1/certify/ ", "https://credentials.example.org/v1/certify/oauth/token/"},
        };
        for (String[] c : cases) {
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", "https://credentials.example.org");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", c[0]);
            assertOwn("server.servlet.path '" + c[0] + "', token " + c[1], c[1]);
        }
    }

    /** Where Boot actually mounted the DispatcherServlet ({@code spring.mvc.servlet.path}) is a prefix too. */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnEndpointUnderTheMountedDispatcherServletPath() {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", "https://credentials.example.org");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", null);
        dispatcherServletPath("/v1/certify/");
        assertOwn("spring.mvc.servlet.path /v1/certify/", "https://credentials.example.org/v1/certify/oauth/token");
    }

    /** {@code server.servlet.context-path} comes before the servlet path, normalised as Boot binds it. */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnEndpointUnderAContextPath() {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", "https://credentials.example.org");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", "/v1/certify");
        org.springframework.boot.autoconfigure.web.ServerProperties server = new org.springframework.boot.autoconfigure.web.ServerProperties();
        server.getServlet().setContextPath("/issuer/");
        org.springframework.beans.factory.support.DefaultListableBeanFactory beans =
                new org.springframework.beans.factory.support.DefaultListableBeanFactory();
        beans.registerSingleton("serverProperties", server);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "serverProperties",
                beans.getBeanProvider(org.springframework.boot.autoconfigure.web.ServerProperties.class));
        assertOwn("context path /issuer/", "https://credentials.example.org/issuer/v1/certify/oauth/token");
    }

    /**
     * F-17 review round 2, m3: every base the deployment names - {@code mosip.certify.identifier} (also written with the
     * servlet path, as the test profile does), {@code mosip.certify.oauth.issuer}, a comma-separated
     * {@code mosip.certify.authorization.url} - identifies the own endpoint on its own.
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_OwnEndpointFromEachBase() {
        String token = "https://credentials.example.org/v1/certify/oauth/token";
        String[][] bases = {
                {"identifier", "https://credentials.example.org"},
                {"identifier", "https://credentials.example.org/v1/certify"},
                {"issuer", "https://credentials.example.org/"},
                {"authorizationUrl", "https://other.example, https://credentials.example.org/"},
                {"domainUrl", "https://credentials.example.org"},
        };
        for (String[] base : bases) {
            for (String field : List.of("identifier", "issuer", "authorizationUrl", "domainUrl")) {
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, field, null);
            }
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, base[0], base[1]);
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", "/v1/certify");
            assertOwn(base[0] + "=" + base[1], token);
        }
    }

    /**
     * No false positive under any servlet path: eSignet's and a root-mounted AS's documents stay exactly as configured,
     * even with {@code mosip.certify.authorization.url} and {@code mosip.certify.oauth.issuer} naming that AS. With an
     * empty prefix {@code <AS base>/oauth/token} is any AS's token path, so only Certify's own origin
     * ({@code domain.url}, {@code identifier}) may claim it there.
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_ExternalAuthorizationServerUnchangedUnderEveryServletPath() throws Exception {
        String[][] externals = {
                {"https://esignet.example", "https://esignet.example/v1/esignet/oauth/token"},
                {"https://idp.example", "https://idp.example/oauth/token"},
        };
        for (String servletPath : java.util.Arrays.asList(null, "", "/", "/v1/certify", "/v1/certify/")) {
            for (String[] external : externals) {
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", external[1]);
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "issuer", external[0]);
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "authorizationUrl", external[0]);
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", "https://credentials.example.org");
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "identifier", "https://credentials.example.org");
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", servletPath);
                dispatcherServletPath(servletPath == null ? "" : servletPath);
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                        "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
                ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "requireInteractiveAuthorizationRequest", true);
                asProperties(as(Map.of(), false, false));

                String expected = "{\"issuer\":\"" + external[0] + "\","
                        + "\"token_endpoint\":\"" + external[1] + "\","
                        + "\"jwks_uri\":\"http://localhost:8090/v1/certify/oauth/.well-known/jwks.json\","
                        + "\"grant_types_supported\":[\"authorization_code\",\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],"
                        + "\"response_types_supported\":[\"code\"],"
                        + "\"code_challenge_methods_supported\":[\"S256\"],"
                        + "\"require_interactive_authorization_request\":true}";
                assertEquals("servlet path " + servletPath + ", external AS " + external[1], expected,
                        new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
                                oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata()));
            }
        }
    }

    /**
     * F-17 review round 2, m3: a token endpoint that ends in {@code <prefix>/oauth/token} but matches no base is served
     * as configured, and said once - not on every metadata request.
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_UnmatchedOwnLookingEndpointIsReportedOnce() {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(OAuthAuthorizationServerMetadataService.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", "https://typo.example/v1/certify/oauth/token");
            ownIdentity("https://credentials.example.org");
            asProperties(as(Map.of(), false, false));
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
            ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");

            for (int i = 0; i < 3; i++) {
                assertEquals("not matched, so served as configured", List.of("authorization_code"),
                        oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata().getGrantTypesSupported());
            }

            List<ch.qos.logback.classic.spi.ILoggingEvent> warnings = appender.list.stream()
                    .filter(e -> e.getLevel() == ch.qos.logback.classic.Level.WARN).toList();
            assertEquals("one WARN for three builds: " + warnings, 1, warnings.size());
            assertTrue(warnings.get(0).getFormattedMessage().contains("https://typo.example/v1/certify/oauth/token"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    /** Builds with {@code authorization_code} only and no way to complete it: the own endpoint drops it. */
    private void assertOwn(String where, String tokenEndpoint) {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", tokenEndpoint);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");
        asProperties(as(Map.of(), false, false));
        assertEquals(where + ": Certify's own token endpoint, so the uncompletable grant goes",
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata().getGrantTypesSupported());
    }

    private void dispatcherServletPath(String path) {
        org.springframework.beans.factory.support.DefaultListableBeanFactory beans =
                new org.springframework.beans.factory.support.DefaultListableBeanFactory();
        beans.registerSingleton("dispatcherServletPath", (org.springframework.boot.autoconfigure.web.servlet.DispatcherServletPath) () -> path);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "dispatcherServletPath",
                beans.getBeanProvider(org.springframework.boot.autoconfigure.web.servlet.DispatcherServletPath.class));
    }

    /** The deployment's own identity, the base `mosip.certify.oauth.token-endpoint` is built from. */
    private void ownIdentity(String base) {
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "authorizationUrl", base);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "domainUrl", base);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "servletPath", "/v1/certify");
    }

    private void asProperties(AsProperties properties) {
        org.springframework.beans.factory.support.DefaultListableBeanFactory beans =
                new org.springframework.beans.factory.support.DefaultListableBeanFactory();
        beans.registerSingleton("asProperties", properties);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "asProperties",
                beans.getBeanProvider(AsProperties.class));
    }

    private static AsProperties as(Map<String, AsProperties.Client> clients, boolean attestationRequired, boolean advertiseAnonymousAccess) {
        return new AsProperties(clients, new AsProperties.Authorization("none", null),
                new AsProperties.Par(Duration.ofSeconds(90)),
                new AsProperties.ClientAttestation(attestationRequired, Map.of(), Duration.ofSeconds(60), Duration.ofMinutes(5)),
                new AsProperties.PreAuthorizedGrant(advertiseAnonymousAccess));
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithMultipleValues_ShouldParseCorrectly() {
        // Arrange - set multiple values
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "S256");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code");
        assertEquals("Grant types should be parsed correctly", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedResponseTypes = Arrays.asList("code");
        assertEquals("Response types should be parsed correctly", expectedResponseTypes, result.getResponseTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList("S256");
        assertEquals("Code challenge methods should be parsed correctly", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
    }
}
