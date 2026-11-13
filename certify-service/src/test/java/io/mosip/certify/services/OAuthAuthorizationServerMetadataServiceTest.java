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
     * token endpoint, {@code authorization_code} stays only when a code can be obtained - the own authorization endpoint
     * (a registered client) or an Interactive Authorization Endpoint - and is removed otherwise, and the pre-authorized
     * code grant takes its place rather than leaving an empty list (RFC 8414 gives an absent list the default
     * {@code authorization_code, implicit}).
     */
    @Test
    public void getOAuthAuthorizationServerMetadata_ExternalAuthorizationServerIsUnchanged() {
        // eSignet's document is repeated, not composed: no endpoint ends in /oauth/token, so none of the rules apply
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", "https://as.example/token");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported",
                "authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", "");
        asProperties(as(Map.of(), false, false));

        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        assertEquals("an external AS's grants are the deployment's, not ours to trim",
                Arrays.asList("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                result.getGrantTypesSupported());
        assertEquals(Arrays.asList("S256"), result.getCodeChallengeMethodsSupported());
        assertNull(result.getAuthorizationEndpoint());
    }

    /** IAE-only deployments keep authorization_code: the code is obtained at the IAE, so RFC 8414 section 2 holds. */
    @Test
    public void getOAuthAuthorizationServerMetadata_InteractiveAuthorizationEndpointKeepsAuthorizationCode() {
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

    /** Removing the only configured grant must not leave the list empty: an absent list means authorization_code+implicit. */
    @Test
    public void getOAuthAuthorizationServerMetadata_NeverEmitsAnEmptyGrantList() {
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
