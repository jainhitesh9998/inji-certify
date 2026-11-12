package io.mosip.certify.filter;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.dpop.DpopProofValidator;
import io.mosip.certify.oid4vci.Oid4vciAccessTokenFilter;
import io.mosip.certify.oid4vci.Oid4vciIssuer;
import io.mosip.certify.oid4vci.Oid4vciIssuerResolver;
import io.mosip.certify.tenancy.PathTenantResolver;
import io.mosip.certify.tenancy.TenancyProperties;
import io.mosip.certify.tenancy.TenantContexts;
import io.mosip.certify.tenancy.TenantResolutionFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The audience/issuer rule the OpenID4VCI 1.0 surface applies to an access token (M-09): a token addressed to this
 * surface's identifier or to its credential endpoint is accepted, one addressed elsewhere is not, and the same token is
 * refused by the compatibility filter, whose audiences are exactly the deployment's list. The validator under test is
 * the production one ({@link AccessTokenValidationFilter#tokenValidator()}), not a copy, with the decoder replaced by
 * one over a locally generated key so no JWK Set has to be fetched.
 */
class Oid4vciAccessTokenFilterTest {

    static final String ISSUER_IDENTIFIER = "https://issuer.example/v1/certify/oid4vci";
    static final String AS_ISSUER = "https://issuer.example/v1/certify";
    static final String LEGACY_AUDIENCE = "https://issuer.example/v1/certify/issuance/credential";
    static final String TENANT_A_SURFACE = AS_ISSUER + "/t/a/oid4vci";

    /** Path-resolved tenants {@code a} and {@code b}, each without an issuer override: {@code {deployment}/t/{id}/oid4vci}. */
    static final TenancyProperties TENANCY = new TenancyProperties(true, TenancyProperties.RESOLVER_PATH,
            Map.of("a", tenant(), "b", tenant()));

    private static TenancyProperties.Tenant tenant() {
        return new TenancyProperties.Tenant(List.of(), null, null, null, List.of(), List.of());
    }

    private KeyPair keys;
    private ParsedAccessToken parsedAccessToken;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        parsedAccessToken = new ParsedAccessToken();
    }

    @Test
    void aTokenAddressedToTheSurfaceCredentialEndpointIsAccepted() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        assertDoesNotThrow(() -> decode(filter, token(ISSUER_IDENTIFIER + "/credential")));
    }

    @Test
    void aTokenAddressedToTheSurfaceIdentifierIsAccepted() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        assertDoesNotThrow(() -> decode(filter, token(ISSUER_IDENTIFIER)));
    }

    @Test
    void theCompatibilityAudienceKeepsWorkingOnTheNewSurface() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        assertDoesNotThrow(() -> decode(filter, token(LEGACY_AUDIENCE)));
    }

    @Test
    void aTokenAddressedElsewhereIsRefused() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        assertThrows(JwtValidationException.class, () -> decode(filter, token("https://someone-else.example/credential")));
    }

    @Test
    void aTokenFromAnotherIssuerIsRefused() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        String foreign = signed(new JWTClaimsSet.Builder().issuer("https://other-as.example").audience(ISSUER_IDENTIFIER + "/credential")
                .subject("2154189532").claim("client_id", "").issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        assertThrows(JwtValidationException.class, () -> decode(filter, foreign));
    }

    @Test
    void theCompatibilityFilterDoesNotAcceptTheSurfaceAudience() throws Exception {
        AccessTokenValidationFilter legacy = new AccessTokenValidationFilter();
        prepare(legacy, parsedAccessToken);
        assertThrows(JwtValidationException.class, () -> decode(legacy, token(ISSUER_IDENTIFIER + "/credential")),
                "the legacy filter's audiences are exactly mosip.certify.authn.allowed-audiences");
    }

    /** The whole filter, not just the validator: an accepted token marks the request as authenticated. */
    @Test
    void theFilterAuthenticatesTheRequestWithTheSurfacesToken() throws Exception {
        Oid4vciAccessTokenFilter filter = oid4vciFilter();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vci/credential");
        request.setRequestURI("/oid4vci/credential");
        request.addHeader("Authorization", "Bearer " + token(ISSUER_IDENTIFIER + "/credential"));

        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> { });

        assertTrue(parsedAccessToken.isActive());
        AccessTokenValidationFilter asFilter = filter;
        assertFalse(asFilter.shouldNotFilter(request));
    }

    /**
     * The filter-level tenant rule: a token addressed to tenant {@code a}'s {@code /oid4vci} credential endpoint is
     * accepted only where tenant {@code a} is the resolved tenant. Tenant B's surface, the default surface and the
     * compatibility filter all refuse it; a token addressed to the default surface is refused at tenant A unless the
     * deployment lists that audience. Tenant resolution runs through the real {@link TenantResolutionFilter} and
     * {@link PathTenantResolver}, before the token filter, exactly as in production.
     *
     * <p>This is the rule the filter applies, not an offer flow: {@code /pre-authorized-data} and {@code /oauth/token}
     * have no {@code /t/{tenant}} mapping and the AS metadata publishes one token endpoint, so no offer token is minted
     * for a non-default tenant today (M-09 review round 2; decision log 2026-11-13). Tenant-aware offer and token
     * endpoints are deferred, and this test pins what the resource-server side will then be asked to accept.
     */
    @Test
    void aTokenAddressedToATenantsSurfaceIsAcceptedOnlyAtThatTenant() throws Exception {
        AuthorizationContext context = new AuthorizationContext();
        Oid4vciAccessTokenFilter filter = oid4vciFilter(context);
        TenantResolutionFilter tenants = new TenantResolutionFilter(new PathTenantResolver(TENANCY), context);

        String tenantAToken = token(TENANT_A_SURFACE + "/credential");
        assertTrue(run(tenants, filter, "/v1/certify/t/a/oid4vci/credential", tenantAToken),
                "tenant A's own surface accepts the token addressed to its credential endpoint");
        assertFalse(run(tenants, filter, "/v1/certify/oid4vci/credential", tenantAToken),
                "the default surface does not accept tenant A's token");
        assertFalse(run(tenants, filter, "/v1/certify/t/b/oid4vci/credential", tenantAToken),
                "tenant B does not accept tenant A's token");
        String defaultToken = token(ISSUER_IDENTIFIER + "/credential");
        assertFalse(run(tenants, filter, "/v1/certify/t/a/oid4vci/credential", defaultToken),
                "tenant A does not accept the default surface's token (it is not in mosip.certify.authn.allowed-audiences)");
        assertTrue(run(tenants, filter, "/v1/certify/oid4vci/credential", defaultToken),
                "the default surface still accepts its own token");
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    private Oid4vciAccessTokenFilter oid4vciFilter() {
        return oid4vciFilter(new AuthorizationContext());
    }

    private Oid4vciAccessTokenFilter oid4vciFilter(AuthorizationContext context) {
        Oid4vciAccessTokenFilter filter = new Oid4vciAccessTokenFilter();
        org.springframework.beans.factory.support.DefaultListableBeanFactory beans =
                new org.springframework.beans.factory.support.DefaultListableBeanFactory();
        beans.registerSingleton("oid4vciIssuerResolver",
                new Oid4vciIssuerResolver(new Oid4vciIssuer(ISSUER_IDENTIFIER), new TenantContexts(TENANCY)));
        beans.registerSingleton("authorizationContext", context);
        ReflectionTestUtils.setField(filter, "issuers", beans.getBeanProvider(Oid4vciIssuerResolver.class));
        ReflectionTestUtils.setField(filter, "authorizationContext", beans.getBeanProvider(AuthorizationContext.class));
        prepare(filter, parsedAccessToken);
        return filter;
    }

    /** Runs tenant resolution and then the token filter for one request, and answers whether the token was accepted. */
    private boolean run(TenantResolutionFilter tenants, Oid4vciAccessTokenFilter filter, String path, String token)
            throws Exception {
        parsedAccessToken.setActive(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setRequestURI(path);
        request.addHeader("Authorization", "Bearer " + token);
        tenants.doFilter(request, new MockHttpServletResponse(), (req, res) ->
                filter.doFilter((HttpServletRequest) req, (HttpServletResponse) res, (req2, res2) -> { }));
        return parsedAccessToken.isActive();
    }

    @SuppressWarnings("unchecked")
    private void prepare(AccessTokenValidationFilter filter, ParsedAccessToken parsed) {
        ReflectionTestUtils.setField(filter, "issuerUri", AS_ISSUER);
        ReflectionTestUtils.setField(filter, "allowedAudiences", List.of(LEGACY_AUDIENCE));
        ReflectionTestUtils.setField(filter, "urlPatterns", List.of("/issuance/credential"));
        ReflectionTestUtils.setField(filter, "parsedAccessToken", parsed);
        ReflectionTestUtils.setField(filter, "dpopProofValidator", new DpopProofValidator());
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) keys.getPublic()).build();
        decoder.setJwtValidator(filter.tokenValidator());
        ReflectionTestUtils.setField(filter, "nimbusJwtDecoder", decoder);
    }

    private Object decode(AccessTokenValidationFilter filter, String token) {
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) ReflectionTestUtils.getField(filter, "nimbusJwtDecoder");
        return decoder.decode(token);
    }

    private String token(String audience) throws Exception {
        return signed(new JWTClaimsSet.Builder().issuer(AS_ISSUER).audience(audience).subject("2154189532")
                .claim("client_id", "").claim("scope", "offer_surface_vc").issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
    }

    private String signed(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner(keys.getPrivate()));
        return jwt.serialize();
    }
}
