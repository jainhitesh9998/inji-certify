package io.mosip.certify.as;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-17 review round 1 (m6): the authorization server document develop's compose stack serves is byte-identical before and
 * after the grant rules. Arguing it field by field is weaker than holding the whole document, so the expected JSON below
 * was produced by the implementation as it was on {@code 4f67ee7c} ({@code OAuthAuthorizationServerMetadataService}
 * before F-17) bound with these very properties - the files the compose stack activates
 * ({@code default, csvdp-farmer, rebuild} for {@code docker-compose.yaml} + {@code docker-compose.rebuild.yaml}) and the
 * environment it sets ({@code mosip_certify_domain_url=http://certify-nginx:80}):
 *
 * <pre>{@code
 * new ObjectMapper().writeValueAsString(preChangeService.getOAuthAuthorizationServerMetadata())
 * }</pre>
 *
 * <p>The deployment here is the one that keeps {@code authorization_code}: {@code certify-default.properties} configures
 * the Interactive Authorization Endpoint, which is the owner-approved compatibility interpretation of RFC 8414's
 * "no grant type uses the authorization endpoint" clause (docs/design/20-mdl-issuer.md G29).
 *
 * <p>Both literals were (re)produced the same way in F-17 review round 3: the {@code 4f67ee7c} source of
 * {@code OAuthAuthorizationServerMetadataService} ({@code git show 4f67ee7c:certify-service/src/main/java/io/mosip/certify/services/OAuthAuthorizationServerMetadataService.java})
 * compiled into the test tree under another name, given the field values {@link ComposeProperties#documentService}
 * binds for each property set, and serialised with a plain {@code ObjectMapper}; the throwaway copy was then deleted.
 */
class DevelopAsMetadataDocumentTest {

    /**
     * Whether the deployment's token endpoint is Certify's own, shown by behaviour: the same configuration listing only
     * {@code authorization_code}, with no client and no IAE, is rewritten to the pre-authorized grant only when own.
     */
    static boolean isOwn(Binder binder) {
        io.mosip.certify.services.OAuthAuthorizationServerMetadataService service = ComposeProperties.documentService(binder);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "grantTypesSupported", "authorization_code");
        org.springframework.test.util.ReflectionTestUtils.setField(service, "interactiveAuthorizationEndpoint", "");
        return !service.getOAuthAuthorizationServerMetadata().getGrantTypesSupported().contains("authorization_code");
    }

    /** Recorded from the {@code 4f67ee7c} implementation with the properties below (no golden file changed). */
    static final String DEVELOP_DOCUMENT = "{\"issuer\":\"http://certify-nginx:80\","
            + "\"token_endpoint\":\"http://certify-nginx:80/v1/certify/oauth/token\","
            + "\"jwks_uri\":\"http://certify-nginx:80/v1/certify/.well-known/jwks.json\","
            + "\"grant_types_supported\":[\"authorization_code\",\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],"
            + "\"response_types_supported\":[\"code\"],"
            + "\"code_challenge_methods_supported\":[\"S256\"],"
            + "\"dpop_signing_alg_values_supported\":[\"ES256\",\"ES384\",\"ES512\",\"RS256\",\"PS256\",\"EdDSA\"],"
            + "\"interactive_authorization_endpoint\":\"http://certify-nginx:80/v1/certify/oauth/iae\","
            + "\"require_interactive_authorization_request\":true}";

    /**
     * Plain {@code docker-compose.yaml} ({@code active_profile_env=default, csvdp-farmer}, no rebuild overlay): the
     * authorization server is {@code mosip.certify.authorization.url=https://esignet-mock.collab.mosip.net} from
     * {@code certify-default.properties}, and every URL of the document is built from it. Recorded from the
     * {@code 4f67ee7c} implementation with these properties.
     */
    static final String PLAIN_COMPOSE_DOCUMENT = "{\"issuer\":\"https://esignet-mock.collab.mosip.net\","
            + "\"token_endpoint\":\"https://esignet-mock.collab.mosip.net/v1/certify/oauth/token\","
            + "\"jwks_uri\":\"https://esignet-mock.collab.mosip.net/v1/certify/.well-known/jwks.json\","
            + "\"grant_types_supported\":[\"authorization_code\",\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],"
            + "\"response_types_supported\":[\"code\"],"
            + "\"code_challenge_methods_supported\":[\"S256\"],"
            + "\"dpop_signing_alg_values_supported\":[\"ES256\",\"ES384\",\"ES512\",\"RS256\",\"PS256\",\"EdDSA\"],"
            + "\"interactive_authorization_endpoint\":\"https://esignet-mock.collab.mosip.net/v1/certify/oauth/iae\","
            + "\"require_interactive_authorization_request\":true}";

    @Test
    void thePlainComposeDocumentIsByteIdentical() throws Exception {
        Binder binder = ComposeProperties.binder(ComposeProperties.sources(
                Map.of("mosip.certify.domain.url", "http://certify-nginx:80"), "default", "csvdp-farmer"));
        assertEquals("https://esignet-mock.collab.mosip.net", ComposeProperties.get(binder, "mosip.certify.authorization.url"));

        String document = ComposeProperties.document(ComposeProperties.documentService(binder));

        assertEquals(PLAIN_COMPOSE_DOCUMENT, document,
                "develop's plain compose document must not change (F-17 review round 2, m5)");
        // under the owner's identity-only rule (2026-11-13) this token endpoint is not Certify's own: it is on the
        // authorization server's host (esignet-mock), not on Certify's identity (http://certify-nginx:80), so the
        // document is served exactly as configured - which is the 4f67ee7c output above
        assertFalse(isOwn(binder), "the plain compose token endpoint is not Certify's identity + mount + /oauth/token");
    }

    @Test
    void theDevelopComposeDocumentIsByteIdentical() throws Exception {
        Binder binder = ComposeProperties.binder(ComposeProperties.sources(
                Map.of("mosip.certify.domain.url", "http://certify-nginx:80"), "default", "csvdp-farmer", "rebuild"));

        String document = ComposeProperties.document(ComposeProperties.documentService(binder));

        assertEquals(DEVELOP_DOCUMENT, document,
                "an unchanged deployment's authorization server metadata must not change (F-17 review round 1, m6)");
        // the rebuild overlay points the authorization server at Certify itself: own, and the grant rules keep the
        // document's bytes because certify-default.properties configures the IAE
        assertTrue(isOwn(binder), "the rebuild token endpoint is http://certify-nginx:80 + /v1/certify + /oauth/token");
    }
}
