package io.mosip.certify.as;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mDL demo stack's authorization server as it is configured and served (gaps G29 and G30): pre-authorized only. It
 * registers no client of Certify's own AS, so the document has no {@code authorization_endpoint} and no PAR; it lists
 * the one grant its token endpoint completes, keeps the Interactive Authorization Endpoint of the farmer profiles out,
 * and advertises the anonymous pre-authorized grant the offer page relies on.
 *
 * <p>The sources are merged the way Spring Boot loads them, with the precedence the container actually has: the
 * environment on top ({@code mosip_certify_domain_url} from the overlay), then the profile files in the order
 * {@code docker-compose.yaml}, {@code docker-compose.rebuild.yaml} and {@code docker-compose.mdl.yaml} activate them -
 * {@code default, csvdp-farmer, rebuild, mdl, <MDL_PKI_PROFILE>} - a later file overriding an earlier one, with
 * placeholders resolved across the merge. The resolved values are fed into the real
 * {@link io.mosip.certify.services.OAuthAuthorizationServerMetadataService}, and the whole document it serialises is
 * held, for both PKI profiles (they set no authorization server property, so their documents must be the same).
 */
class MdlAuthorizationServerPropertiesTest {

    /** The one value the overlay supplies from outside (`CERTIFY_PUBLIC_URL` -> `mosip_certify_domain_url`). */
    static final String PUBLIC_URL = "https://credentials.example.org";
    static final String PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    /** The document the mDL stack serves: one grant, no endpoint of a flow it does not have. */
    static final String MDL_DOCUMENT = "{\"issuer\":\"" + PUBLIC_URL + "\","
            + "\"token_endpoint\":\"" + PUBLIC_URL + "/v1/certify/oauth/token\","
            + "\"jwks_uri\":\"" + PUBLIC_URL + "/v1/certify/.well-known/jwks.json\","
            + "\"grant_types_supported\":[\"" + PRE_AUTHORIZED + "\"],"
            + "\"response_types_supported\":[\"code\"],"
            + "\"dpop_signing_alg_values_supported\":[\"ES256\",\"ES384\",\"ES512\",\"RS256\",\"PS256\",\"EdDSA\"],"
            + "\"pre-authorized_grant_anonymous_access_supported\":true}";

    @Test
    void bothPkiProfilesServeThePreAuthorizedOnlyDocument() throws Exception {
        for (String pki : new String[]{"mdl-dev", "mdl-operator"}) {
            Binder binder = profile(pki);

            // what the files say, resolved with the real precedence
            assertEquals(PRE_AUTHORIZED, ComposeProperties.get(binder, "mosip.certify.oauth.grant-types-supported"),
                    pki + ": the one grant this stack can complete");
            assertEquals("", ComposeProperties.get(binder, "mosip.certify.oauth.interactive-authorization-endpoint"),
                    pki + ": the IAE of the farmer profiles stays off");
            assertEquals("false", ComposeProperties.get(binder, "mosip.certify.oauth.require-interactive-authorization-request"));
            assertEquals("true", ComposeProperties.get(binder, "certify.as.pre-authorized-grant.advertise-anonymous-access"),
                    pki + ": the offer flow is anonymous (OID4VCI 1.0 section 12.3)");

            AsProperties as = binder.bind("certify.as", org.springframework.boot.context.properties.bind.Bindable.of(AsProperties.class)).get();
            assertFalse(as.enabled(), pki + ": no client of Certify's own AS is registered: " + as.clients());
            assertTrue(as.clients() == null || as.clients().isEmpty(), pki + ": " + as.clients());

            String document = ComposeProperties.document(ComposeProperties.documentService(binder));
            assertEquals(MDL_DOCUMENT, document, pki + ": the live authorization server document");
        }
    }

    @Test
    void noPkiProfileOrOverlayAddsAnAuthorizationEndpoint() throws Exception {
        for (String pki : new String[]{"mdl-dev", "mdl-operator"}) {
            Binder binder = profile(pki);
            String document = ComposeProperties.document(ComposeProperties.documentService(binder));
            assertFalse(document.contains("authorization_endpoint"), pki + ": " + document);
            assertFalse(document.contains("pushed_authorization_request_endpoint"), pki + ": " + document);
            assertFalse(document.contains("interactive_authorization_endpoint"), pki + ": " + document);
            assertFalse(document.contains("require_interactive_authorization_request"), pki + ": " + document);
            assertFalse(document.contains("code_challenge_methods_supported"), pki + ": " + document);
        }
    }

    /** default, csvdp-farmer, rebuild, mdl then the PKI profile, as docker-compose.mdl.yaml sets active_profile_env. */
    private static Binder profile(String pki) throws Exception {
        return ComposeProperties.binder(ComposeProperties.sources(Map.of("mosip.certify.domain.url", PUBLIC_URL),
                "default", "csvdp-farmer", "rebuild", "mdl", pki));
    }
}
