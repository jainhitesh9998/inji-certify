package io.mosip.certify.as;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mDL demo stack's authorization server as it is configured and served (F-21, decision log 2026-11-13): the
 * pre-authorized grant the offer flow uses next to Certify's own authorization code flow ({@code P3-05}). One client is
 * registered ({@code demo-wallet}, redirecting to the public offer page), so the document carries
 * {@code authorization_endpoint}, {@code pushed_authorization_request_endpoint} and
 * {@code require_pushed_authorization_requests} and lists both grants - which is what a wallet that looks for an
 * authorization endpoint even on a pre-authorized offer (Talao) needs (gap G29). The subject mode is left at its
 * default {@code none}: the flow is advertised, no code is issued.
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

    /** The document the mDL stack serves: the code flow it now advertises and the pre-authorized grant it issues on. */
    static final String MDL_DOCUMENT = "{\"issuer\":\"" + PUBLIC_URL + "\","
            + "\"token_endpoint\":\"" + PUBLIC_URL + "/v1/certify/oauth/token\","
            + "\"jwks_uri\":\"" + PUBLIC_URL + "/v1/certify/.well-known/jwks.json\","
            + "\"grant_types_supported\":[\"authorization_code\",\"" + PRE_AUTHORIZED + "\"],"
            + "\"response_types_supported\":[\"code\"],"
            + "\"code_challenge_methods_supported\":[\"S256\"],"
            + "\"dpop_signing_alg_values_supported\":[\"ES256\",\"ES384\",\"ES512\",\"RS256\",\"PS256\",\"EdDSA\"],"
            + "\"token_endpoint_auth_methods_supported\":[\"none\"],"
            + "\"authorization_endpoint\":\"" + PUBLIC_URL + "/v1/certify/oauth/authorize\","
            + "\"pushed_authorization_request_endpoint\":\"" + PUBLIC_URL + "/v1/certify/oauth/par\","
            + "\"require_pushed_authorization_requests\":true,"
            + "\"pre-authorized_grant_anonymous_access_supported\":true}";

    @Test
    void bothPkiProfilesServeTheCodeFlowAndPreAuthorizedDocument() throws Exception {
        for (String pki : new String[]{"mdl-dev", "mdl-operator"}) {
            Binder binder = profile(pki);

            // what the files say, resolved with the real precedence
            assertEquals("authorization_code," + PRE_AUTHORIZED,
                    ComposeProperties.get(binder, "mosip.certify.oauth.grant-types-supported"),
                    pki + ": the two grants this stack completes");
            assertEquals("", ComposeProperties.get(binder, "mosip.certify.oauth.interactive-authorization-endpoint"),
                    pki + ": the IAE of the farmer profiles stays off");
            assertEquals("false", ComposeProperties.get(binder, "mosip.certify.oauth.require-interactive-authorization-request"));
            assertEquals("true", ComposeProperties.get(binder, "certify.as.pre-authorized-grant.advertise-anonymous-access"),
                    pki + ": the offer flow is anonymous (OID4VCI 1.0 section 12.3)");
            // one registered client, redirecting to the offer page on the public URL, built as the file's other
            // public URLs are (mosip.certify.domain.url + the servlet path)
            assertEquals(PUBLIC_URL + "/v1/certify/offer/",
                    ComposeProperties.get(binder, "certify.as.clients.demo-wallet.redirect-uris[0]"),
                    pki + ": the client's only redirect URI is the public offer page");

            AsProperties as = binder.bind("certify.as", Bindable.of(AsProperties.class)).get();
            assertTrue(as.enabled(), pki + ": the code flow is on: " + as.clients());
            assertEquals(List.of("demo-wallet"), List.copyOf(as.clients().keySet()), pki + ": exactly one client");
            // `none` is the default and what this profile must keep (the demo is public: a fixed subject would hand
            // one synthetic holder's mDL to anyone)
            assertEquals(AsProperties.SUBJECT_MODE_NONE, as.authorization().subjectMode(), pki + ": subject mode, never fixed");
            assertNull(as.authorization().fixedSubject(), pki + ": no fixed subject");

            // the client is public (a redirect URI, no secret): RFC 8414 section 2 would read an absent list as
            // client_secret_basic, which this deployment has nothing to authenticate with
            assertTrue(as.clientAttestation() == null || as.clientAttestation().attesters() == null
                    || as.clientAttestation().attesters().isEmpty(), pki + ": no attester configured");
            String document = ComposeProperties.document(ComposeProperties.documentService(binder));
            assertTrue(document.contains("\"token_endpoint_auth_methods_supported\":[\"none\"]"), pki + ": " + document);
            assertEquals(MDL_DOCUMENT, document, pki + ": the live authorization server document");
        }
    }

    @Test
    void theDocumentCarriesNoInteractiveAuthorizationEndpointMembers() throws Exception {
        for (String pki : new String[]{"mdl-dev", "mdl-operator"}) {
            Binder binder = profile(pki);
            String document = ComposeProperties.document(ComposeProperties.documentService(binder));
            assertFalse(document.contains("interactive_authorization_endpoint"), pki + ": " + document);
            assertFalse(document.contains("require_interactive_authorization_request"), pki + ": " + document);
        }
    }

    /**
     * No mDL profile file sets {@code certify.as.authorization.subject-mode} at all, so the default {@code none} holds:
     * the flow can be advertised, and a registered client's authorization request is refused with {@code access_denied}
     * instead of issuing a code for a subject nobody authenticated. {@code fixed} would hand one synthetic holder's mDL
     * to anyone who completes the flow on the public host, so its absence is asserted in the files themselves, not only
     * in the resolved document.
     */
    @Test
    void noMdlProfileFileSetsAFixedSubjectMode() throws Exception {
        for (String name : List.of("mdl", "mdl-dev", "mdl-operator")) {
            java.util.Properties properties = ComposeProperties.load(name);
            for (String key : properties.stringPropertyNames()) {
                assertFalse(key.startsWith("certify.as.authorization.subject-mode"),
                        "certify-" + name + ".properties sets " + key + "=" + properties.getProperty(key));
                assertFalse(key.startsWith("certify.as.authorization.fixed-subject"),
                        "certify-" + name + ".properties sets " + key + "=" + properties.getProperty(key));
            }
        }
    }

    /**
     * The demo's token endpoint is Certify's own under the owner's identity-only rule (2026-11-13):
     * {@code mosip.certify.domain.url} (the public URL) + the {@code /v1/certify} mount + {@code /oauth/token}. Shown by
     * behaviour, for both PKI profiles: the same configuration listing only {@code authorization_code}, with the client
     * removed and no IAE, is rewritten to the pre-authorized grant, which only an own document is.
     */
    @Test
    void theDemoTokenEndpointIsCertifysOwnByIdentity() throws Exception {
        for (String pki : new String[]{"mdl-dev", "mdl-operator"}) {
            Binder binder = profile(pki);
            assertEquals(PUBLIC_URL + "/v1/certify/oauth/token", ComposeProperties.get(binder, "mosip.certify.oauth.token-endpoint"));
            assertEquals(PUBLIC_URL, ComposeProperties.get(binder, "mosip.certify.domain.url"));
            assertEquals("/v1/certify", ComposeProperties.get(binder, "spring.mvc.servlet.path"));

            AsProperties as = binder.bind("certify.as", Bindable.of(AsProperties.class)).get();
            io.mosip.certify.services.OAuthAuthorizationServerMetadataService service = ComposeProperties.documentService(binder);
            org.springframework.test.util.ReflectionTestUtils.setField(service, "grantTypesSupported", "authorization_code");
            // no client registered: the same identity-built endpoint, now with nothing that could complete the code grant
            org.springframework.beans.factory.support.DefaultListableBeanFactory beans =
                    new org.springframework.beans.factory.support.DefaultListableBeanFactory();
            beans.registerSingleton("asProperties", new AsProperties(Map.of(), as.authorization(), as.par(),
                    as.clientAttestation(), as.preAuthorizedGrant()));
            org.springframework.test.util.ReflectionTestUtils.setField(service, "asProperties",
                    beans.getBeanProvider(AsProperties.class));
            assertEquals(List.of(PRE_AUTHORIZED), service.getOAuthAuthorizationServerMetadata().getGrantTypesSupported(),
                    pki + ": an own document advertises only completable grants");
        }
    }

    /** default, csvdp-farmer, rebuild, mdl then the PKI profile, as docker-compose.mdl.yaml sets active_profile_env. */
    private static Binder profile(String pki) throws Exception {
        return ComposeProperties.binder(ComposeProperties.sources(Map.of("mosip.certify.domain.url", PUBLIC_URL),
                "default", "csvdp-farmer", "rebuild", "mdl", pki));
    }
}
