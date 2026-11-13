package io.mosip.certify.as;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertiesPropertySource;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mDL demo stack's authorization server settings (gaps G29 and G30): it is pre-authorized only. The demo registers
 * no client of Certify's own AS, so the document has no {@code authorization_endpoint} and no PAR; it lists the one
 * grant its token endpoint completes, keeps the Interactive Authorization Endpoint of the farmer profiles out, and
 * advertises the anonymous pre-authorized grant the offer page relies on.
 *
 * <p>Reads the committed compose property files the way Spring Boot does - a placeholder-resolving binder over
 * {@code certify-default.properties}, {@code certify-rebuild.properties}, {@code certify-mdl.properties} and the PKI
 * profile - rather than restating the values in the test, so moving the setting is caught here.
 */
class MdlAuthorizationServerPropertiesTest {

    /** The one value the overlay supplies from outside (`CERTIFY_PUBLIC_URL` -> `mosip_certify_domain_url`). */
    static final String PUBLIC_URL = "https://credentials.example.org";
    static final Path CONFIG = Path.of("..", "docker-compose", "docker-compose-injistack", "config").toAbsolutePath().normalize();
    static final String PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    static final List<String> INTERACTIVE_AUTHORIZATION_KEYS = List.of(
            "mosip.certify.oauth.interactive-authorization-endpoint",
            "mosip.certify.oauth.require-interactive-authorization-request");

    @Test
    void theMdlProfileIsPreAuthorizedOnly() throws Exception {
        Properties mdl = load("certify-mdl.properties");
        assertEquals(PRE_AUTHORIZED, mdl.getProperty("mosip.certify.oauth.grant-types-supported"),
                "the one grant this stack can complete: it has no authorization endpoint and no IAE");
        assertTrue(mdl.stringPropertyNames().stream().noneMatch(key -> key.startsWith("certify.as.clients.")),
                "no client of Certify's own AS is registered on the demo");
        AsProperties as = bind(mdl);
        assertFalse(as.enabled(), "no registered client, so no authorization endpoint is advertised: " + as.clients());
        assertEquals("", mdl.getProperty("mosip.certify.oauth.interactive-authorization-endpoint"),
                "the IAE of the farmer profiles stays off");
        assertEquals("false", mdl.getProperty("mosip.certify.oauth.require-interactive-authorization-request"));
        assertEquals("true", mdl.getProperty("certify.as.pre-authorized-grant.advertise-anonymous-access"),
                "the offer flow is anonymous (OID4VCI 1.0 section 12.3)");
    }

    @Test
    void thePkiProfilesDoNotPutTheAuthorizationCodeFlowBack() throws Exception {
        for (String file : List.of("certify-mdl-dev.properties", "certify-mdl-operator.properties")) {
            Properties profile = load(file);
            for (String key : INTERACTIVE_AUTHORIZATION_KEYS) {
                assertFalse(profile.containsKey(key), file + " overrides " + key);
            }
            for (String key : profile.stringPropertyNames()) {
                assertFalse(key.startsWith("certify.as.clients.") || key.equals("mosip.certify.oauth.grant-types-supported"),
                        file + " overrides the authorization server configuration: " + key);
            }
        }
        // the mDL profile changes exactly these three mosip.certify.oauth.* settings, and nothing else under the prefix
        assertEquals(new TreeSet<>(List.of("mosip.certify.oauth.grant-types-supported",
                        "mosip.certify.oauth.interactive-authorization-endpoint",
                        "mosip.certify.oauth.require-interactive-authorization-request")),
                keysUnder(load("certify-mdl.properties"), "mosip.certify.oauth."));
    }

    /** Binds {@code certify.as} over the compose files in the order Spring Boot's profile-specific loading uses. */
    private static AsProperties bind(Properties mdl) throws IOException {
        MutablePropertySources sources = new MutablePropertySources();
        sources.addFirst(new MapPropertySource("environment", java.util.Map.of("mosip.certify.domain.url", PUBLIC_URL)));
        sources.addLast(new PropertiesPropertySource("certify-default", load("certify-default.properties")));
        sources.addLast(new PropertiesPropertySource("certify-rebuild", load("certify-rebuild.properties")));
        sources.addLast(new PropertiesPropertySource("certify-mdl", mdl));
        sources.addLast(new PropertiesPropertySource("certify-mdl-dev", load("certify-mdl-dev.properties")));
        Binder binder = new Binder(ConfigurationPropertySources.from(sources),
                new PropertySourcesPlaceholdersResolver(sources));
        return binder.bind("certify.as", Bindable.of(AsProperties.class)).get();
    }

    private static Properties load(String name) throws IOException {
        Path path = CONFIG.resolve(name);
        assertTrue(Files.isRegularFile(path), "the compose profile must be committed at " + path);
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path)) {
            properties.load(reader);
        }
        return properties;
    }

    private static Set<String> keysUnder(Properties properties, String prefix) {
        Set<String> keys = new TreeSet<>();
        properties.stringPropertyNames().stream().filter(key -> key.startsWith(prefix)).forEach(keys::add);
        return keys;
    }
}
