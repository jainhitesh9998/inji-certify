package io.mosip.certify.as;

import io.mosip.certify.dpop.DpopProofValidator;
import io.mosip.certify.services.OAuthAuthorizationServerMetadataService;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The compose stack's configuration as Spring Boot sees it, for tests that hold the demo's documents: the committed
 * {@code docker-compose-injistack/config/certify-*.properties} files in the order {@code active_profile_env} lists them
 * (a later profile wins), with the environment variable the overlay sets for the public URL on top. Placeholders are
 * resolved across the merged sources, so a value built from {@code ${mosip.certify.domain.url}} reads as the URL a
 * deployment would serve.
 */
final class ComposeProperties {

    static final Path CONFIG = Path.of("..", "docker-compose", "docker-compose-injistack", "config").toAbsolutePath().normalize();

    private ComposeProperties() {
    }

    /**
     * @param environment the variables the compose file sets (highest precedence, as the process environment is)
     * @param files       property file base names in profile order, {@code default} first: {@code default},
     *                    {@code csvdp-farmer}, {@code rebuild}, {@code mdl}, then the PKI profile
     */
    static MutablePropertySources sources(Map<String, String> environment, String... files) throws IOException {
        MutablePropertySources sources = new MutablePropertySources();
        // addFirst in profile order leaves the last loaded profile at the highest precedence ...
        for (String file : files) {
            sources.addFirst(new PropertiesPropertySource("certify-" + file, load(file)));
        }
        // ... and the environment above every file, as it is in the container
        sources.addFirst(new MapPropertySource("environment", new java.util.LinkedHashMap<>(environment)));
        return sources;
    }

    static Binder binder(MutablePropertySources sources) {
        return new Binder(ConfigurationPropertySources.from(sources), new PropertySourcesPlaceholdersResolver(sources));
    }

    /** A resolved property value, or {@code null} when the files do not set it. */
    static String get(Binder binder, String key) {
        return binder.bind(key, Bindable.of(String.class)).orElse(null);
    }

    static boolean getBoolean(Binder binder, String key) {
        return binder.bind(key, Bindable.of(Boolean.class)).orElse(false);
    }

    /**
     * The service the deployment's configuration produces: every field it reads (`mosip.certify.oauth.*`, the identity
     * its own token URL is built from, `certify.as`, the DPoP algorithms) resolved from the merged sources, exactly as
     * the Spring context would bind them.
     */
    static OAuthAuthorizationServerMetadataService documentService(Binder binder) {
        OAuthAuthorizationServerMetadataService service = new OAuthAuthorizationServerMetadataService();
        ReflectionTestUtils.setField(service, "issuer", get(binder, "mosip.certify.oauth.issuer"));
        ReflectionTestUtils.setField(service, "tokenEndpoint", get(binder, "mosip.certify.oauth.token-endpoint"));
        ReflectionTestUtils.setField(service, "jwksUri", get(binder, "mosip.certify.oauth.jwks-uri"));
        ReflectionTestUtils.setField(service, "grantTypesSupported", get(binder, "mosip.certify.oauth.grant-types-supported"));
        ReflectionTestUtils.setField(service, "responseTypesSupported", get(binder, "mosip.certify.oauth.response-types-supported"));
        ReflectionTestUtils.setField(service, "codeChallengeMethodsSupported", get(binder, "mosip.certify.oauth.code-challenge-methods-supported"));
        ReflectionTestUtils.setField(service, "interactiveAuthorizationEndpoint", get(binder, "mosip.certify.oauth.interactive-authorization-endpoint"));
        String require = get(binder, "mosip.certify.oauth.require-interactive-authorization-request");
        ReflectionTestUtils.setField(service, "requireInteractiveAuthorizationRequest", require == null || Boolean.parseBoolean(require.trim()));
        ReflectionTestUtils.setField(service, "authorizationUrl", get(binder, "mosip.certify.authorization.url"));
        ReflectionTestUtils.setField(service, "domainUrl", get(binder, "mosip.certify.domain.url"));
        ReflectionTestUtils.setField(service, "identifier", get(binder, "mosip.certify.identifier"));
        ReflectionTestUtils.setField(service, "servletPath", get(binder, "server.servlet.path"));
        // where Boot mounts the DispatcherServlet (spring.mvc.servlet.path; certify-default.properties sets it)
        String mounted = get(binder, "spring.mvc.servlet.path");
        if (mounted != null) {
            DefaultListableBeanFactory web = new DefaultListableBeanFactory();
            web.registerSingleton("dispatcherServletPath",
                    (org.springframework.boot.autoconfigure.web.servlet.DispatcherServletPath) () -> mounted);
            ReflectionTestUtils.setField(service, "dispatcherServletPath",
                    web.getBeanProvider(org.springframework.boot.autoconfigure.web.servlet.DispatcherServletPath.class));
        }

        DpopProofValidator dpop = new DpopProofValidator();
        String algorithms = get(binder, "mosip.certify.dpop.allowed-algorithms");
        ReflectionTestUtils.setField(dpop, "allowedAlgorithms", algorithms == null ? List.of()
                : Arrays.stream(algorithms.split(",")).map(String::trim).filter(a -> !a.isBlank()).toList());
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("dpopProofValidator", dpop);
        ReflectionTestUtils.setField(service, "dpopProofValidator", beans.getBeanProvider(DpopProofValidator.class));

        DefaultListableBeanFactory as = new DefaultListableBeanFactory();
        as.registerSingleton("asProperties", binder.bind("certify.as", Bindable.of(AsProperties.class))
                .orElse(new AsProperties(Map.of(), new AsProperties.Authorization("none", null),
                        new AsProperties.Par(java.time.Duration.ofSeconds(90)),
                        new AsProperties.ClientAttestation(false, Map.of(), java.time.Duration.ofSeconds(60), java.time.Duration.ofMinutes(5)),
                        new AsProperties.PreAuthorizedGrant(false))));
        ReflectionTestUtils.setField(service, "asProperties", as.getBeanProvider(AsProperties.class));
        return service;
    }

    static String document(OAuthAuthorizationServerMetadataService service) throws IOException {
        return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(service.getOAuthAuthorizationServerMetadata());
    }

    static Properties load(String name) throws IOException {
        Path path = CONFIG.resolve("certify-" + name + ".properties");
        assertTrue(Files.isRegularFile(path), "the compose profile must be committed at " + path);
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path)) {
            properties.load(reader);
        }
        return properties;
    }
}
