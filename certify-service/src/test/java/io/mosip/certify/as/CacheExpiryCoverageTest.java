package io.mosip.certify.as;

import io.mosip.certify.core.config.SimpleCacheConfig;
import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySources;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the caches actually live for, from the configuration the deployment runs with (F-21 review round 1, finding 3).
 *
 * <p>{@link SimpleCacheConfig} gives a cache with no {@code mosip.certify.cache.expire-in-seconds} entry 60 seconds, and
 * the compose stack had none for {@code preAuthCodeCache}: every pre-authorized code was evicted a minute after it was
 * minted, while its offer advertised {@code expires_in} 600 (up to the service's maximum). The tests below hold both
 * property files to the rule that a code outlives the longest offer, that a pushed request outlives
 * {@code certify.as.par.expires-in}, and that no cache in {@code mosip.certify.cache.names} silently takes the default;
 * the last one proves by measurement that the map is the effective TTL.
 */
class CacheExpiryCoverageTest {

    private static final SpelExpressionParser SPEL = new SpelExpressionParser();

    @Test
    void theComposeStackLetsAPreAuthorizedCodeOutliveTheLongestOffer() throws Exception {
        Map<String, Object> values = composeValues();
        assertLevels(values, "the compose profile");

        long maxOfferExpiry = Long.parseLong(String.valueOf(values.get("mosip.certify.pre-auth.max-expiry-seconds")));
        assertEquals(3600, maxOfferExpiry, "the offer service's cap (PreAuthorizedCodeService)");
        assertEquals(maxOfferExpiry, ((Number) expiry(values).get("preAuthCodeCache")).longValue(),
                "a code evicted before its offer's expires_in is an offer that cannot be redeemed");
        assertTrue(((Number) expiry(values).get("parRequestCache")).longValue() >= (Long) values.get(PAR_LIFETIME),
                "a pushed authorization request must live at least as long as certify.as.par.expires-in ("
                        + values.get(PAR_LIFETIME) + " s)");
    }

    @Test
    void theLocalProfileLetsAPreAuthorizedCodeOutliveTheLongestOffer() throws Exception {
        Map<String, Object> values = localValues();
        assertLevels(values, "application-local.properties");

        long maxOfferExpiry = Long.parseLong(String.valueOf(values.get("mosip.certify.pre-auth.max-expiry-seconds")));
        assertEquals(3600, maxOfferExpiry);
        assertEquals(maxOfferExpiry, ((Number) expiry(values).get("preAuthCodeCache")).longValue());
        assertTrue(((Number) expiry(values).get("parRequestCache")).longValue() >= (Long) values.get(PAR_LIFETIME),
                "a pushed authorization request must live at least as long as certify.as.par.expires-in ("
                        + values.get(PAR_LIFETIME) + " s)");
    }

    /** The keys the offer service reads: the compose file carried `pre-auth-code.*`, which nothing ever read. */
    @Test
    void theOfferExpiryPropertiesAreTheNamesTheServiceReads() throws Exception {
        for (Map<String, Object> values : List.<Map<String, Object>>of(composeValues(), localValues())) {
            for (String key : List.of("mosip.certify.pre-auth.default-expiry-seconds",
                    "mosip.certify.pre-auth.min-expiry-seconds", "mosip.certify.pre-auth.max-expiry-seconds")) {
                assertTrue(values.containsKey(key), "missing " + key + " (PreAuthorizedCodeService reads it)");
            }
        }
        for (String file : List.of("certify-mdl.properties", "certify-mdl-dev.properties", "certify-mdl-operator.properties"))
            assertFalse(Files.readString(ComposeProperties.CONFIG.resolve(file)).contains("mosip.certify.pre-auth-code."),
                    file + " sets a pre-auth-code.* key nothing reads");
    }

    /**
     * The mapping itself, by measurement: a cache whose expiry entry is 1 second drops its entry, and one with no entry
     * takes the 60 s default rather than living until something else removes it (the bug finding 3 found in compose).
     */
    @Test
    void theExpiryMapIsTheEffectiveTtl() throws Exception {
        SimpleCacheConfig config = new SimpleCacheConfig();
        ReflectionTestUtils.setField(config, "cacheNames", List.of("short", "defaulted"));
        ReflectionTestUtils.setField(config, "cacheMaxSize", Map.of("short", 10, "defaulted", 10));
        ReflectionTestUtils.setField(config, "cacheExpireInSeconds", Map.of("short", 1));
        // the container calls this on the bean; here the manager is built and initialised by hand
        var manager = config.cacheManager();
        ((org.springframework.cache.support.AbstractCacheManager) manager).initializeCaches();

        Cache shortLived = manager.getCache("short");
        Cache defaulted = manager.getCache("defaulted");
        assertNotNull(shortLived);
        assertNotNull(defaulted);
        shortLived.put("k", "v");
        defaulted.put("k", "v");
        assertEquals("v", shortLived.get("k", String.class));
        Thread.sleep(1_500);
        assertNull(shortLived.get("k", String.class), "a 1-second entry expires: the map is the TTL");
        assertEquals("v", defaulted.get("k", String.class), "the default is 60 s, not 1 s");
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    /**
     * Every cache the deployment names has a TTL, so none takes the silent 60 s default, and both bounded caches an
     * unauthenticated caller writes into (offers, pushed requests) also have a size. The size map is deliberately not
     * required to be complete: it only bounds the {@code simple} backend, and a cache left out there is unbounded rather
     * than wrong.
     */
    private static void assertLevels(Map<String, Object> values, String where) {
        Set<String> names = new TreeSet<>(Arrays.asList(String.valueOf(values.get("mosip.certify.cache.names")).split(",")));
        names.removeIf(String::isBlank);
        assertTrue(names.contains("preAuthCodeCache"), where + ": " + names);
        assertTrue(names.contains("parRequestCache"), where + ": " + names);
        assertTrue(names.contains("clientAttestationJtiCache"), where + ": " + names);
        assertTrue(sizes(values).keySet().containsAll(Set.of("preAuthCodeCache", "parRequestCache",
                        "clientAttestationJtiCache")),
                where + ": every cache an unauthenticated or attested caller writes is bounded (" + sizes(values) + ")");
        // the replay cache must outlive a proof: pop-max-age PT5M plus clock-skew PT60S
        assertTrue(((Number) expiry(values).get("clientAttestationJtiCache")).longValue() >= 360,
                where + ": the client-attestation replay cache covers pop-max-age + clock-skew");
        assertEquals(new TreeSet<>(names), new TreeSet<>(expiry(values).keySet()),
                where + ": mosip.certify.cache.expire-in-seconds must name every cache, or it lives 60 s");
    }

    /**
     * {@code certify.as.par.expires-in} as the service binds it (typed, default {@code PT90S}): the PAR cache entry must
     * cover it, or a pushed request dies before the authorization endpoint reads it.
     */
    private static long parLifetimeSeconds(org.springframework.boot.context.properties.bind.Binder binder) {
        AsProperties as = binder.bind("certify.as", org.springframework.boot.context.properties.bind.Bindable.of(AsProperties.class))
                .orElse(null);
        return as == null ? 90 : as.par().expiresIn().toSeconds();
    }

    private static Map<String, Object> composeValues() throws IOException {
        // default, csvdp-farmer, rebuild, mdl and mdl-dev, as the container merges them (the PKI profiles add no cache key)
        MutablePropertySources sources = ComposeProperties.sources(Map.of("mosip.certify.domain.url", "https://example.org"),
                "default", "csvdp-farmer", "rebuild", "mdl", "mdl-dev");
        var binder = ComposeProperties.binder(sources);
        Map<String, Object> values = new LinkedHashMap<>();
        for (String key : KEYS) {
            values.put(key, ComposeProperties.get(binder, key));
        }
        for (String name : List.of("mosip.certify.cache.size", "mosip.certify.cache.expire-in-seconds")) {
            String unresolved = ComposeProperties.get(binder, name);
            assertNotNull(unresolved, name);
            values.put(name, unresolved);  // already resolved across the merged sources by the Binder
        }
        values.put(PAR_LIFETIME, parLifetimeSeconds(binder));
        return values;
    }

    private static Map<String, Object> localValues() throws IOException {
        Path path = Path.of("src/main/resources/application-local.properties");
        if (!Files.isRegularFile(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(path)) {
            properties.load(reader);
        }
        MutablePropertySources sources = new MutablePropertySources();
        sources.addFirst(new PropertiesPropertySource("application-local.properties", properties));
        var binder = ComposeProperties.binder(sources);
        Map<String, Object> values = new LinkedHashMap<>();
        for (String key : KEYS) {
            values.put(key, ComposeProperties.get(binder, key));
        }
        for (String name : List.of("mosip.certify.cache.size", "mosip.certify.cache.expire-in-seconds")) {
            values.put(name, ComposeProperties.get(binder, name));
        }
        values.put(PAR_LIFETIME, parLifetimeSeconds(binder));
        return values;
    }

    /** The PAR lifetime as the service binds it, put in the map by the readers below (it is a typed default, not a key). */
    private static final String PAR_LIFETIME = "certify.as.par.expires-in (bound)";

    private static final List<String> KEYS = List.of("mosip.certify.cache.names",
            "mosip.certify.pre-auth.default-expiry-seconds", "mosip.certify.pre-auth.min-expiry-seconds",
            "mosip.certify.pre-auth.max-expiry-seconds", "mosip.certify.pre-auth.cache-expire-seconds",
            "mosip.certify.par.cache-expire-seconds");

    /** A {@code {'name': 1000, ...}} SpEL map literal, the form both properties files use. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Map<String, Object> values, String key) {
        String literal = String.valueOf(values.get(key));
        assertTrue(literal.startsWith("{"), key + " is not a map literal: " + literal);
        Map<String, Object> parsed = (Map<String, Object>) SPEL.parseExpression(literal).getValue();
        assertNotNull(parsed, key);
        return parsed;
    }

    private static Map<String, Object> sizes(Map<String, Object> values) {
        return map(values, "mosip.certify.cache.size");
    }

    private static Map<String, Object> expiry(Map<String, Object> values) {
        return map(values, "mosip.certify.cache.expire-in-seconds");
    }
}
