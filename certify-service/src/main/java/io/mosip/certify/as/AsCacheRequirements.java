package io.mosip.certify.as;

import io.mosip.certify.services.VCICacheService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Refuses to start when Certify's own authorization server is on and a cache it writes is not configured (F-21 review
 * round 2). Each failure was otherwise found by the first caller, and badly: a pushed authorization request with no
 * {@code parRequestCache} was a NullPointerException (500); a client attestation with no
 * {@code clientAttestationJtiCache} was a 401 "jti was already used"; a cache missing from
 * {@code mosip.certify.cache.expire-in-seconds} lived 60 seconds with the {@code simple} backend (shorter than
 * {@code certify.as.par.expires-in}) and for ever with Redis.
 *
 * <ul>
 *   <li>with a client registered ({@code certify.as.clients}): {@code parRequestCache}, its TTL at least
 *       {@code certify.as.par.expires-in};</li>
 *   <li>with an attester configured ({@code certify.as.client-attestation.attesters}): {@code clientAttestationJtiCache},
 *       its TTL at least {@code pop-max-age} + {@code clock-skew}, as long as a proof can be replayed.</li>
 * </ul>
 * A required cache must have an entry in {@code mosip.certify.cache.expire-in-seconds} and, with the {@code simple}
 * backend, be named in {@code mosip.certify.cache.names} (Redis creates the caches of the expiry map itself). Nothing is
 * required of a deployment with neither, which is every deployment before the rebuild.
 */
@Component
public class AsCacheRequirements implements InitializingBean {

    static final String CACHE_NAMES = "mosip.certify.cache.names";
    static final String CACHE_EXPIRY = "mosip.certify.cache.expire-in-seconds";
    static final String CACHE_TYPE = "spring.cache.type";

    private final AsProperties properties;
    private final Environment environment;

    public AsCacheRequirements(AsProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() {
        List<String> problems = problems(properties, environment.getProperty(CACHE_TYPE, "simple"),
                environment.getProperty(CACHE_NAMES), environment.getProperty(CACHE_EXPIRY));
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Certify's authorization server (certify.as) cannot start: "
                    + String.join("; ", problems));
        }
    }

    /** Every way the cache configuration falls short of what {@code as} needs; empty when it does not. */
    static List<String> problems(AsProperties as, String cacheType, String names, String expiry) {
        List<String> problems = new ArrayList<>();
        boolean clients = as != null && as.enabled();
        boolean attesters = as != null && as.clientAttestation() != null && as.clientAttestation().attesters() != null
                && !as.clientAttestation().attesters().isEmpty();
        if (!clients && !attesters) {
            return problems;
        }
        Set<String> named = names == null ? Set.of()
                : Arrays.stream(names.split(",")).map(String::trim).filter(n -> !n.isEmpty()).collect(Collectors.toSet());
        Map<?, ?> ttl;
        try {
            Object parsed = expiry == null || expiry.isBlank() ? null : new SpelExpressionParser().parseExpression(expiry).getValue();
            ttl = parsed instanceof Map<?, ?> map ? map : Map.of();
        } catch (RuntimeException e) {
            problems.add(CACHE_EXPIRY + " is not a map literal: " + e.getMessage());
            ttl = Map.of();
        }
        boolean simple = cacheType == null || "simple".equalsIgnoreCase(cacheType.trim());
        if (clients) {
            require(problems, VCICacheService.PAR_REQUEST_CACHE, as.par().expiresIn().toSeconds(),
                    "certify.as.clients is set, so pushed authorization requests are stored; they must live "
                            + "certify.as.par.expires-in", simple, named, ttl);
        }
        if (attesters) {
            AsProperties.ClientAttestation attestation = as.clientAttestation();
            require(problems, VCICacheService.CLIENT_ATTESTATION_JTI_CACHE,
                    attestation.popMaxAge().toSeconds() + attestation.clockSkew().toSeconds(),
                    "certify.as.client-attestation.attesters is set, so attestation proofs are checked for replay; "
                            + "a proof must be remembered for pop-max-age + clock-skew", simple, named, ttl);
        }
        return problems;
    }

    private static void require(List<String> problems, String cache, long seconds, String why, boolean simple,
                                Set<String> named, Map<?, ?> ttl) {
        if (simple && !named.contains(cache)) {
            problems.add(cache + " is not in " + CACHE_NAMES + " (" + why + ")");
        }
        Object configured = ttl.get(cache);
        if (!(configured instanceof Number number)) {
            problems.add(cache + " has no entry in " + CACHE_EXPIRY + " (" + why + ", " + seconds + " s)");
        } else if (number.longValue() < seconds) {
            problems.add(cache + " lives " + number.longValue() + " s in " + CACHE_EXPIRY + ", less than " + seconds
                    + " s (" + why + ")");
        }
    }
}
