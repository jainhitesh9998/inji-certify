package io.mosip.certify.as;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Certify's own authorization server refuses to start without the caches it writes (F-21 review round 2, Opus m4): a
 * pushed authorization request with no {@code parRequestCache} was a 500, a client attestation with no
 * {@code clientAttestationJtiCache} a misleading 401 "jti was already used", and a cache missing from the expiry map
 * lived 60 s ({@code simple}) or for ever (Redis).
 */
class AsCacheRequirementsTest {

    static final String NAMES = "preAuthCodeCache,parRequestCache,clientAttestationJtiCache";
    static final String EXPIRY = "{'preAuthCodeCache': 3600, 'parRequestCache': 300, 'clientAttestationJtiCache': 600}";

    @Test
    void aDeploymentWithoutTheCodeFlowOrAttestersNeedsNothing() {
        assertEquals(List.of(), AsCacheRequirements.problems(as(false, false, 90), "simple", "preAuthCodeCache", "{}"),
                "every deployment before the rebuild: no client, no attester");
        assertEquals(List.of(), AsCacheRequirements.problems(as(false, false, 90), "simple", null, null));
    }

    @Test
    void theCodeFlowNeedsTheParCacheNamedAndExpiringNoSoonerThanAPushedRequest() {
        assertEquals(List.of(), AsCacheRequirements.problems(as(true, false, 90), "simple", NAMES, EXPIRY));
        assertProblem(AsCacheRequirements.problems(as(true, false, 90), "simple", "preAuthCodeCache", EXPIRY),
                "parRequestCache is not in mosip.certify.cache.names");
        assertProblem(AsCacheRequirements.problems(as(true, false, 90), "simple", NAMES, "{'preAuthCodeCache': 3600}"),
                "parRequestCache has no entry in mosip.certify.cache.expire-in-seconds");
        assertProblem(AsCacheRequirements.problems(as(true, false, 400), "simple", NAMES, EXPIRY),
                "parRequestCache lives 300 s");
        // no attester: the replay cache is not required
        assertEquals(List.of(), AsCacheRequirements.problems(as(true, false, 90), "simple", "parRequestCache",
                "{'parRequestCache': 90}"));
    }

    @Test
    void attestersNeedTheReplayCacheForPopMaxAgePlusClockSkew() {
        // pop-max-age PT5M + clock-skew PT60S = 360 s
        assertEquals(List.of(), AsCacheRequirements.problems(as(false, true, 90), "simple", NAMES, EXPIRY));
        assertProblem(AsCacheRequirements.problems(as(false, true, 90), "simple", "parRequestCache", EXPIRY),
                "clientAttestationJtiCache is not in mosip.certify.cache.names");
        assertProblem(AsCacheRequirements.problems(as(false, true, 90), "simple", NAMES,
                "{'clientAttestationJtiCache': 359}"), "clientAttestationJtiCache lives 359 s");
        // attesters alone (no client) do not need the PAR cache: attestation is checked at the token endpoint too
        assertEquals(List.of(), AsCacheRequirements.problems(as(false, true, 90), "simple", "clientAttestationJtiCache",
                "{'clientAttestationJtiCache': 360}"));
    }

    /** Redis creates the caches of the expiry map itself, so the names list is not required there - the TTL is. */
    @Test
    void withRedisTheExpiryEntryIsWhatCounts() {
        assertEquals(List.of(), AsCacheRequirements.problems(as(true, true, 90), "redis", "", EXPIRY));
        List<String> problems = AsCacheRequirements.problems(as(true, true, 90), "redis", NAMES, "{'preAuthCodeCache': 1}");
        assertEquals(2, problems.size(), problems.toString());
        assertTrue(problems.stream().allMatch(p -> p.contains("has no entry in")), problems.toString());
    }

    @Test
    void anExpiryMapThatIsNotAMapIsAProblemNotACrash() {
        assertProblem(AsCacheRequirements.problems(as(true, false, 90), "simple", NAMES, "{'parRequestCache': "),
                "is not a map literal");
    }

    /** The context itself refuses to start, with the reason in the message. */
    @Test
    void theApplicationContextFailsAtStartup() {
        new ApplicationContextRunner()
                .withUserConfiguration(AsConfiguration.class, AsCacheRequirements.class)
                .withPropertyValues("certify.as.clients.demo-wallet.redirect-uris[0]=https://wallet.example/cb",
                        "spring.cache.type=simple", "mosip.certify.cache.names=preAuthCodeCache",
                        "mosip.certify.cache.expire-in-seconds={'preAuthCodeCache': 3600}")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("parRequestCache is not in mosip.certify.cache.names")
                            .hasMessageContaining("parRequestCache has no entry in mosip.certify.cache.expire-in-seconds");
                });
        new ApplicationContextRunner()
                .withUserConfiguration(AsConfiguration.class, AsCacheRequirements.class)
                .withPropertyValues("certify.as.clients.demo-wallet.redirect-uris[0]=https://wallet.example/cb",
                        "spring.cache.type=simple", "mosip.certify.cache.names=" + NAMES,
                        "mosip.certify.cache.expire-in-seconds=" + EXPIRY)
                .run(context -> assertThat(context).hasNotFailed());
    }

    private static void assertProblem(List<String> problems, String expected) {
        assertTrue(problems.stream().anyMatch(p -> p.contains(expected)), expected + " in " + problems);
    }

    private static AsProperties as(boolean client, boolean attester, long parSeconds) {
        return new AsProperties(
                client ? Map.of("demo-wallet", new AsProperties.Client(List.of("https://wallet.example/cb"))) : Map.of(),
                new AsProperties.Authorization("none", null), new AsProperties.Par(Duration.ofSeconds(parSeconds)),
                new AsProperties.ClientAttestation(false, attester ? Map.of("a", new AsProperties.Attester("{}")) : Map.of(),
                        Duration.ofSeconds(60), Duration.ofMinutes(5)),
                new AsProperties.PreAuthorizedGrant(false));
    }
}
