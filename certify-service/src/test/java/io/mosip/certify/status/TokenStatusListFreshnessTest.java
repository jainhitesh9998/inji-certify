package io.mosip.certify.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.services.StatusListIndexProvider;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.TestKeyProviders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Token Status List freshness (draft-ietf-oauth-status-list 5.1, 8.3): a list JWT that is about to expire, has expired,
 * or names another URI in {@code sub} is signed again when it is served, with the same bits and a signature that
 * verifies; a concurrent status change is never overwritten; one re-sign per list at a time; a stalled or failing signer
 * never gets an expired list served, never parks request threads beyond {@code renew-wait}, and is not retried within
 * {@code renew-backoff}.
 */
class TokenStatusListFreshnessTest {

    static final Duration TTL = Duration.ofHours(1);
    static final Instant T0 = Instant.parse("2026-11-13T10:00:00Z");
    static final String DOMAIN = "https://credentials.example.org";
    static final String SERVLET_PATH = "/v1/certify";
    static final String LIST_ID = "4b4a7c5e-5d9a-4b3a-9b0e-2f0b8f6a1c11";
    static final Duration RENEW_WAIT = Duration.ofSeconds(5);
    static final Duration BACKOFF = Duration.ofSeconds(30);

    final Map<String, String> documents = new ConcurrentHashMap<>();
    final AtomicInteger replaced = new AtomicInteger();
    final KeyProviderRegistry keys = TestKeyProviders.registry("status-es256", SignatureAlgorithm.ES256);
    StatusListCredentialRepository repository;

    @BeforeEach
    void repository() {
        repository = mock(StatusListCredentialRepository.class);
        when(repository.findById(anyString())).thenAnswer(inv -> Optional.ofNullable(documents.get(inv.<String>getArgument(0)))
                .map(document -> row(inv.getArgument(0), document)));
        when(repository.replaceDocument(anyString(), anyString(), anyString())).thenAnswer(inv -> {
            boolean done = documents.replace(inv.getArgument(0), inv.getArgument(1), inv.getArgument(2));
            if (done) {
                replaced.incrementAndGet();
            }
            return done ? 1 : 0;
        });
    }

    @Test
    void aListCloseToExpiryIsSignedAgainOnGetWithTheSameBits() throws Exception {
        byte[] bits = revokedAt(3, 17);
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, bits));

        Instant later = T0.plus(TTL).plusSeconds(60); // exp is now less than ttl away
        TokenStatusListService lists = service(DOMAIN, later);
        assertEquals(TokenStatusListService.Freshness.RENEW, lists.freshness(LIST_ID, documents.get(LIST_ID)));
        String served = lists.jwt(LIST_ID).orElseThrow();

        JWTClaimsSet claims = verified(served);
        assertEquals(later.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
        assertEquals(later.plus(TTL).plus(TTL), claims.getExpirationTime().toInstant(), "exp = iat + 2 ttl from the re-signing instant");
        assertEquals(TTL.getSeconds(), claims.getLongClaim("ttl"));
        assertEquals(lists.uri(LIST_ID), claims.getSubject());
        assertArrayEquals(bits, TokenStatusListService.bits(served), "the list content is unchanged");
        assertEquals(served, documents.get(LIST_ID), "the re-signed list is persisted");
        assertEquals(1, replaced.get());
    }

    @Test
    void aFreshListIsServedAsStored() {
        String stored = service(DOMAIN, T0).sign(LIST_ID, revokedAt(5));
        documents.put(LIST_ID, stored);
        assertEquals(stored, service(DOMAIN, T0.plus(TTL).minusSeconds(1)).jwt(LIST_ID).orElseThrow());
        assertEquals(0, replaced.get());
    }

    @Test
    void anExpiredListIsSignedAgain() throws Exception {
        byte[] bits = revokedAt(0, 8, 1023);
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, bits));
        Instant muchLater = T0.plus(Duration.ofDays(3));
        TokenStatusListService lists = service(DOMAIN, muchLater);
        assertEquals(TokenStatusListService.Freshness.UNUSABLE, lists.freshness(LIST_ID, documents.get(LIST_ID)));

        JWTClaimsSet claims = verified(lists.jwt(LIST_ID).orElseThrow());
        assertTrue(claims.getExpirationTime().toInstant().isAfter(muchLater.plus(TTL)));
        assertArrayEquals(bits, TokenStatusListService.bits(documents.get(LIST_ID)));
    }

    @Test
    void aChangedDomainYieldsASubEqualToTheNewUri() throws Exception {
        byte[] bits = revokedAt(42);
        documents.put(LIST_ID, service("https://old-host.example.org", T0).sign(LIST_ID, bits));

        TokenStatusListService moved = service(DOMAIN, T0.plusSeconds(60)); // fresh by time, stale by URI
        assertEquals(TokenStatusListService.Freshness.UNUSABLE, moved.freshness(LIST_ID, documents.get(LIST_ID)));
        String served = moved.jwt(LIST_ID).orElseThrow();

        JWTClaimsSet claims = verified(served);
        assertEquals(DOMAIN + SERVLET_PATH + "/credentials/token-status-list/" + LIST_ID, claims.getSubject());
        assertEquals(moved.uri(LIST_ID), claims.getSubject());
        assertArrayEquals(bits, TokenStatusListService.bits(served));
    }

    @Test
    void aStatusChangeDuringTheReSignIsNeverOverwritten() throws Exception {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt()));
        Instant later = T0.plus(TTL).plusSeconds(60);
        TokenStatusListService lists = service(DOMAIN, later);
        // the batch job revokes index 9 (and signs the list) between the read and the compare-and-set of the re-sign
        String revoked = lists.sign(LIST_ID, revokedAt(9));
        AtomicBoolean raced = new AtomicBoolean();
        when(repository.replaceDocument(anyString(), anyString(), anyString())).thenAnswer(inv -> {
            if (raced.compareAndSet(false, true)) {
                documents.put(LIST_ID, revoked);
            }
            boolean done = documents.replace(inv.getArgument(0), inv.getArgument(1), inv.getArgument(2));
            return done ? 1 : 0;
        });

        String served = lists.jwt(LIST_ID).orElseThrow();
        assertTrue(TokenStatusListService.get(TokenStatusListService.bits(served), 9), "the revocation survives");
        assertTrue(TokenStatusListService.get(TokenStatusListService.bits(documents.get(LIST_ID)), 9), "and stays stored");
        assertEquals(revoked, documents.get(LIST_ID), "the fresh list the batch job wrote is not signed again");
    }

    @Test
    void oneReSignPerListWhileOthersGetThePreviousValidList() throws Exception {
        String previous = service(DOMAIN, T0).sign(LIST_ID, revokedAt(1));
        documents.put(LIST_ID, previous);
        Instant later = T0.plus(TTL).plusSeconds(60);
        TokenStatusListService lists = service(DOMAIN, later);

        List<String> served = concurrently(32, () -> lists.jwt(LIST_ID).orElseThrow());
        assertEquals(1, replaced.get(), "exactly one re-sign");
        for (String jwt : served) {
            JWTClaimsSet claims = verified(jwt);
            assertTrue(claims.getExpirationTime().toInstant().isAfter(later), "every reader got a list that has not expired");
            assertTrue(jwt.equals(previous) || jwt.equals(documents.get(LIST_ID)));
        }
    }

    @Test
    void anUnusableListMakesReadersWaitForTheOneReSign() throws Exception {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(2)));
        Instant muchLater = T0.plus(Duration.ofDays(1));
        TokenStatusListService lists = service(DOMAIN, muchLater);

        List<String> served = concurrently(16, () -> lists.jwt(LIST_ID).orElseThrow());
        assertEquals(1, replaced.get(), "exactly one re-sign");
        for (String jwt : served) {
            assertEquals(documents.get(LIST_ID), jwt, "nobody is served the expired list");
        }
    }

    @Test
    void aListThatCannotBeSignedIsServedUntilItExpiresAndRefusedAfter() {
        String stored = service(DOMAIN, T0).sign(LIST_ID, revokedAt(4));
        documents.put(LIST_ID, stored);
        TokenStatusListProperties broken = properties("keymanager:no-such-key", RENEW_WAIT, BACKOFF);
        TokenStatusListService dueForRenewal = service(DOMAIN, T0.plus(TTL).plusSeconds(60), broken);
        assertEquals(stored, dueForRenewal.jwt(LIST_ID).orElseThrow(), "still valid: served as stored");

        TokenStatusListService expired = service(DOMAIN, T0.plus(Duration.ofDays(1)), broken);
        assertThrows(IllegalStateException.class, () -> expired.jwt(LIST_ID));
        assertEquals(stored, documents.get(LIST_ID));
    }

    @Test
    void anUnknownOrBitstringListIsNotServed() {
        assertTrue(service(DOMAIN, T0).jwt("no-such-list").isEmpty());
        StatusListCredential bitstring = row(LIST_ID, "{}");
        bitstring.setCredentialType("BitstringStatusListCredential");
        when(repository.findById(LIST_ID)).thenReturn(Optional.of(bitstring));
        assertFalse(service(DOMAIN, T0).jwt(LIST_ID).isPresent());
    }

    /**
     * Review round 1, item 1: a signer that hangs (HSM or keymanager stall) holds the one request that re-signs the list;
     * a request for the same expired list waits at most {@code renew-wait} and is answered 503, instead of waiting
     * without limit (every Tomcat thread would end up parked on the lock).
     */
    @Test
    void aRequestForAnExpiredListWaitsAtMostRenewWaitForAHungSigner() throws Exception {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(6)));
        CountDownLatch signing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        KeyProviderRegistry hung = signerThat(() -> {
            signing.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        Duration renewWait = Duration.ofMillis(300);
        TokenStatusListService lists = service(DOMAIN, Clock.fixed(T0.plus(Duration.ofDays(1)), ZoneOffset.UTC),
                properties("keymanager:status-es256", renewWait, BACKOFF), hung);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Optional<String>> first = pool.submit(() -> lists.jwt(LIST_ID));
            assertTrue(signing.await(10, TimeUnit.SECONDS), "the first request is signing");

            long started = System.nanoTime();
            TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
            Duration waited = Duration.ofNanos(System.nanoTime() - started);
            assertTrue(waited.compareTo(renewWait) >= 0 && waited.compareTo(Duration.ofSeconds(5)) < 0, "waited " + waited);
            assertEquals(1, refused.retryAfterSeconds());

            release.countDown();
            String renewed = first.get(10, TimeUnit.SECONDS).orElseThrow();
            assertEquals(renewed, documents.get(LIST_ID), "the hung request finishes the re-sign once the signer answers");
            assertEquals(renewed, lists.jwt(LIST_ID).orElseThrow());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    /**
     * Review round 1, item 2: the stored list was due (one second left) when the request began, the signer took two seconds
     * and failed; by then the stored list has expired, so it is not served with 200.
     */
    @Test
    void aListThatExpiresWhileTheSignerFailsIsNotServed() {
        Instant start = T0.plus(TTL).plus(TTL).minusSeconds(1); // exp one second away: due, still valid
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(7)));
        MutableClock clock = new MutableClock(start);
        TokenStatusListService lists = service(DOMAIN, clock, properties("keymanager:status-es256", RENEW_WAIT, BACKOFF), signerThat(() -> {
            clock.advance(Duration.ofSeconds(2));
            throw new IllegalStateException("HSM session lost");
        }));
        assertEquals(TokenStatusListService.Freshness.RENEW, lists.freshness(LIST_ID, documents.get(LIST_ID)));

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(refused.getCause().getMessage().contains("HSM session lost"));
    }

    /**
     * Review round 1, item 3: after a failed re-sign the list is not signed again for {@code renew-backoff}; meanwhile the
     * stored list is served while it is valid and 503 is answered at once when it is not; after the window it is signed again.
     */
    @Test
    void aFailedReSignIsNotRetriedWithinTheBackoff() throws Exception {
        String stored = service(DOMAIN, T0).sign(LIST_ID, revokedAt(8));
        documents.put(LIST_ID, stored);
        AtomicInteger attempts = new AtomicInteger();
        AtomicBoolean broken = new AtomicBoolean(true);
        MutableClock clock = new MutableClock(T0.plus(TTL).plus(TTL).minusSeconds(10)); // due, valid for ten more seconds
        TokenStatusListService lists = service(DOMAIN, clock, properties("keymanager:status-es256", RENEW_WAIT, BACKOFF), signerThat(() -> {
            attempts.incrementAndGet();
            if (broken.get()) {
                throw new IllegalStateException("signer down");
            }
        }));

        assertEquals(stored, lists.jwt(LIST_ID).orElseThrow(), "valid: served as stored after the failure");
        assertEquals(1, attempts.get());
        clock.advance(Duration.ofSeconds(5));
        assertEquals(stored, lists.jwt(LIST_ID).orElseThrow(), "within the back-off and still valid: served as stored");
        assertEquals(1, attempts.get(), "not signed again within the back-off");

        clock.advance(Duration.ofSeconds(10)); // the stored list expired five seconds ago; fifteen seconds of the window are left
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(1, attempts.get(), "503 at once, without signing");
        assertEquals(15, refused.retryAfterSeconds(), "Retry-After the rest of the window");

        clock.advance(Duration.ofSeconds(15)); // the window has passed: signed again, failed again
        assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(2, attempts.get());

        broken.set(false);
        clock.advance(BACKOFF);
        String renewed = lists.jwt(LIST_ID).orElseThrow();
        assertEquals(3, attempts.get());
        assertArrayEquals(revokedAt(8), TokenStatusListService.bits(renewed));
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshness(LIST_ID, renewed));
    }

    /**
     * Review round 2, item 2: {@code exp} is stamped before the signer runs, so a signer that succeeds only after
     * {@code 2 ttl} has passed yields a list that is already expired. It is not served with 200: 503 with
     * {@code Retry-After}, the failure backs off, and the next renewal once the signer is quick again serves a fresh list.
     */
    @Test
    void aSlowSignerThatSucceedsAfterExpNeverGetsAnExpiredListServed() throws Exception {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(10)));
        MutableClock clock = new MutableClock(T0.plus(Duration.ofDays(1))); // the stored list expired long ago
        AtomicBoolean slow = new AtomicBoolean(true);
        AtomicInteger attempts = new AtomicInteger();
        TokenStatusListService lists = service(DOMAIN, clock, properties("keymanager:status-es256", RENEW_WAIT, BACKOFF), signerThat(() -> {
            attempts.incrementAndGet();
            if (slow.get()) {
                clock.advance(TTL.multipliedBy(2).plusSeconds(1)); // the signer answers, successfully, after exp
            }
        }));

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(refused.getCause().getMessage().contains("expired by the time the signer answered"), refused.getCause().getMessage());
        assertEquals(1, attempts.get());
        assertEquals(TokenStatusListService.Freshness.UNUSABLE, lists.freshness(LIST_ID, documents.get(LIST_ID)),
                "what the slow signer stored is expired too; it is never served");

        assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(1, attempts.get(), "within the back-off: 503 at once, not signed again");

        slow.set(false);
        clock.advance(BACKOFF);
        String renewed = lists.jwt(LIST_ID).orElseThrow();
        assertEquals(2, attempts.get());
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshness(LIST_ID, renewed));
        assertArrayEquals(revokedAt(10), TokenStatusListService.bits(renewed));
        assertEquals(renewed, documents.get(LIST_ID));
    }

    /** Review round 2, item 6: a clock that moves backwards after a failure never makes Retry-After exceed renew-backoff. */
    @Test
    void aClockMovingBackwardsNeverStretchesTheBackoff() {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(11)));
        MutableClock clock = new MutableClock(T0.plus(Duration.ofDays(1)));
        AtomicBoolean broken = new AtomicBoolean(true);
        TokenStatusListService lists = service(DOMAIN, clock, properties("keymanager:status-es256", RENEW_WAIT, BACKOFF), signerThat(() -> {
            if (broken.get()) {
                throw new IllegalStateException("signer down");
            }
        }));
        assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));

        clock.advance(Duration.ofHours(-1)); // NTP steps the clock back an hour
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class, () -> lists.jwt(LIST_ID));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds(), "capped at renew-backoff, not an hour and thirty seconds");

        broken.set(false);
        clock.advance(BACKOFF); // the window ends when Retry-After said it would
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshness(LIST_ID, lists.jwt(LIST_ID).orElseThrow()));
    }

    /** Review round 1, item 7: the endpoint answers an expired list whose signer throws with 503 and Retry-After, no body. */
    @Test
    void theEndpointAnswers503WithRetryAfterForAnExpiredListThatCannotBeSigned() throws Exception {
        documents.put(LIST_ID, service(DOMAIN, T0).sign(LIST_ID, revokedAt(9)));
        TokenStatusListService lists = service(DOMAIN, Clock.fixed(T0.plus(Duration.ofDays(1)), ZoneOffset.UTC),
                properties("keymanager:status-es256", RENEW_WAIT, BACKOFF), signerThat(() -> {
                    throw new IllegalStateException("keymanager unavailable");
                }));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        mvc.perform(get("/credentials/token-status-list/" + LIST_ID).accept(TokenStatusListService.MEDIA_TYPE))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, Long.toString(BACKOFF.getSeconds())))
                .andExpect(content().string(""));
        mvc.perform(get("/credentials/token-status-list/" + LIST_ID))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
        mvc.perform(get("/credentials/token-status-list/no-such-list")).andExpect(status().isNotFound());
    }

    // ---- M-11d: the CWT branch of the same state machine ----------------------------------------------------------

    /**
     * A {@code TokenStatusListCwt} row goes through the same freshness machine: a token with less than {@code ttl} left
     * is signed again when it is served, with the same bits, and answered in its own media type (D-M11-2).
     */
    @Test
    void aCwtListIsSignedAgainWhenStaleAndServedInItsOwnMediaType() {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(
                TokenStatusListCwtServiceTest.T0);
        fixture.clock = clock;
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        byte[] before = TokenStatusListCwtServiceTest.TokenStatusListCwtBase.token(
                fixture.rows.get(listId).getVcDocument());

        clock.advance(TTL.plusSeconds(60));
        TokenStatusListService.Served served = lists.served(listId).orElseThrow();
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, served.mediaType());
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshnessCwt(listId,
                lists.envelope(fixture.rows.get(listId).getVcDocument())), "stored fresh once signed again");
        TokenStatusListCwt.Decoded after = TokenStatusListCwt.decode(served.body());
        assertEquals(clock.instant().getEpochSecond(), after.iat().getEpochSecond());
        assertArrayEquals(TokenStatusListCwt.decode(before).lst(), after.lst(), "the bits are unchanged");
        assertEquals(1, fixture.replaced.get());
    }

    /**
     * M-11d's ordering rule: {@link StatusListRetiredException} extends {@link IllegalStateException}, so the service
     * must catch it before the general refusal mapping. A retired list is {@link TokenStatusListGoneException} (410),
     * while any other refusal on the same path is {@link TokenStatusListUnavailableException} (503, back-off): this test
     * puts the two side by side on one fixture.
     */
    @Test
    void aRetiredCwtListAnswersGoneWhereAFailedRenewalAnswers503() {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(
                TokenStatusListCwtServiceTest.T0);
        fixture.clock = clock;
        TokenStatusListService lists = fixture.lists(clock);

        // retired: the stored signer is past its notAfter and the token's own exp has passed too
        String retired = "a-retired-cwt-list";
        byte[] token = TokenStatusListCwtServiceTest.TokenStatusListCwtBase.storedToken(
                TokenStatusListCwtServiceTest.URI(retired), TokenStatusListCwtServiceTest.T0.minus(Duration.ofHours(3)),
                TokenStatusListCwtServiceTest.T0.minus(Duration.ofHours(1)), new byte[128],
                StatusListTestKeys.key("expired", StatusListTestKeys.EXPIRED_KEYS, StatusListTestKeys.EXPIRED));
        fixture.rows.put(retired, fixture.row(retired, TokenStatusListService.TYPE_CWT,
                TokenStatusListCwtServiceTest.TokenStatusListCwtBase.envelope(new TokenStatusListService.SignerBinding(
                        TokenStatusListService.SIGNER_DOCUMENT, "x509-file:mdl-dsc",
                        StatusListSigners.x5tS256(StatusListTestKeys.EXPIRED)), token)));
        fixture.documents.put(retired, fixture.rows.get(retired).getVcDocument());
        assertThrows(TokenStatusListGoneException.class, () -> lists.served(retired));

        // not retired: the same expired token, but its signer is a live one that fails instead (503 + Retry-After)
        TokenStatusListService.Entry live = lists.allocateCwt("revocation", fixture.dsc());
        fixture.switching.failSigning.set(true);
        clock.advance(TTL.multipliedBy(2));
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(fixture.listId(live)));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
    }

    // ---- helpers -------------------------------------------------------------------------------------

    TokenStatusListService service(String domain, Instant now) {
        return service(domain, now, properties("keymanager:status-es256", RENEW_WAIT, BACKOFF));
    }

    TokenStatusListService service(String domain, Instant now, TokenStatusListProperties properties) {
        return service(domain, Clock.fixed(now, ZoneOffset.UTC), properties, keys);
    }

    TokenStatusListService service(String domain, Clock clock, TokenStatusListProperties properties, KeyProviderRegistry signers) {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("mosip.certify.domain.url", domain)
                .withProperty("server.servlet.path", SERVLET_PATH);
        return new TokenStatusListService(repository, mock(StatusListCredentialService.class), mock(StatusListIndexProvider.class),
                signers, properties, new ObjectMapper(), environment, clock);
    }

    static TokenStatusListProperties properties(String keyRef, Duration renewWait, Duration backoff) {
        return new TokenStatusListProperties(keyRef, "ES256", "leaf", 1024, TTL, renewWait, backoff, null);
    }

    /** The test registry, with {@code before} run each time a list is about to be signed (to block, throw or move the clock). */
    KeyProviderRegistry signerThat(Runnable before) {
        KeyProviderRegistry signers = mock(KeyProviderRegistry.class);
        when(signers.signingContext(any())).thenAnswer(inv -> {
            before.run();
            return keys.signingContext(inv.getArgument(0));
        });
        return signers;
    }

    /** A clock the test (or a signer) moves. */
    static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            now = new AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(t -> t.plus(by));
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }
    }

    static StatusListCredential row(String id, String document) {
        StatusListCredential row = new StatusListCredential();
        row.setId(id);
        row.setVcDocument(document);
        row.setCredentialType(TokenStatusListService.TYPE);
        row.setStatusPurpose("revocation");
        row.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        return row;
    }

    static byte[] revokedAt(long... indices) {
        byte[] bits = new byte[1024 / 8];
        for (long idx : indices) {
            TokenStatusListService.set(bits, idx, true);
        }
        return bits;
    }

    /** The list's claims after checking its type and its signature by the x5c leaf. */
    static JWTClaimsSet verified(String jwt) throws Exception {
        SignedJWT list = SignedJWT.parse(jwt);
        assertEquals(TokenStatusListService.TYP, list.getHeader().getType().getType());
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(list.getHeader().getX509CertChain().get(0).decode()));
        assertTrue(list.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())), "the list verifies with its x5c leaf");
        assertNotEquals(null, list.getJWTClaimsSet().getJSONObjectClaim("status_list"));
        return list.getJWTClaimsSet();
    }

    static List<String> concurrently(int threads, java.util.concurrent.Callable<String> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return call.call();
                }));
            }
            start.countDown();
            List<String> results = new ArrayList<>();
            for (Future<String> future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }
}
