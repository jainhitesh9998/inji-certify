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
import org.springframework.mock.env.MockEnvironment;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Token Status List freshness (draft-ietf-oauth-status-list 5.1, 8.3): a list JWT that is about to expire, has expired,
 * or names another URI in {@code sub} is signed again when it is served, with the same bits and a signature that
 * verifies; a concurrent status change is never overwritten; one re-sign per list at a time.
 */
class TokenStatusListFreshnessTest {

    static final Duration TTL = Duration.ofHours(1);
    static final Instant T0 = Instant.parse("2026-11-13T10:00:00Z");
    static final String DOMAIN = "https://credentials.example.org";
    static final String SERVLET_PATH = "/v1/certify";
    static final String LIST_ID = "4b4a7c5e-5d9a-4b3a-9b0e-2f0b8f6a1c11";

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
        TokenStatusListProperties broken = new TokenStatusListProperties("keymanager:no-such-key", "ES256", "leaf", 1024, TTL);
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

    // ---- helpers -------------------------------------------------------------------------------------

    TokenStatusListService service(String domain, Instant now) {
        return service(domain, now, new TokenStatusListProperties("keymanager:status-es256", "ES256", "leaf", 1024, TTL));
    }

    TokenStatusListService service(String domain, Instant now, TokenStatusListProperties properties) {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("mosip.certify.domain.url", domain)
                .withProperty("server.servlet.path", SERVLET_PATH);
        return new TokenStatusListService(repository, mock(StatusListCredentialService.class), mock(StatusListIndexProvider.class),
                keys, properties, new ObjectMapper(), environment, Clock.fixed(now, ZoneOffset.UTC));
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
