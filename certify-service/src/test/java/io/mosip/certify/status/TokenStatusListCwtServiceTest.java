package io.mosip.certify.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.services.StatusListIndexProvider;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.CwtEnvelope;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static io.mosip.certify.status.StatusListTestKeys.DEDICATED;
import static io.mosip.certify.status.StatusListTestKeys.DEDICATED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static io.mosip.certify.status.StatusListTestKeys.freshCrl;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * M-11d: CWT status lists in the service (docs/design/wp/M-11-status-list-under-iaca.md sections 4.3-4.7 and the M-11d
 * spec). A {@code TokenStatusListCwt} row holds the section 4.4 envelope — the signer it is pinned to and the base64url
 * token — and is served as {@code application/statuslist+cwt} (D-M11-2), signed again by its own pinned certificate
 * (D-M11-1 (a)) through the same freshness state machine as the JWT lists, and retired to {@code 410} once that
 * certificate is past its {@code notAfter} (D-M11-7).
 *
 * <p>What this test proves, item by item:
 * <ul>
 *   <li>{@code allocateCwt} pins the Document Signer, creates a row of the new type and signs a token whose {@code sub}
 *   is the list's URI and whose {@code x5chain} is that signer, and reuses a list only for the same signer;</li>
 *   <li>a fresh token is served as stored; a stale or moved one is signed again with the same bits, a new {@code iat}
 *   and the same signer leaf, {@code exp} capped at the earliest {@code notAfter} of the signer's path;</li>
 *   <li>the batch job's CWT path sets the bit and re-signs with the pinned version even after a newer one was added to
 *   the provider;</li>
 *   <li>the service never trusts its own row for the signer: renewal re-reads the envelope, and a token whose leaf is
 *   not the pinned one is refused rather than re-signed;</li>
 *   <li>a retired list (pinned signer past {@code notAfter}) is never re-signed, is served as stored while its own
 *   {@code exp} holds and raises {@link TokenStatusListGoneException} after it — {@link StatusListRetiredException}
 *   extends {@link IllegalStateException}, so catching it before the general 503 mapping is what keeps D-M11-7's 410
 *   from becoming a 503 forever;</li>
 *   <li>a gone signer, a policy refusal and a failing signer are the existing back-off + {@link
 *   TokenStatusListUnavailableException} (503 with {@code Retry-After}), never an old body;</li>
 *   <li>one re-sign per list at a time.</li>
 * </ul>
 */
class TokenStatusListCwtServiceTest {

    static final Instant T0 = Instant.parse("2026-11-13T10:00:00Z");
    static final Duration TTL = Duration.ofHours(1);
    static final Duration RENEW_WAIT = Duration.ofSeconds(5);
    static final Duration BACKOFF = Duration.ofSeconds(30);
    static final String DOMAIN = "https://credentials.example.org";
    static final String SERVLET_PATH = "/v1/certify";
    static final KeyRef ALIAS = KeyRef.parse("x509-file:mdl-dsc");

    /** A Document Signer that ends at a chosen instant (the last-ttl and last-second cases). */
    static final java.security.KeyPair SOON_KEYS = StatusListTestKeys.p256();
    static final java.security.KeyPair LAST_SECOND_KEYS = StatusListTestKeys.p256();
    static final java.security.KeyPair INTERMEDIATE_DSC_KEYS = StatusListTestKeys.p256();

    static X509Certificate signerUntil(java.security.KeyPair keys, Instant notAfter, String commonName) {
        return StatusListTestKeys.signer(keys, commonName, IACA, StatusListTestKeys.IACA_KEYS,
                List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
                Instant.now().minus(100, java.time.temporal.ChronoUnit.DAYS), notAfter);
    }

    @Test
    void allocateCwtCreatesAPinnedListWhoseTokenIsTheCwtForm() {
        Fixture fixture = new Fixture();
        TokenStatusListService.Entry entry = fixture.lists(T0).allocateCwt("revocation", fixture.dsc());

        StatusListCredential row = fixture.rows.get(fixture.listId(entry));
        assertEquals(TokenStatusListService.TYPE_CWT, row.getCredentialType());
        assertEquals("revocation", row.getStatusPurpose());
        assertEquals(StatusListCredential.CredentialStatus.AVAILABLE, row.getCredentialStatus());
        TokenStatusListService.StoredEnvelope stored = fixture.lists(T0).envelope(row.getVcDocument());
        assertEquals(TokenStatusListService.ENVELOPE_VERSION, stored.v());
        assertEquals(TokenStatusListService.SIGNER_DOCUMENT, stored.signer().mode());
        assertEquals("x509-file:mdl-dsc@2026-11", stored.signer().keyRef(), "the version that allocated the indices is pinned");
        assertEquals(StatusListSigners.x5tS256(DSC), stored.signer().x5tS256());

        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(Base64.getUrlDecoder().decode(stored.token()));
        assertEquals(entry.uri(), decoded.sub());
        assertEquals(T0.getEpochSecond(), decoded.iat().getEpochSecond());
        assertEquals(T0.plus(TTL).plus(TTL).getEpochSecond(), decoded.exp().getEpochSecond());
        assertEquals(TTL.getSeconds(), decoded.ttl());
        assertEquals(1, decoded.bits());
        assertEquals(1, decoded.x5chain().size(), "the x5chain is the signer leaf, never the IACA");
        assertEquals(DSC, decoded.x5chain().get(0));
        assertEquals(fixture.properties.sizeBits() / 8, decoded.lst().length);
        for (int index = 0; index < decoded.lst().length * 8; index++) {
            assertFalse(TokenStatusListService.get(decoded.lst(), index));
        }
    }

    @Test
    void allocateCwtReusesTheListOfTheSameSignerButStartsANewOneForAnotherSigner() {
        Fixture fixture = new Fixture();
        TokenStatusListService lists = fixture.lists(T0);

        TokenStatusListService.Entry first = lists.allocateCwt("revocation", fixture.dsc());
        TokenStatusListService.Entry second = lists.allocateCwt("revocation", fixture.dsc());
        assertEquals(fixture.listId(first), fixture.listId(second), "one Document Signer keeps one list");
        assertNotEquals(first.idx(), second.idx());

        // the operator rotates the Document Signer: the bare alias now names the new version
        fixture.provider.add("mdl-dsc@2027-01", DEDICATED_KEYS.getPrivate(), CertificateChain.of(DEDICATED, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        TokenStatusListService.Entry other = lists.allocateCwt("revocation", fixture.signing("x509-file:mdl-dsc"));
        assertNotEquals(fixture.listId(first), fixture.listId(other),
                "a rotated Document Signer's mDLs go to a list pinned to the new certificate");
        assertEquals(StatusListSigners.x5tS256(DEDICATED),
                lists.envelope(fixture.rows.get(fixture.listId(other)).getVcDocument()).signer().x5tS256());
    }

    @Test
    void aFullListIsMarkedFullAndTheNextOneIsCreated() {
        Fixture fixture = new Fixture(8);
        TokenStatusListService lists = fixture.lists(T0);
        TokenStatusListService.Entry first = lists.allocateCwt("revocation", fixture.dsc());
        for (int index = 1; index < 8; index++) {
            assertEquals(fixture.listId(first), fixture.listId(lists.allocateCwt("revocation", fixture.dsc())));
        }
        TokenStatusListService.Entry overflow = lists.allocateCwt("revocation", fixture.dsc());
        assertNotEquals(fixture.listId(first), fixture.listId(overflow));
        assertEquals(StatusListCredential.CredentialStatus.FULL,
                fixture.rows.get(fixture.listId(first)).getCredentialStatus(), "the full list takes no more indices");
        assertEquals(StatusListCredential.CredentialStatus.AVAILABLE,
                fixture.rows.get(fixture.listId(overflow)).getCredentialStatus());
    }

    @Test
    void aFreshCwtListIsServedAsStored() {
        Fixture fixture = new Fixture();
        TokenStatusListService lists = fixture.lists(T0);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        byte[] stored = TokenStatusListCwtBase.token(fixture.rows.get(fixture.listId(entry)).getVcDocument());

        TokenStatusListService.Served served = lists.served(fixture.listId(entry)).orElseThrow();
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, served.mediaType());
        assertArrayEquals(stored, served.body());
        assertEquals(0, fixture.replaced.get());
    }

    @Test
    void aStaleCwtListIsSignedAgainWithTheSameBitsANewIatAndTheSameSigner() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        TokenStatusListCwt.Decoded before = TokenStatusListCwt.decode(TokenStatusListCwtBase.token(
                fixture.rows.get(listId).getVcDocument()));
        byte[] bits = before.lst();
        TokenStatusListService.set(bits, entry.idx(), true);
        fixture.storeBits(listId, bits, clock.instant());

        clock.advance(TTL.plusSeconds(60)); // exp is now less than ttl away
        TokenStatusListService.Served served = lists.served(listId).orElseThrow();
        TokenStatusListCwt.Decoded after = TokenStatusListCwt.decode(served.body());
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, served.mediaType());
        assertEquals(clock.instant().getEpochSecond(), after.iat().getEpochSecond());
        assertEquals(clock.instant().plus(TTL).plus(TTL).getEpochSecond(), after.exp().getEpochSecond());
        assertEquals(before.sub(), after.sub());
        assertEquals(DSC, after.x5chain().get(0), "the list keeps the signer that allocated its indices");
        assertArrayEquals(bits, after.lst(), "the list content is unchanged");
        assertTrue(TokenStatusListService.get(after.lst(), entry.idx()));
        assertEquals(1, fixture.replaced.get(), "the re-signed token is stored");
        assertArrayEquals(served.body(), TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument()));
    }

    @Test
    void expIsCappedAtTheEarliestNotAfterOfTheSignersPath() {
        Fixture fixture = new Fixture(1024, Duration.ofDays(365), RENEW_WAIT, BACKOFF);
        TokenStatusListService.Entry entry = fixture.lists(T0).allocateCwt("revocation", fixture.dsc());
        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(
                TokenStatusListCwtBase.token(fixture.rows.get(fixture.listId(entry)).getVcDocument()));
        assertEquals(DSC.getNotAfter().toInstant().getEpochSecond(), decoded.exp().getEpochSecond(),
                "a token never outlives the certificate a verifier builds its path through (section 4.1, D7)");
    }

    @Test
    void aChangedDomainYieldsASubEqualToTheNewUri() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService moved = fixture.lists(clock, "https://old-host.example.org");
        TokenStatusListService.Entry entry = moved.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        clock.advance(Duration.ofSeconds(30)); // still fresh by time, stale by URI
        TokenStatusListService current = fixture.lists(clock);

        TokenStatusListService.Served served = current.served(listId).orElseThrow();
        assertEquals(current.uri(listId), TokenStatusListCwt.decode(served.body()).sub());
        assertTrue(TokenStatusListCwt.decode(served.body()).sub().startsWith(DOMAIN + SERVLET_PATH));
    }

    @Test
    void aBatchUpdateSetsTheBitAndResignsWithThePinnedVersionAfterARotation() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        // the operator rotates the Document Signer: the alias now resolves to a newer version, the pinned one stays
        fixture.provider.add("mdl-dsc@2027-01", DEDICATED_KEYS.getPrivate(), CertificateChain.of(DEDICATED, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        assertEquals(DEDICATED, fixture.provider.resolve(ALIAS).chain().leaf().orElseThrow(),
                "the bare alias now names the new Document Signer");

        clock.advance(Duration.ofMinutes(1));
        lists.update(fixture.rows.get(listId), Map.of(entry.idx(), true));

        TokenStatusListCwt.Decoded updated = TokenStatusListCwt.decode(
                TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument()));
        assertTrue(TokenStatusListService.get(updated.lst(), entry.idx()), "the revoked bit is set");
        assertEquals(DSC, updated.x5chain().get(0), "the list is re-signed by the version its mDLs carry, not the new one");
        assertEquals(clock.instant().getEpochSecond(), updated.iat().getEpochSecond());
        assertEquals("x509-file:mdl-dsc@2026-11", lists.envelope(fixture.rows.get(listId).getVcDocument()).signer().keyRef());
    }

    @Test
    void aTamperedStoredTokenIsRefusedAndAVerifierRejectsIt() {
        Fixture fixture = new Fixture();
        TokenStatusListService lists = fixture.lists(T0);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        byte[] genuine = TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument());
        assertTrue(TokenStatusListCwt.verifies(genuine, DSC), "the stored token starts out verifiable");
        // one bit of lst flipped in the payload without re-signing: the signature no longer covers the bits, so the
        // stored row is refused (503, fail closed) rather than served or, worse, re-signed (review round 1, major 1)
        byte[] tampered = TokenStatusListCwtBase.tamperLst(genuine, 9, true);
        assertFalse(TokenStatusListCwt.verifies(tampered, DSC), "an independent verifier rejects the tampered token");
        assertTrue(TokenStatusListService.get(TokenStatusListCwt.decode(tampered).lst(), 9), "its payload says revoked");

        int signedBefore = fixture.signed.get();
        fixture.storeToken(listId, tampered);
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(listId));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertEquals(0, fixture.replaced.get(), "nothing is written: a tampered token is never repaired by signing");
        assertEquals(signedBefore, fixture.signed.get(), "and nothing is signed");
    }

    @Test
    void aTamperedTokenIsNotLaunderedIntoAValidOneByRenewal() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        // the reproduction of review round 1, major 1: revoke, clear the stored bit in the DB without signing, then
        // advance into renewal. Without the signature check the re-sign makes signature=true and revoked=false.
        byte[] bits = TokenStatusListCwt.decode(TokenStatusListCwtBase.token(
                fixture.rows.get(listId).getVcDocument())).lst();
        TokenStatusListService.set(bits, entry.idx(), true);
        fixture.storeBits(listId, bits, T0);
        byte[] revoked = TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument());
        clock.advance(TTL.plusSeconds(60));

        int signedBefore = fixture.signed.get();
        fixture.storeToken(listId, TokenStatusListCwtBase.tamperLst(revoked, entry.idx(), false)); // clears the revoked bit
        assertThrows(TokenStatusListUnavailableException.class, () -> lists.served(listId));
        assertEquals(signedBefore, fixture.signed.get(), "renewal never signs a payload the pinned signer did not sign");
        assertEquals(0, fixture.replaced.get());
    }

    @Test
    void aTokenThatIsNotThePinnedSignersIsRefusedNotResigned() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        // the envelope is edited to pin the OTHER Document Signer's certificate: token and signer do not belong together
        TokenStatusListService.StoredEnvelope stored = lists.envelope(fixture.rows.get(listId).getVcDocument());
        String edited = TokenStatusListCwtBase.envelope(new TokenStatusListService.SignerBinding(
                stored.signer().mode(), stored.signer().keyRef(), StatusListSigners.x5tS256(DEDICATED)),
                Base64.getUrlDecoder().decode(stored.token()));
        fixture.rows.get(listId).setVcDocument(edited);
        fixture.documents.put(listId, edited);
        clock.advance(TTL.multipliedBy(2)); // the token is expired, so a renewal is attempted

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(listId));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(refused.getMessage().contains("does not verify with its pinned signer"), refused.getMessage());
        assertEquals(0, fixture.replaced.get());
    }

    @Test
    void anExpiredPinnedSignerRetiresTheListAfterItsExp() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        // a stored token whose exp outlives its signer, as a row written before the exp cap (or by another writer) looks
        String listId = "a-retired-cwt-list";
        byte[] token = TokenStatusListCwtBase.storedToken(URI(listId), T0.minus(Duration.ofHours(2)),
                T0.plus(Duration.ofMinutes(30)), new byte[128],
                StatusListTestKeys.key("expired", EXPIRED_KEYS, EXPIRED));
        fixture.rows.put(listId, fixture.row(listId, TokenStatusListService.TYPE_CWT, TokenStatusListCwtBase.envelope(
                new TokenStatusListService.SignerBinding(TokenStatusListService.SIGNER_DOCUMENT,
                        "x509-file:mdl-dsc", StatusListSigners.x5tS256(EXPIRED)), token)));
        fixture.documents.put(listId, fixture.rows.get(listId).getVcDocument());

        // the stored signer expired, but its own exp holds: served as stored, never signed again
        TokenStatusListService.Served served = lists.served(listId).orElseThrow();
        assertArrayEquals(token, served.body());
        assertEquals(0, fixture.signed.get(), "a retired list is never re-signed");

        clock.advance(Duration.ofMinutes(31)); // past its exp
        TokenStatusListGoneException gone = assertThrows(TokenStatusListGoneException.class, () -> lists.served(listId));
        assertTrue(gone.getMessage().contains("retired"), "the 410 is the retirement, not the 503 back-off: " + gone.getMessage());
        assertEquals(0, fixture.signed.get());
        assertEquals(0, fixture.replaced.get());
    }

    @Test
    void aPinnedSignerThatIsGoneAnswers503NeverAnOldBody() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        fixture.switching.available.set(false); // the rotated-away version is no reference any more
        clock.advance(TTL.multipliedBy(2));

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(fixture.listId(entry)));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(String.valueOf(refused.getCause().getMessage()).startsWith(StatusListSigners.GONE),
                String.valueOf(refused.getCause()));
    }

    @Test
    void aPolicyRefusalAtRenewalAnswers503AndNeverAnOldBody() {
        Fixture fixture = new Fixture();
        TokenStatusListService lists = fixture.lists(new MutableClock(T0));
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        // once an IACA anchor is configured the signer is held to it, and the IACA now revokes the Document Signer
        fixture.registry.crl.set(StatusListTestKeys.crl(T0.minus(Duration.ofHours(1)), T0.plus(Duration.ofDays(1)),
                DSC.getSerialNumber()));
        fixture.registry.enforced.set(true);
        fixture.clock.advance(TTL.multipliedBy(2));
        TokenStatusListService enforced = fixture.lists(fixture.clock);

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> enforced.served(fixture.listId(entry)));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(String.valueOf(refused.getCause().getMessage()).startsWith(StatusListSignerPolicy.REVOKED),
                String.valueOf(refused.getCause()));
        // the stored token is still what it was: a refused re-sign never publishes an old exp
        assertEquals(TokenStatusListCwt.decode(TokenStatusListCwtBase.token(
                fixture.rows.get(fixture.listId(entry)).getVcDocument())).exp().getEpochSecond(),
                T0.plus(TTL).plus(TTL).getEpochSecond());
    }

    @Test
    void aFailingSignerIsBackedOffThenAnswered503() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        fixture.switching.failSigning.set(true);
        clock.advance(TTL.multipliedBy(2));

        assertThrows(TokenStatusListUnavailableException.class, () -> lists.served(fixture.listId(entry)));
        int attempts = fixture.signed.get();
        assertThrows(TokenStatusListUnavailableException.class, () -> lists.served(fixture.listId(entry)));
        assertEquals(attempts, fixture.signed.get(), "within the back-off the list is not signed again");

        fixture.switching.failSigning.set(false);
        clock.advance(BACKOFF);
        TokenStatusListService.Served served = lists.served(fixture.listId(entry)).orElseThrow();
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshnessCwt(fixture.listId(entry),
                lists.envelope(fixture.rows.get(fixture.listId(entry)).getVcDocument())));
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, served.mediaType());
    }

    @Test
    void concurrentServesOfADueListSignItOnce() throws Exception {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        fixture.storeBits(listId, TokenStatusListCwt.decode(TokenStatusListCwtBase.token(
                fixture.rows.get(listId).getVcDocument())).lst(), clock.instant());
        clock.advance(TTL.plusSeconds(60));

        int signedBefore = fixture.signed.get();
        List<String> bodies = concurrently(8, () -> Base64.getEncoder().encodeToString(
                lists.served(listId).orElseThrow().body()));
        assertEquals(8, bodies.size());
        assertEquals(1, fixture.replaced.get(), "one re-sign per list at a time; the rest get that token or the stored one");
        assertEquals(1, fixture.signed.get() - signedBefore, "exactly one signature for eight concurrent requests");
        for (String body : bodies) {
            TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(Base64.getDecoder().decode(body));
            assertEquals(entry.uri(), decoded.sub());
            assertEquals(DSC, decoded.x5chain().get(0));
        }
    }

    @Test
    void aRowOfAnotherTypeIsNotFoundAndAnUnknownListIsEmpty() {
        Fixture fixture = new Fixture();
        TokenStatusListService lists = fixture.lists(T0);
        fixture.rows.put("bitstring", fixture.row("bitstring", "BitstringStatusListCredential", "{}"));
        assertTrue(lists.served("bitstring").isEmpty(), "the token endpoint only serves token status lists");
        assertTrue(lists.served("no-such-list").isEmpty());
    }

    /**
     * Review round 1, major 2(c): the schedule that lost a revocation — allocation reads the candidate rows, a revocation
     * commits, then allocation marks the list {@code FULL}. Writing the whole entity would restore the document it read;
     * the status is written on its own, so the committed revocation stays.
     */
    @Test
    void markingAFullListFullKeepsAConcurrentlyCommittedRevocation() {
        Fixture fixture = new Fixture(8);
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry first = lists.allocateCwt("revocation", fixture.dsc());
        for (int index = 1; index < 8; index++) {
            lists.allocateCwt("revocation", fixture.dsc()); // fill the pool: the next allocation marks it FULL
        }
        String listId = fixture.listId(first);
        byte[] bits = TokenStatusListCwt.decode(tokenOf(fixture, listId)).lst().clone();
        TokenStatusListService.set(bits, 0, true);
        AtomicReference<String> committed = new AtomicReference<>();
        fixture.interleave = () -> {
            // the revocation commits between the candidate read and the marking: a re-signed token with the bit set
            fixture.storeBits(listId, bits, T0);
            committed.set(fixture.rows.get(listId).getVcDocument());
            fixture.rows.get(listId).setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        };

        TokenStatusListService.Entry overflow = lists.allocateCwt("revocation", fixture.dsc());

        assertNotEquals(listId, fixture.listId(overflow), "the full list takes no more indices");
        assertEquals(StatusListCredential.CredentialStatus.FULL,
                fixture.rows.get(listId).getCredentialStatus(), "the list is marked FULL");
        assertEquals(committed.get(), fixture.rows.get(listId).getVcDocument(),
                "marking it FULL wrote no document, so the committed revocation is kept");
        assertTrue(TokenStatusListService.get(
                TokenStatusListCwt.decode(tokenOf(fixture, listId)).lst(), 0), "the revoked bit is still set");
    }

    /**
     * Review round 1, major 5: once {@code exp} sits at the signer path's {@code validUntil}, a new signature carries the
     * same {@code exp}; renewing on every request would sign and write without changing a byte. In the last {@code ttl}
     * before {@code notAfter} the list is served as stored.
     */
    @Test
    void theLastTtlBeforeTheSignerNotAfterSignsNothing() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        X509Certificate soon = signerUntil(SOON_KEYS, T0.plus(TTL), "Status List Test Last Hour DSC");
        fixture.provider.add("mdl-dsc@2030-01", SOON_KEYS.getPrivate(), CertificateChain.of(soon, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.signing("x509-file:mdl-dsc@2030-01"));
        assertEquals(soon.getNotAfter().toInstant(), TokenStatusListCwt.decode(
                TokenStatusListCwtBase.token(fixture.rows.get(fixture.listId(entry)).getVcDocument())).exp(),
                "exp is capped at the signer's notAfter");

        clock.advance(TTL.minusSeconds(60)); // less than ttl to go: the old rule renewed on every request
        int signedBefore = fixture.signed.get();
        for (int request = 0; request < 5; request++) {
            assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, lists.served(fixture.listId(entry)).orElseThrow().mediaType());
        }
        assertEquals(signedBefore, fixture.signed.get(), "a capped list is signed no more than once (here: never)");
        assertEquals(0, fixture.replaced.get(), "and nothing is written");
        assertEquals(TokenStatusListService.Freshness.FRESH, lists.freshnessCwt(fixture.listId(entry),
                lists.envelope(fixture.rows.get(fixture.listId(entry)).getVcDocument())));
    }

    /**
     * Review round 1, minor 7: {@code encode} answers the last second of the leaf's validity as retirement, and that has
     * to be the 410, not the 503 — the catch order in {@code served} is what decides it.
     */
    @Test
    void aListInTheSignersLastSecondIsRetiredByEncodeNotByResolve() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        X509Certificate lastSecond = signerUntil(LAST_SECOND_KEYS, T0.plus(TTL), "Status List Test Last Second DSC");
        fixture.provider.add("mdl-dsc@2030-02", LAST_SECOND_KEYS.getPrivate(), CertificateChain.of(lastSecond, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation",
                fixture.signing("x509-file:mdl-dsc@2030-02"));
        String listId = fixture.listId(entry);

        clock.advance(TTL); // exactly notAfter: resolve still accepts the signer, encode cannot give it a second
        TokenStatusListGoneException gone = assertThrows(TokenStatusListGoneException.class, () -> lists.served(listId));
        assertTrue(gone.getMessage().contains("retired"), gone.getMessage());
        assertEquals(0, fixture.replaced.get());
    }

    /**
     * Review round 1, minor 7: an intermediate that ends before the leaf gives {@code STATUS_SIGNER_EXPIRED} at renewal —
     * the back-off and 503, not retirement, because the leaf still has years to run and an operator can issue a new
     * intermediate path.
     */
    @Test
    void anIntermediateEndingFirstIsRefusedExpiredNotRetired() {
        Fixture fixture = new Fixture(1024, Duration.ofDays(20), RENEW_WAIT, BACKOFF);
        MutableClock clock = new MutableClock(T0);
        Instant intermediateEnd = StatusListTestKeys.SHORT_INTERMEDIATE.getNotAfter().toInstant();
        X509Certificate leaf = StatusListTestKeys.signer(INTERMEDIATE_DSC_KEYS, "Status List Test Behind A Short Intermediate",
                StatusListTestKeys.SHORT_INTERMEDIATE, StatusListTestKeys.SHORT_INTERMEDIATE_KEYS,
                List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
                Instant.now().minus(100, java.time.temporal.ChronoUnit.DAYS), Instant.now().plus(200, java.time.temporal.ChronoUnit.DAYS));
        fixture.provider.add("mdl-dsc@2030-03", INTERMEDIATE_DSC_KEYS.getPrivate(),
                CertificateChain.of(leaf, StatusListTestKeys.SHORT_INTERMEDIATE), SignatureAlgorithm.ES256, "mdoc-dsc");
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation",
                fixture.signing("x509-file:mdl-dsc@2030-03"));
        assertEquals(intermediateEnd, TokenStatusListCwt.decode(
                TokenStatusListCwtBase.token(fixture.rows.get(fixture.listId(entry)).getVcDocument())).exp(),
                "exp is capped at the earliest notAfter of the path");

        clock.advance(Duration.between(T0, intermediateEnd).plusSeconds(1));
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(fixture.listId(entry)));
        assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        assertTrue(String.valueOf(refused.getCause().getMessage()).startsWith(StatusListSignerPolicy.EXPIRED),
                String.valueOf(refused.getCause()));
    }

    /** Review round 1, major 3: a document this build cannot read is unusable (503), never the global advice's 500. */
    @Test
    void anUnreadableDocumentIsUnavailableNotAnInternalError() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        String good = fixture.rows.get(listId).getVcDocument();

        for (String document : List.of("not json at all", "{\"v\":2,\"signer\":{\"mode\":\"document-signer\","
                + "\"keyRef\":\"x509-file:mdl-dsc\",\"x5tS256\":\"abc\"},\"token\":\"AAAA\"}", "{}")) {
            fixture.rows.get(listId).setVcDocument(document);
            TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                    () -> lists.served(listId), document);
            assertEquals(BACKOFF.getSeconds(), refused.retryAfterSeconds());
        }
        // and an envelope naming a signer.mode this build does not know is refused on read (nit 8)
        fixture.rows.get(listId).setVcDocument(good.replace("\"document-signer\"", "\"status-signer\""));
        TokenStatusListUnavailableException unknownMode = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(listId));
        assertTrue(unknownMode.getMessage().contains("cannot read"), unknownMode.getMessage());
    }

    /** Review round 1, nit 8: the dedicated mode is read from the envelope, never hard-coded at renewal. */
    @Test
    void aDedicatedListIsResignedUnderItsOwnMode() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        // rewrite the envelope's mode to dedicated: renewal must hold the signer to the .45 EKU, which this Document
        // Signer does not carry, so the refusal proves the stored mode decided
        String document = fixture.rows.get(listId).getVcDocument();
        fixture.rows.get(listId).setVcDocument(document.replace("\"document-signer\"", "\"dedicated\""));
        fixture.registry.enforced.set(true); // the signer rules (purpose included) only run under a configured IACA
        clock.advance(TTL.plusSeconds(60));
        byte[] stored = tokenOf(fixture, listId);

        // the renewal is refused, so the still-valid token is served as stored and nothing is signed or written; the
        // refusal names the *dedicated* purpose, which only the stored mode can ask for
        TokenStatusListService.Served served = lists.served(listId).orElseThrow();
        assertArrayEquals(stored, served.body());
        assertEquals(0, fixture.replaced.get());

        clock.advance(TTL.plus(BACKOFF)); // past exp and past the back-off
        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(listId));
        assertTrue(String.valueOf(refused.getCause().getMessage()).startsWith(StatusListSignerPolicy.PURPOSE),
                String.valueOf(refused.getCause()));
    }

    /**
     * Review round 2, major 5 (GPT's case): the request reads a genuine document, the list is due, and by the time the
     * renewal reads the table it holds a token the pinned signer did not sign. The renewal refuses it, and its fallback
     * must not serve it either: every document read again is checked before it is returned, so the answer is 503.
     */
    @Test
    void aDocumentReadAgainForTheFallbackIsServedOnlyWhenItVerifies() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        String listId = fixture.listId(lists.allocateCwt("revocation", fixture.dsc()));
        StatusListCredential genuine = Fixture.copy(fixture.rows.get(listId));
        fixture.storeToken(listId, TokenStatusListCwtBase.tamperLst(tokenOf(fixture, listId), 9, true));
        // the request's first read still sees the genuine row (open-in-view, or a read just before the write committed)
        when(fixture.repository.findById(listId)).thenReturn(Optional.of(genuine));
        clock.advance(TTL.plusSeconds(60)); // due: the renewal reads the table again and finds the tampered token

        TokenStatusListUnavailableException refused = assertThrows(TokenStatusListUnavailableException.class,
                () -> lists.served(listId));
        assertTrue(refused.getMessage().contains("does not verify with its pinned signer"), refused.getMessage());
        assertEquals(0, fixture.replaced.get(), "nothing is written");
    }

    /**
     * Review round 2, major 5, the retirement branch: the renewal finds the signer retired and reads the table again; a
     * document another writer left there — a later {@code exp} and a flipped bit the pinned certificate did not sign —
     * is checked before it is served as stored, so the answer is 503, not that token.
     */
    @Test
    void aRetiredListsDocumentReadAgainIsServedOnlyWhenItVerifies() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService lists = fixture.lists(clock);
        String listId = "a-retired-cwt-list";
        SigningKey expired = StatusListTestKeys.key("expired", EXPIRED_KEYS, EXPIRED);
        TokenStatusListService.SignerBinding binding = new TokenStatusListService.SignerBinding(
                TokenStatusListService.SIGNER_DOCUMENT, "x509-file:mdl-dsc", StatusListSigners.x5tS256(EXPIRED));
        String stored = TokenStatusListCwtBase.envelope(binding, TokenStatusListCwtBase.storedToken(URI(listId),
                T0.minus(Duration.ofHours(2)), T0.plus(Duration.ofMinutes(30)), new byte[128], expired));
        String forged = TokenStatusListCwtBase.envelope(binding, TokenStatusListCwtBase.tamperLst(
                TokenStatusListCwtBase.storedToken(URI(listId), T0, T0.plus(Duration.ofHours(3)), new byte[128], expired),
                9, true));
        fixture.rows.put(listId, fixture.row(listId, TokenStatusListService.TYPE_CWT, stored));
        when(fixture.repository.findDocumentById(listId)).thenReturn(Optional.of(stored), Optional.of(forged));
        clock.advance(Duration.ofMinutes(31)); // the stored token expired: the renewal finds the signer retired

        assertThrows(TokenStatusListUnavailableException.class, () -> lists.served(listId));
        assertEquals(0, fixture.signed.get());
    }

    /**
     * Review round 2, minor 7: the verification cache is keyed on the whole envelope. Once a list was served, an
     * envelope edited to pin another certificate around the same token is refused by the warm instance exactly as by a
     * cold one.
     */
    @Test
    void aWarmInstanceChecksAnEditedSignerBindingAgain() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        TokenStatusListService warm = fixture.lists(clock);
        String listId = fixture.listId(warm.allocateCwt("revocation", fixture.dsc()));
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, warm.served(listId).orElseThrow().mediaType());

        TokenStatusListService.StoredEnvelope stored = warm.envelope(fixture.rows.get(listId).getVcDocument());
        String edited = TokenStatusListCwtBase.envelope(new TokenStatusListService.SignerBinding(stored.signer().mode(),
                stored.signer().keyRef(), StatusListSigners.x5tS256(DEDICATED)), tokenOf(fixture, listId));
        fixture.rows.get(listId).setVcDocument(edited);
        fixture.documents.put(listId, edited);

        assertThrows(TokenStatusListUnavailableException.class, () -> warm.served(listId), "the warm instance");
        assertThrows(TokenStatusListUnavailableException.class, () -> fixture.lists(clock).served(listId), "a cold one");
    }

    /**
     * Review round 2, minor 8: in a list's last {@code ttl} before its signer's {@code notAfter} every request used to
     * resolve the signer through the key provider to learn that a new signature could not push {@code exp} later. The
     * cap comes from the signer's own certificates now: serving asks the provider for nothing, warm or cold.
     */
    @Test
    void servingAListInItsLastTtlAsksTheKeyProviderForNothing() {
        Fixture fixture = new Fixture();
        MutableClock clock = new MutableClock(T0);
        X509Certificate soon = signerUntil(SOON_KEYS, T0.plus(TTL), "Status List Test Last Hour DSC");
        fixture.provider.add("mdl-dsc@2030-01", SOON_KEYS.getPrivate(), CertificateChain.of(soon, IACA),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        TokenStatusListService lists = fixture.lists(clock);
        String listId = fixture.listId(lists.allocateCwt("revocation", fixture.signing("x509-file:mdl-dsc@2030-01")));
        clock.advance(TTL.minusSeconds(60));

        int resolvedBefore = fixture.resolved.get();
        for (int request = 0; request < 5; request++) {
            lists.served(listId).orElseThrow();
            fixture.lists(clock).served(listId).orElseThrow(); // a cold instance computes it from the stored x5chain
        }
        assertEquals(resolvedBefore, fixture.resolved.get(), "no key-provider lookup while serving");
        assertEquals(0, fixture.replaced.get());
    }

    /** The IACA re-issue of the serving-path G45 case: one key and name, two validity windows. */
    static final java.security.KeyPair REISSUE_IACA_KEYS = StatusListTestKeys.p256();
    static final java.security.KeyPair UNDER_REISSUE_KEYS = StatusListTestKeys.p256();

    static X509Certificate reissueIaca(Instant notBefore, Duration validity) {
        return io.mosip.certify.pki.IsoMdocProfiles.iaca(REISSUE_IACA_KEYS).country("IN")
                .commonName("Status List Test Reissue IACA").issuerAltUri("https://reissue.example.test")
                .crlDistributionPoint("https://reissue.example.test/iaca.crl").notBefore(notBefore).validity(validity).build();
    }

    /**
     * Review round 5, finding 2 (G45 on the serving path): an instance caches the {@code validUntil} of a list's signer
     * path, capped by the IACA in use (A). Once A's re-issue B — same name and key, staged ahead of time — is valid,
     * another instance re-signs the list under B with an {@code exp} past A's {@code notAfter}. Served in the token's last
     * {@code ttl}, the instances that cached A's date must renew it early, both before A ends (the re-issue became valid
     * after their cache was filled) and after it: with the cache keyed only on the list and the pin they kept the cap at
     * A's {@code notAfter}, judged the list {@code FRESH}, and let it expire.
     */
    @Test
    void aCachedCapOfAnIacaThatEndedOrWasSupersededDoesNotStopAnEarlyRenewal() {
        X509Certificate iacaA = reissueIaca(T0.minus(Duration.ofDays(100)), Duration.ofDays(110)); // ends T0 + 10d
        X509Certificate iacaB = reissueIaca(T0.plus(Duration.ofDays(5)), Duration.ofDays(400)); // staged: valid from T0 + 5d
        X509Certificate dsc = StatusListTestKeys.signer(UNDER_REISSUE_KEYS, "Status List Test Under A Reissued IACA", iacaA,
                REISSUE_IACA_KEYS, List.of(StatusListSignerPolicy.DOCUMENT_SIGNER_EKU), true,
                T0.minus(Duration.ofDays(50)), T0.plus(Duration.ofDays(200)));
        Instant endOfA = iacaA.getNotAfter().toInstant();
        TrustAnchorRegistry anchors = new TrustAnchorRegistry() {
            @Override
            public List<Anchor> entries(String purpose) {
                return MDOC_IACA.equals(purpose) ? List.of(new Anchor("iaca-a", MDOC_IACA, iacaA),
                        new Anchor("iaca-b", MDOC_IACA, iacaB)) : List.of();
            }

            @Override
            public Optional<X509CRL> crl(String anchorId) {
                return Optional.empty();
            }
        };
        Fixture fixture = new Fixture();
        fixture.provider.add("mdl-dsc@2030-02", UNDER_REISSUE_KEYS.getPrivate(), CertificateChain.of(dsc),
                SignatureAlgorithm.ES256, "mdoc-dsc");
        MutableClock clock = new MutableClock(T0);
        java.util.function.Supplier<TokenStatusListService> instance = () -> new TokenStatusListService(fixture.repository,
                fixture.bitstringLists, fixture.indexProvider, fixture.counting(fixture.keys), fixture.properties,
                fixture.objectMapper, fixture.environment(), clock, anchors);

        // instance 1 creates the list under A (B is not valid yet): it caches A's notAfter as the cap
        TokenStatusListService first = instance.get();
        String listId = fixture.listId(first.allocateCwt("revocation", fixture.signing("x509-file:mdl-dsc@2030-02")));
        // instance 2 judges the list in its last ttl, still before B is valid: it caches A's notAfter too
        TokenStatusListService second = instance.get();
        clock.advance(TTL.plusMinutes(1));
        assertEquals(TokenStatusListService.Freshness.RENEW, freshness(second, fixture, listId));

        // B is valid; instance 3 re-signs the expired list, under B: exp is past A's notAfter
        clock.advance(Duration.between(clock.instant(), endOfA.minus(Duration.ofMinutes(90))));
        TokenStatusListService third = instance.get();
        third.served(listId).orElseThrow();
        Instant exp = TokenStatusListCwt.decode(tokenOf(fixture, listId)).exp();
        assertEquals(clock.instant().plus(TTL).plus(TTL).getEpochSecond(), exp.getEpochSecond(), "signed under B, not capped by A");
        assertTrue(exp.isAfter(endOfA));

        // in the token's last ttl, A still valid: the re-issue that became valid since instance 1's cache was filled counts
        clock.advance(Duration.ofMinutes(70));
        assertTrue(clock.instant().isBefore(endOfA));
        assertEquals(TokenStatusListService.Freshness.RENEW, freshness(first, fixture, listId),
                "renewed early before A ends: the cached cap was A's notAfter");
        // and after A ended (the reviewer's case)
        clock.advance(Duration.ofMinutes(21));
        assertTrue(clock.instant().isAfter(endOfA));
        assertEquals(TokenStatusListService.Freshness.RENEW, freshness(second, fixture, listId),
                "renewed early after A ended: the cached cap was in the past");
        Instant before = clock.instant();
        second.served(listId).orElseThrow();
        TokenStatusListCwt.Decoded renewed = TokenStatusListCwt.decode(tokenOf(fixture, listId));
        assertEquals(before.getEpochSecond(), renewed.iat().getEpochSecond(), "signed again now");
        assertEquals(before.plus(TTL).plus(TTL).getEpochSecond(), renewed.exp().getEpochSecond());
        assertEquals(dsc, renewed.x5chain().get(0), "by the pinned signer");
    }

    private static TokenStatusListService.Freshness freshness(TokenStatusListService lists, Fixture fixture, String listId) {
        return lists.freshnessCwt(listId, lists.envelope(fixture.rows.get(listId).getVcDocument()));
    }

    private static byte[] tokenOf(Fixture fixture, String listId) {
        return TokenStatusListCwtBase.token(fixture.rows.get(listId).getVcDocument());
    }

    @Test
    void theMdocSettingsRefuseWhatThisBuildDoesNotImplement() {
        TokenStatusListProperties.Mdoc defaults = new TokenStatusListProperties.Mdoc(null, null, null);
        assertEquals(TokenStatusListProperties.Mdoc.FORMAT_CWT, defaults.tokenFormat(), "CWT by default (D-M11-3)");
        assertEquals(TokenStatusListProperties.Mdoc.SIGNER_DOCUMENT, defaults.signer(), "the Document Signer by default");
        assertNull(defaults.keyRef());
        assertEquals(TokenStatusListProperties.Mdoc.FORMAT_JWT,
                new TokenStatusListProperties.Mdoc("jwt", null, null).tokenFormat(), "the escape hatch is accepted");

        assertThrows(IllegalArgumentException.class, () -> new TokenStatusListProperties.Mdoc("vc+sd-jwt", null, null));
        // nit 8: a list the codec cannot read back is refused at binding, never at the first request
        assertThrows(IllegalArgumentException.class,
                () -> new TokenStatusListProperties(null, "ES256", "leaf", 0, TTL, RENEW_WAIT, BACKOFF, null));
        assertThrows(IllegalArgumentException.class,
                () -> new TokenStatusListProperties(null, "ES256", "leaf", 12, TTL, RENEW_WAIT, BACKOFF, null));
        assertThrows(IllegalArgumentException.class, () -> new TokenStatusListProperties(null, "ES256", "leaf",
                TokenStatusListCwt.MAX_BITS + 8, TTL, RENEW_WAIT, BACKOFF, null));
        assertThrows(IllegalArgumentException.class, () -> new TokenStatusListProperties.Mdoc("cwt", "status-signer", null));
        IllegalArgumentException dedicated = assertThrows(IllegalArgumentException.class,
                () -> new TokenStatusListProperties.Mdoc("cwt", "dedicated", null));
        assertTrue(dedicated.getMessage().contains("available from M-11h"), dedicated.getMessage());
        IllegalArgumentException keyRef = assertThrows(IllegalArgumentException.class,
                () -> new TokenStatusListProperties.Mdoc("cwt", "document-signer", "x509-file:mdl-status"));
        assertTrue(keyRef.getMessage().contains("key-ref"), keyRef.getMessage());
    }

    /**
     * {@code mdoc.token-format=jwt} is D-M11-3's escape hatch, and the one startup line that warns the operator what it
     * costs: ISO/IEC 18013-5 second edition 12.3.6.3 makes an mDoc's status list a CWT, so Paradym and Credo refuse a
     * JWT list.
     */
    @Test
    void theJwtEscapeHatchWarnsAtStartup() {
        Fixture fixture = new Fixture();
        fixture.jwtTokenFormat = true;
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(TokenStatusListService.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            fixture.lists(T0);
        } finally {
            logger.detachAppender(appender);
        }
        assertTrue(appender.list.stream().anyMatch(event -> event.getLevel() == ch.qos.logback.classic.Level.WARN
                        && event.getFormattedMessage().contains("12.3.6.3")),
                "the escape hatch logs one WARN citing ISO/IEC 18013-5 second edition 12.3.6.3: "
                        + appender.list.stream().map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).toList());
        assertTrue(appender.list.stream().anyMatch(event -> event.getLevel() == ch.qos.logback.classic.Level.INFO
                        && event.getFormattedMessage().contains("not enforced")),
                "and the INFO line says the trust-anchor rules do not apply");
    }

    // ---- fixture -----------------------------------------------------------------------------------------------

    /**
     * The service over an in-memory repository (a Mockito mock with the answers a table would give), a monotonic index
     * provider, the real {@link JcaKeyProvider} holding the test Document Signer under a versioned alias, and a provider
     * the tests can make unavailable or failing.
     */
    static final class Fixture {

        final Map<String, String> documents = new ConcurrentHashMap<>();
        final Map<String, StatusListCredential> rows = new ConcurrentHashMap<>();
        final Map<String, Long> nextIndex = new ConcurrentHashMap<>();
        final Map<String, Integer> sequence = new ConcurrentHashMap<>();
        final AtomicInteger replaced = new AtomicInteger();
        final AtomicInteger signed = new AtomicInteger();
        /** Every key-provider lookup the services built here make (pinning, re-signing; never serving). */
        final AtomicInteger resolved = new AtomicInteger();
        final AtomicInteger sequenceCounter = new AtomicInteger();

        final JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        final SwitchingProvider switching;
        final KeyProviderRegistry keys;
        final StatusListCredentialRepository repository = mock(StatusListCredentialRepository.class);
        final StatusListIndexProvider indexProvider = mock(StatusListIndexProvider.class);
        final StatusListCredentialService bitstringLists = mock(StatusListCredentialService.class);
        final ObjectMapper objectMapper = new ObjectMapper();
        final MutableRegistry registry = new MutableRegistry();
        /** Run once inside the next candidate read, after the rows were projected: a concurrent commit (tests). */
        Runnable interleave = () -> { };
        TokenStatusListProperties properties;
        MutableClock clock;
        /** Whether the services this fixture builds use {@code mdoc.token-format=jwt} (D-M11-3's escape hatch). */
        boolean jwtTokenFormat;

        Fixture() {
            this(1024, TTL, RENEW_WAIT, BACKOFF);
        }

        Fixture(int sizeBits) {
            this(sizeBits, TTL, RENEW_WAIT, BACKOFF);
        }

        Fixture(int sizeBits, Duration ttl, Duration renewWait, Duration backoff) {
            properties = new TokenStatusListProperties("x509-file:mdl-dsc", "ES256", "leaf", sizeBits, ttl, renewWait, backoff, null);
            clock = new MutableClock(T0);
            provider.add("mdl-dsc@2026-11", DSC_KEYS.getPrivate(), CertificateChain.of(DSC, IACA), SignatureAlgorithm.ES256,
                    "mdoc-dsc");
            switching = new SwitchingProvider(provider);
            keys = new KeyProviderRegistry(List.of(switching));
            registry.crl.set(freshCrl());

            when(repository.findById(anyString())).thenAnswer(inv ->
                    Optional.ofNullable(rows.get(inv.<String>getArgument(0))).map(Fixture::copy));
            when(repository.save(any(StatusListCredential.class))).thenAnswer(inv -> save(inv.getArgument(0)));
            when(repository.saveAndFlush(any(StatusListCredential.class))).thenAnswer(inv -> save(inv.getArgument(0)));
            when(repository.replaceDocument(anyString(), anyString(), anyString())).thenAnswer(inv -> {
                String id = inv.getArgument(0);
                String previous = inv.getArgument(1);
                StatusListCredential row = rows.get(id);
                if (row == null || !previous.equals(row.getVcDocument())) {
                    return 0;
                }
                row.setVcDocument(inv.getArgument(2));
                documents.put(id, row.getVcDocument());
                replaced.incrementAndGet();
                return 1;
            });
            when(repository.findCwtCandidates(anyString(), anyString(), any())).thenAnswer(inv -> {
                List<StatusListCredentialRepository.CwtCandidate> projected = rows.values().stream()
                        .filter(row -> inv.getArgument(0).equals(row.getCredentialType()))
                        .filter(row -> inv.getArgument(1).equals(row.getStatusPurpose()))
                        .filter(row -> inv.getArgument(2).equals(row.getCredentialStatus()))
                        .sorted(Comparator.comparing(StatusListCredential::getCreatedDtimes)
                                .thenComparing(row -> sequence.getOrDefault(row.getId(), 0)).reversed())
                        .map(row -> (StatusListCredentialRepository.CwtCandidate) new Candidate(row.getId(), row.getVcDocument()))
                        .toList();
                Runnable concurrent = interleave;
                interleave = () -> { };
                concurrent.run(); // a revocation commits now, after the rows (and their documents) were read
                return projected;
            });
            when(repository.findByIdForUpdate(anyString())).thenAnswer(inv ->
                    Optional.ofNullable(rows.get(inv.<String>getArgument(0))).map(Fixture::copy));
            when(repository.findDocumentById(anyString())).thenAnswer(inv ->
                    Optional.ofNullable(rows.get(inv.<String>getArgument(0))).map(StatusListCredential::getVcDocument));
            when(repository.updateCredentialStatus(anyString(), any())).thenAnswer(inv -> {
                StatusListCredential row = rows.get(inv.<String>getArgument(0));
                if (row == null) {
                    return 0;
                }
                row.setCredentialStatus(inv.getArgument(1));
                return 1;
            });
            when(repository.findFirstByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
                    anyString(), anyString(), any())).thenAnswer(inv -> rows.values().stream()
                    .filter(row -> inv.getArgument(0).equals(row.getCredentialType()))
                    .filter(row -> inv.getArgument(1).equals(row.getStatusPurpose()))
                    .filter(row -> inv.getArgument(2).equals(row.getCredentialStatus()))
                    .findFirst());
            when(repository.findByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
                    anyString(), anyString(), any())).thenAnswer(inv -> rows.values().stream()
                    .filter(row -> inv.getArgument(0).equals(row.getCredentialType()))
                    .filter(row -> inv.getArgument(1).equals(row.getStatusPurpose()))
                    .filter(row -> inv.getArgument(2).equals(row.getCredentialStatus()))
                    .sorted(Comparator.comparing(StatusListCredential::getCreatedDtimes)
                            .thenComparing(row -> sequence.getOrDefault(row.getId(), 0)).reversed())
                    .map(Fixture::copy).toList());
            when(indexProvider.acquireIndex(anyString(), any())).thenAnswer(inv -> {
                String id = inv.getArgument(0);
                long next = nextIndex.merge(id, 1L, Long::sum) - 1;
                return next < sizeBits ? Optional.of(next) : Optional.<Long>empty();
            });
        }

        private StatusListCredential save(StatusListCredential row) {
            rows.put(row.getId(), copy(row));
            documents.put(row.getId(), row.getVcDocument());
            sequence.putIfAbsent(row.getId(), sequenceCounter.incrementAndGet());
            return row;
        }

        static StatusListCredential copy(StatusListCredential row) {
            StatusListCredential copy = new StatusListCredential();
            copy.setId(row.getId());
            copy.setVcDocument(row.getVcDocument());
            copy.setCredentialType(row.getCredentialType());
            copy.setStatusPurpose(row.getStatusPurpose());
            copy.setCapacityInKB(row.getCapacityInKB());
            copy.setCredentialStatus(row.getCredentialStatus());
            copy.setCreatedDtimes(row.getCreatedDtimes());
            copy.setUpdatedDtimes(row.getUpdatedDtimes());
            return copy;
        }

        StatusListCredential row(String id, String type, String document) {
            StatusListCredential row = new StatusListCredential();
            row.setId(id);
            row.setVcDocument(document);
            row.setCredentialType(type);
            row.setStatusPurpose("revocation");
            row.setCapacityInKB(1L);
            row.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
            row.setCreatedDtimes(LocalDateTime.now());
            return row;
        }

        /** The projection row allocation reads. */
        record Candidate(String id, String vcDocument) implements StatusListCredentialRepository.CwtCandidate {
            @Override
            public String getId() {
                return id;
            }

            @Override
            public String getVcDocument() {
                return vcDocument;
            }
        }

        TokenStatusListService lists(Instant now) {
            return lists(Clock.fixed(now, ZoneOffset.UTC));
        }

        TokenStatusListService lists(Clock withClock) {
            return lists(withClock, DOMAIN);
        }

        TokenStatusListService lists(Clock withClock, String domain) {
            MockEnvironment environment = new MockEnvironment()
                    .withProperty("mosip.certify.domain.url", domain)
                    .withProperty("server.servlet.path", SERVLET_PATH);
            TokenStatusListProperties bound = properties;
            if (jwtTokenFormat) {
                bound = new TokenStatusListProperties(properties.keyRef(), properties.alg(), properties.x5c(),
                        properties.sizeBits(), properties.ttl(), properties.renewWait(), properties.renewBackoff(),
                        new TokenStatusListProperties.Mdoc(TokenStatusListProperties.Mdoc.FORMAT_JWT, null, null));
            }
            return new TokenStatusListService(repository, bitstringLists, indexProvider, counting(keys), bound,
                    objectMapper, environment, withClock, registry);
        }

        /** The registry, counting every signer invocation so a refusal can be proved to reach no signer. */
        KeyProviderRegistry counting(KeyProviderRegistry delegate) {
            KeyProvider counting = new KeyProvider() {
                @Override
                public String id() {
                    return delegate.all().get(0).id();
                }

                @Override
                public SigningKey resolve(KeyRef ref) {
                    resolved.incrementAndGet();
                    return delegate.provider(id()).resolve(ref);
                }

                @Override
                public List<PublicKeyDescriptor> publicKeys(io.mosip.certify.signing.KeyFilter filter) {
                    return delegate.provider(id()).publicKeys(filter);
                }

                @Override
                public Set<SignatureAlgorithm> supportedAlgorithms() {
                    return delegate.provider(id()).supportedAlgorithms();
                }

                @Override
                public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
                    signed.incrementAndGet();
                    return delegate.provider(id()).signRaw(data, key, algorithm);
                }
            };
            return new KeyProviderRegistry(List.of(counting));
        }

        SigningContext dsc() {
            return signing("x509-file:mdl-dsc");
        }

        SigningContext signing(String ref) {
            return signing(KeyRef.parse(ref));
        }

        /** A signing context over the provider's alias, or over a key the provider does not hold. */
        SigningContext signing(KeyRef ref) {
            try {
                return keys.signingContext(SigningConfig.of(ref, SignatureAlgorithm.ES256));
            } catch (RuntimeException e) {
                throw new AssertionError("the fixture must hold " + ref, e);
            }
        }

        SigningContext signing(java.security.KeyPair pair, X509Certificate certificate) {
            return StatusListTestKeys.context(pair, certificate, IACA);
        }

        String listId(TokenStatusListService.Entry entry) {
            return entry.uri().substring(entry.uri().lastIndexOf('/') + 1);
        }

        /** Replaces a stored token with one whose bits are {@code bits}, signed at {@code at} (as an older writer left it). */
        void storeBits(String listId, byte[] bits, Instant at) {
            TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(
                    TokenStatusListCwtBase.token(rows.get(listId).getVcDocument()));
            storeToken(listId, TokenStatusListCwtBase.encode(decoded.sub(), at, decoded.exp(),
                    Duration.ofSeconds(decoded.ttl()), bits, dsc()));
        }

        void storeToken(String listId, byte[] token) {
            TokenStatusListService.StoredEnvelope stored;
            try {
                stored = objectMapper.readValue(rows.get(listId).getVcDocument(), TokenStatusListService.StoredEnvelope.class);
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
            rows.get(listId).setVcDocument(TokenStatusListCwtBase.envelope(stored.signer(), token));
            documents.put(listId, rows.get(listId).getVcDocument());
        }

        MockEnvironment environment() {
            return new MockEnvironment().withProperty("mosip.certify.domain.url", DOMAIN)
                    .withProperty("server.servlet.path", SERVLET_PATH);
        }
    }

    /** The properties the token codec needs to sign at a fixed instant, without going through the service. */
    static final class TokenStatusListCwtBase {

        static byte[] encode(String sub, Instant iat, Instant exp, Duration ttl, byte[] bits, SigningContext signing) {
            return TokenStatusListCwt.encode(sub, iat, exp, ttl, bits, signing, StatusListSignerPolicy.notEnforced(), iat,
                    StatusListSignerPolicy.Mode.DOCUMENT_SIGNER);
        }

        static String envelope(TokenStatusListService.SignerBinding signer, byte[] token) {
            try {
                return new ObjectMapper().writeValueAsString(new TokenStatusListService.StoredEnvelope(
                        TokenStatusListService.ENVELOPE_VERSION, signer,
                        Base64.getUrlEncoder().withoutPadding().encodeToString(token)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        static byte[] token(String document) {
            try {
                return Base64.getUrlDecoder().decode(new ObjectMapper()
                        .readValue(document, TokenStatusListService.StoredEnvelope.class).token());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /** A CWT signed with the given key, used where {@code encode}'s exp cap must be bypassed (a foreign writer's row). */
        static byte[] storedToken(String sub, Instant iat, Instant exp, byte[] bits, SigningKey key) {
            LinkedHashMap<Integer, CBORObject> claims = new LinkedHashMap<>();
            claims.put(TokenStatusListCwt.CLAIM_SUB, CBORObject.FromObject(sub));
            claims.put(TokenStatusListCwt.CLAIM_EXP, CBORObject.FromObject(exp.getEpochSecond()));
            claims.put(TokenStatusListCwt.CLAIM_IAT, CBORObject.FromObject(iat.getEpochSecond()));
            claims.put(TokenStatusListCwt.CLAIM_STATUS_LIST, CBORObject.NewOrderedMap()
                    .Add(CBORObject.FromObject("lst"), CBORObject.FromObject(TokenStatusListService.zlib(bits)))
                    .Add(CBORObject.FromObject("bits"), CBORObject.FromObject(1)));
            claims.put(TokenStatusListCwt.CLAIM_TTL, CBORObject.FromObject(3600L));
            return CwtEnvelope.signOrdered(claims, CoseHeaderPolicy.statusListCwt(), key, StatusListTestKeys.SIGNER);
        }

        /** One bit of {@code lst} written inside the payload, with the signature left untouched (a tampered row). */
        static byte[] tamperLst(byte[] token, long idx, boolean value) {
            CBORObject sign1 = CBORObject.DecodeFromBytes(token).UntagOne();
            CBORObject claims = CBORObject.DecodeFromBytes(sign1.get(2).GetByteString());
            CBORObject statusList = claims.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST));
            byte[] bits = TokenStatusListCwt.inflate(statusList.get(CBORObject.FromObject("lst")).GetByteString(),
                    TokenStatusListCwt.MAX_BITS / 8);
            TokenStatusListService.set(bits, idx, value);
            statusList.set(CBORObject.FromObject("lst"), CBORObject.FromObject(TokenStatusListService.zlib(bits)));
            CBORObject rebuilt = CBORObject.NewArray()
                    .Add(sign1.get(0))
                    .Add(sign1.get(1))
                    .Add(CBORObject.FromObject(claims.EncodeToBytes()))
                    .Add(sign1.get(3));
            return CBORObject.FromObjectAndTag(rebuilt, CoseEnvelope.TAG_COSE_SIGN1).EncodeToBytes();
        }
    }

    /** A provider whose alias a test can make unavailable or whose signing can be made to fail (rotation, HSM outage). */
    static final class SwitchingProvider implements KeyProvider {

        private final KeyProvider delegate;
        final AtomicBoolean available = new AtomicBoolean(true);
        final AtomicBoolean failSigning = new AtomicBoolean(false);

        SwitchingProvider(KeyProvider delegate) {
            this.delegate = delegate;
        }

        @Override
        public String id() {
            return delegate.id();
        }

        @Override
        public SigningKey resolve(KeyRef ref) {
            if (!available.get()) {
                throw new SigningException("No key with alias '" + ref.alias() + "' in provider " + id());
            }
            return delegate.resolve(ref);
        }

        @Override
        public List<PublicKeyDescriptor> publicKeys(io.mosip.certify.signing.KeyFilter filter) {
            return delegate.publicKeys(filter);
        }

        @Override
        public Set<SignatureAlgorithm> supportedAlgorithms() {
            return delegate.supportedAlgorithms();
        }

        @Override
        public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
            if (failSigning.get()) {
                throw new SigningException("HSM session lost");
            }
            return delegate.signRaw(data, key, algorithm);
        }
    }

    /** A registry whose one IACA anchor and CRL a test can change. */
    static final class MutableRegistry implements TrustAnchorRegistry {

        final AtomicReference<X509CRL> crl = new AtomicReference<>();
        /** Whether an {@code mdoc-iaca} anchor is configured: the D16 switch of section 4.7. */
        final AtomicBoolean enforced = new AtomicBoolean(false);

        @Override
        public List<Anchor> entries(String purpose) {
            return enforced.get() && MDOC_IACA.equals(purpose)
                    ? List.of(new Anchor("test-iaca", MDOC_IACA, IACA)) : List.of();
        }

        @Override
        public Optional<X509CRL> crl(String anchorId) {
            return Optional.ofNullable(crl.get());
        }
    }

    /** A clock the test moves. */
    static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            now = new AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(instant -> instant.plus(by));
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

    static List<String> concurrently(int threads, Callable<String> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int index = 0; index < threads; index++) {
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

    static {
        // the fixture certificates are built relative to now; the test instants must sit inside their validity
        if (!DSC.getNotAfter().toInstant().isAfter(T0)) {
            throw new IllegalStateException("the fixture Document Signer must outlive " + T0);
        }
    }

    /** The URI a list is served at, for the stored rows a test writes by hand. */
    static String URI(String listId) {
        return DOMAIN + SERVLET_PATH + "/credentials/token-status-list/" + listId;
    }
}
