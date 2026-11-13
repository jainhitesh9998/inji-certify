package io.mosip.certify.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.registry.JpaConfigurationRegistry;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.services.StatusListIndexProvider;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KidStrategy;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Token Status Lists (draft-ietf-oauth-status-list): rows of {@code status_list_credential} whose type is
 * {@link #TYPE}, the document being the signed list itself ({@code typ statuslist+jwt}, {@code sub} its URI,
 * {@code status_list.bits} 1, {@code status_list.lst} the zlib-compressed bit array, least significant bit first).
 * Indices come from the same {@code status_list_available_indices} rows as the Bitstring lists.
 *
 * <p>Freshness: a list JWT expires ({@code exp = iat + 2 ttl}) and its {@code sub} must equal the URI the referenced
 * tokens carry (draft-ietf-oauth-status-list sections 5.1 and 8.3), yet a list is otherwise signed only when a status
 * changes. So a served list whose {@code exp} is less than {@code ttl} away, or whose {@code sub} is not the list's URI
 * under the current {@code mosip.certify.domain.url}, is signed again before it is returned, with the same bits. The
 * new document replaces the stored one only if that one is still unchanged (compare-and-set), so a re-sign never undoes
 * a status change; one request per list re-signs at a time while the others are served the previous, still valid, list,
 * or, when it is not valid, wait for the re-sign at most {@code renew-wait}. After a failed re-sign the list is not signed
 * again for {@code renew-backoff}. An expired list is never served: the endpoint answers 503 with {@code Retry-After}.
 */
@Slf4j
@Service
@EnableConfigurationProperties(TokenStatusListProperties.class)
public class TokenStatusListService {

    public static final String TYPE = "TokenStatusList";
    public static final String MEDIA_TYPE = "application/statuslist+jwt";
    public static final String TYP = "statuslist+jwt";
    static final String PATH = "/credentials/token-status-list/";

    public record Entry(String uri, long idx) {}

    private final StatusListCredentialRepository repository;
    private final StatusListCredentialService bitstringLists;
    private final StatusListIndexProvider indexProvider;
    private final KeyProviderRegistry keyProviders;
    private final TokenStatusListProperties properties;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final Clock clock;
    /** One re-sign per list at a time in this instance; other instances are kept consistent by the compare-and-set. */
    private final ConcurrentMap<String, ReentrantLock> renewals = new ConcurrentHashMap<>();
    /** Per list, when its last re-sign failed; it is not signed again within {@code renew-backoff} of that instant. */
    private final ConcurrentMap<String, Instant> failures = new ConcurrentHashMap<>();

    @Autowired
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment) {
        this(repository, bitstringLists, indexProvider, keyProviders, properties, objectMapper, environment, Clock.systemUTC());
    }

    /** As the bean, with the clock that stamps {@code iat}/{@code exp} and decides freshness (tests sign lists in the past). */
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment,
                                  Clock clock) {
        this.clock = clock;
        this.repository = repository;
        this.bitstringLists = bitstringLists;
        this.indexProvider = indexProvider;
        this.keyProviders = keyProviders;
        this.properties = properties;
        this.objectMapper = objectMapper;
        String domain = environment.getRequiredProperty("mosip.certify.domain.url").replaceAll("/+$", "");
        String servletPath = environment.getProperty("server.servlet.path", "").replaceAll("/+$", "");
        this.baseUrl = domain + servletPath;
    }

    public String uri(String listId) {
        return baseUrl + PATH + listId;
    }

    /** A free index in the current list for the purpose, creating the next list when the current one is full. */
    @Transactional
    public Entry allocate(String purpose) {
        StatusListCredential list = repository.findFirstByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
                TYPE, purpose, StatusListCredential.CredentialStatus.AVAILABLE).orElseGet(() -> create(purpose));
        Optional<Long> index = indexProvider.acquireIndex(list.getId(), Map.of());
        if (index.isEmpty()) {
            list.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
            repository.save(list);
            list = create(purpose);
            index = indexProvider.acquireIndex(list.getId(), Map.of());
        }
        long idx = index.orElseThrow(() -> new IllegalStateException("No free index in token status list " + purpose));
        return new Entry(uri(list.getId()), idx);
    }

    /**
     * The list JWT to serve: the stored one while it is fresh, otherwise the list signed again (same bits, new
     * {@code iat}/{@code exp}, {@code sub} the current URI). A list that is only due for renewal is served as stored
     * when another request is renewing it, when the renewal fails, or within {@code renew-backoff} of a failed renewal;
     * an expired list, or one whose {@code sub} is not the current URI, is never served as stored. Whatever is served as
     * stored is judged against the clock at the moment it is returned, not when the request began.
     *
     * <p>A request for an unusable list waits at most {@code renew-wait} for the request that is signing it again, so a
     * stalled signer holds one request thread per list, not every thread that asks for the list.
     *
     * @throws TokenStatusListUnavailableException when the list is unusable and cannot be signed again now
     */
    public Optional<String> jwt(String listId) {
        Optional<String> stored = repository.findById(listId).filter(l -> TYPE.equals(l.getCredentialType())).map(StatusListCredential::getVcDocument);
        if (stored.isEmpty()) {
            return stored;
        }
        Freshness freshness = freshness(listId, stored.get());
        if (freshness == Freshness.FRESH) {
            return stored;
        }
        Optional<Duration> backingOff = backingOff(listId);
        if (backingOff.isPresent()) {
            return Optional.of(servedAsStored(listId, stored.get(), backingOff.get(), null));
        }
        ReentrantLock lock = renewals.computeIfAbsent(listId, id -> new ReentrantLock());
        if (!acquire(listId, lock, freshness)) {
            // only a list that is merely due gets here: another request is signing it again, this one is still valid
            return Optional.of(servedAsStored(listId, stored.get(), properties.renewWait(), null));
        }
        try {
            backingOff = backingOff(listId); // the request this one waited for may have failed meanwhile
            if (backingOff.isPresent()) {
                return Optional.of(servedAsStored(listId, latest(listId, stored.get()), backingOff.get(), null));
            }
            String renewed;
            try {
                renewed = renew(listId);
            } catch (RuntimeException e) {
                failed(listId, e);
                return Optional.of(servedAsStored(listId, latest(listId, stored.get()), properties.renewBackoff(), e));
            }
            failures.remove(listId);
            return Optional.of(usableRenewal(listId, renewed));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Takes the list's renewal lock: at once or not at all for a list that is still valid, within {@code renew-wait} for
     * one that is not (serving it as stored is no option).
     *
     * @return false when a still-valid list's lock is held by another request
     * @throws TokenStatusListUnavailableException when an unusable list's lock is not free within {@code renew-wait}
     */
    private boolean acquire(String listId, ReentrantLock lock, Freshness freshness) {
        if (freshness == Freshness.RENEW) {
            return lock.tryLock();
        }
        try {
            if (lock.tryLock(properties.renewWait().toNanos(), TimeUnit.NANOSECONDS)) {
                return true;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenStatusListUnavailableException("Interrupted while token status list " + listId + " was signed again",
                    properties.renewWait(), e);
        }
        log.warn("Token status list {} is expired or under another URI and still being signed again after {}; answering 503",
                listId, properties.renewWait());
        throw new TokenStatusListUnavailableException("Token status list " + listId + " is still being signed again after "
                + properties.renewWait(), properties.renewWait(), null);
    }

    /**
     * The document as stored, when it is still usable now; a document that expired (or is under another URI) is never
     * served, whatever it was when the request began.
     *
     * @throws TokenStatusListUnavailableException otherwise, with {@code retryAfter}
     */
    private String servedAsStored(String listId, String document, Duration retryAfter, RuntimeException cause) {
        if (freshness(listId, document) != Freshness.UNUSABLE) {
            return document;
        }
        throw new TokenStatusListUnavailableException("Token status list " + listId
                + " is expired or under another URI and could not be signed again", retryAfter, cause);
    }

    /**
     * The renewed document, judged against the clock when it is returned: {@code exp} is stamped before the signer runs,
     * so a signer that answers after it has passed (an HSM or keymanager stall longer than two {@code ttl}) yields a list
     * that is already expired. Such a renewal counts as a failure (back-off, logged once); the list as stored now is
     * served if another writer left a usable one, otherwise 503 with {@code Retry-After}.
     */
    private String usableRenewal(String listId, String renewed) {
        if (freshness(listId, renewed) != Freshness.UNUSABLE) {
            return renewed;
        }
        IllegalStateException stale = new IllegalStateException("Token status list " + listId
                + " was signed again but had expired by the time the signer answered");
        failed(listId, stale);
        return servedAsStored(listId, latest(listId, renewed), properties.renewBackoff(), stale);
    }

    /** The list as stored now (a status update may have replaced it while this request waited or signed), else {@code fallback}. */
    private String latest(String listId, String fallback) {
        try {
            return repository.findById(listId).map(StatusListCredential::getVcDocument).orElse(fallback);
        } catch (RuntimeException e) {
            log.debug("Token status list {} could not be read again; judging the document read first", listId, e);
            return fallback;
        }
    }

    /** The rest of the back-off window after a failed re-sign of the list, empty when there is none. */
    private Optional<Duration> backingOff(String listId) {
        Instant failure = failures.get(listId);
        if (failure == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Duration left = Duration.between(now, failure.plus(properties.renewBackoff()));
        if (left.isNegative() || left.isZero()) {
            return Optional.empty();
        }
        if (left.compareTo(properties.renewBackoff()) > 0) {
            // the clock moved backwards since the failure: the window ends one renew-backoff from now, as Retry-After says
            failures.replace(listId, failure, now);
            left = properties.renewBackoff();
        }
        log.debug("Token status list {} failed to be signed again at {}; not signing it again for {}", listId, failure, left);
        return Optional.of(left);
    }

    /** Records a failed re-sign; its stack trace is logged once, since the list is not signed again within the back-off window. */
    private void failed(String listId, RuntimeException e) {
        failures.put(listId, clock.instant());
        log.error("Token status list {} could not be signed again; not trying again for {} (the stored list is served while it is valid, 503 after)",
                listId, properties.renewBackoff(), e);
    }

    enum Freshness { FRESH, RENEW, UNUSABLE }

    /**
     * {@code FRESH} while {@code exp} is at least {@code ttl} away (a verifier caching the list for {@code ttl} never holds
     * an expired one); {@code RENEW} when it is closer; {@code UNUSABLE} when it has passed, is missing, or {@code sub} is
     * not this list's current URI.
     */
    Freshness freshness(String listId, String jwt) {
        JWTClaimsSet claims;
        try {
            claims = SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            return Freshness.UNUSABLE;
        }
        Instant now = clock.instant();
        if (claims.getExpirationTime() == null || !uri(listId).equals(claims.getSubject())) {
            return Freshness.UNUSABLE;
        }
        Instant exp = claims.getExpirationTime().toInstant();
        if (!exp.isAfter(now)) {
            return Freshness.UNUSABLE;
        }
        return Duration.between(now, exp).compareTo(properties.ttl()) < 0 ? Freshness.RENEW : Freshness.FRESH;
    }

    /** Signs the stored bits again and stores the result unless the list changed meanwhile, in which case it is read again. */
    private String renew(String listId) {
        for (int attempt = 0; attempt < 5; attempt++) {
            String current = repository.findById(listId).map(StatusListCredential::getVcDocument)
                    .orElseThrow(() -> new IllegalStateException("Token status list " + listId + " disappeared"));
            if (freshness(listId, current) == Freshness.FRESH) {
                return current; // signed again by a status update, another request or another instance
            }
            String renewed = sign(listId, bits(current));
            if (repository.replaceDocument(listId, current, renewed) == 1) {
                log.info("Token status list {} signed again (exp or sub was stale), bits unchanged", listId);
                return renewed;
            }
        }
        throw new IllegalStateException("Token status list " + listId + " kept changing while it was signed again");
    }

    /** Applies index → status (true = set) to the list and signs it again; what the batch job does for Bitstring lists. */
    @Transactional
    public void update(StatusListCredential list, Map<Long, Boolean> statuses) {
        byte[] bits = bits(list.getVcDocument());
        statuses.forEach((idx, value) -> set(bits, idx, Boolean.TRUE.equals(value)));
        list.setVcDocument(sign(list.getId(), bits));
        list.setUpdatedDtimes(LocalDateTime.now());
        repository.save(list);
    }

    private StatusListCredential create(String purpose) {
        String id = UUID.randomUUID().toString();
        byte[] bits = new byte[Math.max(1, properties.sizeBits() / 8)];
        StatusListCredential list = new StatusListCredential();
        list.setId(id);
        list.setVcDocument(sign(id, bits));
        list.setCredentialType(TYPE);
        list.setStatusPurpose(purpose);
        list.setCapacityInKB((long) Math.max(1, bits.length / 1024));
        list.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        list.setCreatedDtimes(LocalDateTime.now());
        StatusListCredential saved = repository.saveAndFlush(list);
        bitstringLists.initializeAvailableIndices(saved);
        log.info("Created token status list {} for {} with {} bits", id, purpose, bits.length * 8);
        return saved;
    }

    String sign(String id, byte[] bits) {
        Instant now = clock.instant();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", uri(id));
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plus(properties.ttl()).plus(properties.ttl()).getEpochSecond());
        payload.put("ttl", properties.ttl().getSeconds());
        payload.put("status_list", Map.of("bits", 1, "lst", encode(bits)));
        String json;
        try {
            json = objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot serialise the status list", e);
        }
        KeyRef ref = properties.keyRef() == null || properties.keyRef().isBlank()
                ? LegacyKeyRefs.keymanager("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN") : KeyRef.parse(properties.keyRef());
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(properties.alg())
                .orElseThrow(() -> new IllegalStateException("Unknown algorithm " + properties.alg() + " for the token status list"));
        SigningContext signing = keyProviders.signingContext(new SigningConfig(ref, algorithm, null, null, null, null));
        JwsHeaderPolicy policy = new JwsHeaderPolicy(TYP, KidStrategy.PROVIDER, JpaConfigurationRegistry.chainInclusion(properties.x5c()), false, true, false, Map.of());
        return JwsEnvelope.sign(json, policy, signing.key(), signing.signer());
    }

    /** The bit array of a stored list: {@code status_list.lst}, base64url of the zlib-compressed bytes. */
    static byte[] bits(String jwt) {
        try {
            Map<String, Object> statusList = SignedJWT.parse(jwt).getJWTClaimsSet().getJSONObjectClaim("status_list");
            return decode(String.valueOf(statusList.get("lst")));
        } catch (java.text.ParseException e) {
            throw new IllegalStateException("Stored token status list is not a JWT", e);
        }
    }

    /** Draft section 4.1: index i is bit (i mod 8) of byte i / 8, least significant bit first (bits = 1). */
    static void set(byte[] bits, long idx, boolean value) {
        int b = (int) (idx / 8);
        int shift = (int) (idx % 8);
        if (b >= bits.length) {
            throw new IllegalStateException("Index " + idx + " is outside the list of " + bits.length * 8 + " bits");
        }
        bits[b] = (byte) (value ? bits[b] | (1 << shift) : bits[b] & ~(1 << shift));
    }

    public static boolean get(byte[] bits, long idx) {
        return ((bits[(int) (idx / 8)] >> (int) (idx % 8)) & 1) == 1;
    }

    /**
     * The zlib-compressed bit array, undecorated: what the JWT form carries base64url encoded in
     * {@code status_list.lst} and what the CWT form ({@link TokenStatusListCwt}) carries as the raw {@code bstr} of
     * claim 65533 (draft-ietf-oauth-status-list-21 section 4.3). {@code Deflater.BEST_COMPRESSION} as before, so both
     * forms of one list hold the same bytes.
     */
    static byte[] zlib(byte[] bits) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(bits);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        deflater.end();
        return out.toByteArray();
    }

    static String encode(byte[] bits) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(zlib(bits));
    }

    public static byte[] decode(String lst) {
        Inflater inflater = new Inflater();
        inflater.setInput(Base64.getUrlDecoder().decode(lst));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        try {
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    break;
                }
                out.write(buffer, 0, n);
            }
        } catch (DataFormatException e) {
            throw new IllegalStateException("Token status list lst is not zlib data", e);
        } finally {
            inflater.end();
        }
        return out.toByteArray();
    }
}
