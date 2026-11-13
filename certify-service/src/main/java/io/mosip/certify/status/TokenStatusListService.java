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
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
 *
 * <p>Rows whose type is {@link #TYPE_CWT} hold a CWT Status List Token instead
 * ({@link TokenStatusListCwt}; ISO/IEC 18013-5 second edition 12.3.6.3, owner decisions D-M11-1 and D-M11-7, section 4.4
 * of docs/design/wp/M-11-status-list-under-iaca.md): {@code vc_document} is a small JSON envelope recording the signer
 * the list is pinned to and the base64url token, the signer being the Document Signer that signed the mDLs whose indices
 * the list carries. Such a list is signed again only by its own pinned certificate ({@link StatusListSigners#resolve})
 * and answered {@code application/statuslist+cwt} whatever the {@code Accept} (D-M11-2). Once that certificate is past
 * its {@code notAfter} the list is retired: no re-sign is attempted, the stored token is served while its {@code exp}
 * holds and {@link TokenStatusListGoneException} turns into {@code 410 Gone} afterwards. No database migration: the
 * existing columns carry both kinds (D-M11-4).
 */
@Slf4j
@Service
@EnableConfigurationProperties(TokenStatusListProperties.class)
public class TokenStatusListService {

    public static final String TYPE = "TokenStatusList";
    public static final String MEDIA_TYPE = "application/statuslist+jwt";
    public static final String TYP = "statuslist+jwt";
    /** The {@code credential_type} of a CWT Status List Token row (ISO/IEC 18013-5 second edition 12.3.6.3). */
    public static final String TYPE_CWT = "TokenStatusListCwt";
    /** TSL section 8.2: the media type a CWT row is served as, whatever the {@code Accept} (D-M11-2). */
    public static final String MEDIA_TYPE_CWT = TokenStatusListCwt.MEDIA_TYPE;
    static final String PATH = "/credentials/token-status-list/";

    /** The {@code v} of the section 4.4 envelope; a stored document with another version has no reader here. */
    public static final int ENVELOPE_VERSION = 1;
    /** The {@code signer.mode} of a list signed by the Document Signer that signed the mDLs on it (D-M11-1 (a)). */
    public static final String SIGNER_DOCUMENT = "document-signer";

    public record Entry(String uri, long idx) {}

    /** The signer a CWT list is pinned to: which reference re-signs it, and the SHA-256 of its leaf certificate. */
    public record SignerBinding(String mode, String keyRef, String x5tS256) {

        public SignerBinding {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(x5tS256, "x5tS256");
            mode = mode == null ? SIGNER_DOCUMENT : mode;
        }
    }

    /**
     * What {@code status_list_credential.vc_document} holds for a {@link #TYPE_CWT} row (section 4.4): the envelope, not
     * the token, which is what the endpoint serves. {@code v} is {@link #ENVELOPE_VERSION}, {@code token} is the
     * base64url (unpadded) encoding of the CWT. No field of the envelope is derivable from the row's other columns, and
     * the retirement clock is the stored token's own signer leaf, so nothing else is stored.
     */
    public record StoredEnvelope(int v, SignerBinding signer, String token) {

        public StoredEnvelope {
            Objects.requireNonNull(signer, "signer");
            Objects.requireNonNull(token, "token");
        }
    }

    /** The list as served: its media type (one format per list, D-M11-2) and the body bytes (TSL section 8.2). */
    public record Served(String mediaType, byte[] body) {}

    private final StatusListCredentialRepository repository;
    private final StatusListCredentialService bitstringLists;
    private final StatusListIndexProvider indexProvider;
    private final KeyProviderRegistry keyProviders;
    private final TokenStatusListProperties properties;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final Clock clock;
    /** Pins a CWT list to its signer and resolves that signer again on renewal (section 4.3). */
    private final StatusListSigners signers;
    /** The checks every CWT signer passes before the token is built (section 4.7). */
    private final StatusListSignerPolicy signerPolicy;
    /** The {@code mdoc-iaca} anchors the signer policy enforces, empty when none are configured. */
    private final TrustAnchorRegistry trustAnchors;
    /** One re-sign per list at a time in this instance; other instances are kept consistent by the compare-and-set. */
    private final ConcurrentMap<String, ReentrantLock> renewals = new ConcurrentHashMap<>();
    /** Per list, when its last re-sign failed; it is not signed again within {@code renew-backoff} of that instant. */
    private final ConcurrentMap<String, Instant> failures = new ConcurrentHashMap<>();
    /** Per CWT list, the SHA-256 of the signer leaf its envelope pins: a list's signer never changes. */
    private final ConcurrentMap<String, String> pinnedSigners = new ConcurrentHashMap<>();

    @Autowired
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment,
                                  ObjectProvider<TrustAnchorRegistry> trustAnchors) {
        this(repository, bitstringLists, indexProvider, keyProviders, properties, objectMapper, environment,
                Clock.systemUTC(), trustAnchors.getIfAvailable());
    }

    /** The bean's constructor without a registry (the CWT signer policy then has no trust anchors to enforce). */
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment) {
        this(repository, bitstringLists, indexProvider, keyProviders, properties, objectMapper, environment, Clock.systemUTC(), null);
    }

    /** As the bean, with the clock that stamps {@code iat}/{@code exp} and decides freshness (tests sign lists in the past). */
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment,
                                  Clock clock) {
        this(repository, bitstringLists, indexProvider, keyProviders, properties, objectMapper, environment, clock, null);
    }

    /**
     * The bean, with the clock and the trust-anchor registry spelled out: the {@code mdoc-iaca} anchors a CWT signer is
     * held to (section 4.7), {@code null} when the application configures none.
     */
    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment,
                                  Clock clock, TrustAnchorRegistry trustAnchors) {
        this.clock = clock;
        this.repository = repository;
        this.bitstringLists = bitstringLists;
        this.indexProvider = indexProvider;
        this.keyProviders = keyProviders;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.signers = new StatusListSigners(keyProviders, clock);
        this.trustAnchors = trustAnchors == null ? TrustAnchorRegistry.EMPTY : trustAnchors;
        this.signerPolicy = new StatusListSignerPolicy(this.trustAnchors);
        String domain = environment.getRequiredProperty("mosip.certify.domain.url").replaceAll("/+$", "");
        String servletPath = environment.getProperty("server.servlet.path", "").replaceAll("/+$", "");
        this.baseUrl = domain + servletPath;
        startup();
    }

    /**
     * The two startup lines of section 4.6/4.7: whether the CWT signer's trust-anchor rules apply (as the mDoc
     * formatter says for its DSC policy), and the escape hatch's WARN when {@code mdoc.token-format=jwt} keeps today's
     * shared JWT lists for {@code mso_mdoc}.
     */
    private void startup() {
        if (signerPolicy.enforced()) {
            log.info("CWT status list signer policy enforced on every list: the signer must chain to one of the IACAs {}",
                    trustAnchors.entries(TrustAnchorRegistry.MDOC_IACA).stream()
                            .map(TrustAnchorRegistry.Anchor::id).toList());
        } else {
            // INFO, not WARN: most deployments issue no mso_mdoc at all, and for them this is the expected state
            log.info("CWT status list signer policy is not enforced: no IACA trust anchor is configured"
                    + " (certify.pki.trust-anchors.mdoc-iaca, or an x509-file iaca); CWT lists are signed without checking"
                    + " the Document Signer against an IACA");
        }
        if (TokenStatusListProperties.Mdoc.FORMAT_JWT.equals(properties.mdoc().tokenFormat())) {
            log.warn("certify.status.token-status-list.mdoc.token-format=jwt: mso_mdoc entries go to shared JWT status"
                    + " lists signed by {}. ISO/IEC 18013-5 second edition 12.3.6.3 makes an mDoc's status list a CWT, and"
                    + " @owf/mdoc (Paradym, Credo) refuses a JWT with JwtNotSupportForStatusListError; this escape hatch"
                    + " exists for a deployment that cannot move yet (D-M11-3)",
                    properties.keyRef() == null ? "keymanager's EC key" : properties.keyRef());
        }
    }

    public String uri(String listId) {
        return baseUrl + PATH + listId;
    }

    /**
     * A free index in the CWT list for the purpose signed by {@code signing}, creating the next list when the current
     * one is full (section 4.3).
     *
     * <p>A list belongs to one signer: only rows whose envelope pins the signing key's leaf certificate are candidates,
     * so a Document Signer rotation starts new lists for new mDLs while the old lists keep their indices and are
     * re-signed by their own certificate until it expires. The signer is pinned before anything is allocated, and the
     * policy runs before the first token is signed ({@link #createCwt}); a refused signer consumes no index.
     *
     * @throws IllegalStateException the policy's refusal, or {@code STATUS_SIGNER_NO_CHAIN} when the key has no
     *                               certificate (nothing can be pinned)
     * @throws StatusListRetiredException when the signer is in the last second of its validity: no token it signs could
     *                                    be valid, so the mDL cannot reference a list (M-11e maps it to
     *                                    {@code status_list_unavailable})
     */
    @Transactional
    public Entry allocateCwt(String purpose, SigningContext signing) {
        Objects.requireNonNull(signing, "signing");
        Instant now = clock.instant();
        StatusListSigners.Pinned pinned = signers.pin(signing);
        signerPolicy.check(signing, now, StatusListSignerPolicy.Mode.DOCUMENT_SIGNER);
        List<StatusListCredential> candidates = repository
                .findByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(
                        TYPE_CWT, purpose, StatusListCredential.CredentialStatus.AVAILABLE);
        for (StatusListCredential candidate : candidates) {
            if (!pinned.x5tS256().equals(pinnedSigner(candidate))) {
                continue; // another Document Signer's list: nothing on it indexes this signer's mDLs
            }
            Optional<Long> index = indexProvider.acquireIndex(candidate.getId(), Map.of());
            if (index.isPresent()) {
                return new Entry(uri(candidate.getId()), index.get());
            }
            candidate.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
            repository.save(candidate);
        }
        StatusListCredential created = createCwt(purpose, signing, pinned);
        Optional<Long> index = indexProvider.acquireIndex(created.getId(), Map.of());
        return new Entry(uri(created.getId()), index.orElseThrow(
                () -> new IllegalStateException("No free index in CWT token status list " + purpose)));
    }

    /**
     * Stores the section 4.4 envelope of a newly signed CWT list. {@code exp} is {@code min(now + 2·ttl, validUntil)} —
     * the earliest {@code notAfter} of the signer's whole path (section 4.1) — and {@link TokenStatusListCwt#encode}
     * runs the signer policy itself, so this path cannot sign without it.
     */
    private StatusListCredential createCwt(String purpose, SigningContext signing, StatusListSigners.Pinned pinned) {
        String id = UUID.randomUUID().toString();
        byte[] bits = new byte[Math.max(1, properties.sizeBits() / 8)];
        Instant now = clock.instant();
        Duration ttl = properties.ttl();
        Instant exp = cap(now.plus(ttl).plus(ttl), signerPolicy.validUntil(signing));
        byte[] token = TokenStatusListCwt.encode(uri(id), now, exp, ttl, bits, signing, signerPolicy, now,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER);
        StatusListCredential list = new StatusListCredential();
        list.setId(id);
        list.setVcDocument(document(envelope(pinned, token)));
        list.setCredentialType(TYPE_CWT);
        list.setStatusPurpose(purpose);
        list.setCapacityInKB((long) Math.max(1, bits.length / 1024));
        list.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        list.setCreatedDtimes(LocalDateTime.now());
        StatusListCredential saved = repository.saveAndFlush(list);
        bitstringLists.initializeAvailableIndices(saved);
        pinnedSigners.put(id, pinned.x5tS256());
        log.info("Created CWT token status list {} for {} with {} bit(s), signed by {} ({}), exp {}", id, purpose,
                bits.length * 8, pinned.keyRef(), signing.key().chain().leaf().map(X509Certificate::getSubjectX500Principal).orElse(null), exp);
        return saved;
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
     * The list to serve in its own single format, whatever the caller's {@code Accept} (D-M11-2, TSL sections 8.1-8.2):
     * a {@link #TYPE} row exactly as {@link #jwt} answers today ({@code application/statuslist+jwt}), a {@link #TYPE_CWT}
     * row as {@code application/statuslist+cwt} with the same freshness state machine and the same {@code 503} on
     * failure.
     *
     * @throws TokenStatusListUnavailableException when the list is unusable and cannot be signed again now
     * @throws TokenStatusListGoneException        when a CWT list's signer expired and its own {@code exp} has passed
     */
    public Optional<Served> served(String listId) {
        Optional<StatusListCredential> row = repository.findById(listId);
        if (row.isEmpty()) {
            return Optional.empty();
        }
        String type = row.get().getCredentialType();
        if (TYPE.equals(type)) {
            return jwt(listId).map(jwt -> new Served(MEDIA_TYPE, jwt.getBytes(StandardCharsets.UTF_8)));
        }
        if (!TYPE_CWT.equals(type)) {
            return Optional.empty();
        }
        StoredEnvelope stored = envelope(row.get().getVcDocument());
        Freshness freshness = freshnessCwt(listId, stored);
        if (freshness == Freshness.FRESH) {
            return Optional.of(servedAsStored(stored));
        }
        Optional<Duration> backingOff = backingOff(listId);
        if (backingOff.isPresent()) {
            return Optional.of(servedAsStoredCwt(listId, stored, backingOff.get(), null));
        }
        ReentrantLock lock = renewals.computeIfAbsent(listId, id -> new ReentrantLock());
        if (!acquire(listId, lock, freshness)) {
            return Optional.of(servedAsStoredCwt(listId, stored, properties.renewWait(), null));
        }
        try {
            backingOff = backingOff(listId); // the request this one waited for may have failed meanwhile
            if (backingOff.isPresent()) {
                return Optional.of(servedAsStoredCwt(listId, latestCwt(listId, stored), backingOff.get(), null));
            }
            StoredEnvelope renewed;
            try {
                renewed = renewCwt(listId);
            } catch (StatusListRetiredException e) {
                // caught BEFORE the general IllegalStateException mapping below: a retired list is D-M11-7's 410, not
                // the 503 back-off, and it is never re-signed again
                failures.remove(listId);
                log.info("CWT token status list {} is retired and is not signed again: {}. Its stored token is served"
                        + " while its exp holds, then answered 410 (D-M11-7)", listId, e.getMessage());
                return Optional.of(retiredAsStored(listId, latestCwt(listId, stored), e));
            } catch (RuntimeException e) {
                failed(listId, e);
                return Optional.of(servedAsStoredCwt(listId, latestCwt(listId, stored), properties.renewBackoff(), e));
            }
            failures.remove(listId);
            return Optional.of(usableRenewalCwt(listId, renewed));
        } finally {
            lock.unlock();
        }
    }

    /**
     * The list's freshness, from its own token's claims (TSL sections 8.3 step 4a and 5.1, as {@link #freshness} does
     * for a JWT): {@code FRESH} while {@code exp} is at least {@code ttl} away, {@code RENEW} when it is closer,
     * {@code UNUSABLE} when it has passed, {@code sub} is not this list's current URI, or the stored token cannot be read
     * back as this profile.
     */
    Freshness freshnessCwt(String listId, StoredEnvelope stored) {
        TokenStatusListCwt.Decoded decoded;
        try {
            decoded = TokenStatusListCwt.decode(token(stored));
        } catch (RuntimeException e) {
            log.debug("CWT token status list {} holds a token this codec does not read back: {}", listId, e.getMessage());
            return Freshness.UNUSABLE;
        }
        Instant now = clock.instant();
        if (!uri(listId).equals(decoded.sub()) || !decoded.exp().isAfter(now)) {
            return Freshness.UNUSABLE;
        }
        return Duration.between(now, decoded.exp()).compareTo(properties.ttl()) < 0 ? Freshness.RENEW : Freshness.FRESH;
    }

    /** The stored envelope as served: the token bytes, with the row's own single media type (D-M11-2). */
    private Served servedAsStored(StoredEnvelope stored) {
        return new Served(MEDIA_TYPE_CWT, token(stored));
    }

    /**
     * The stored token, when it is still usable now; an expired one (or one under another URI) is never served, whatever
     * it was when the request began.
     *
     * @throws TokenStatusListUnavailableException otherwise, with {@code retryAfter}
     */
    private Served servedAsStoredCwt(String listId, StoredEnvelope stored, Duration retryAfter, RuntimeException cause) {
        if (freshnessCwt(listId, stored) != Freshness.UNUSABLE) {
            return servedAsStored(stored);
        }
        throw new TokenStatusListUnavailableException("CWT token status list " + listId
                + " is expired or under another URI and could not be signed again", retryAfter, cause);
    }

    /**
     * A retired list (its pinned signer is past {@code notAfter}, D-M11-7): no re-sign is attempted, the stored token is
     * served while its own {@code exp} holds, and {@code 410 Gone} afterwards — asking again cannot help, and signing the
     * list with another certificate would break Credo's rule that a list's chain equals the mDL's issuance chain.
     */
    private Served retiredAsStored(String listId, StoredEnvelope stored, StatusListRetiredException retired) {
        if (freshnessCwt(listId, stored) != Freshness.UNUSABLE) {
            return servedAsStored(stored);
        }
        throw new TokenStatusListGoneException("CWT token status list " + listId + " is retired: " + retired.getMessage(),
                retired);
    }

    /**
     * The renewed token, judged against the clock when it is returned (as {@link #usableRenewal} does for a JWT):
     * {@code exp} is stamped before the signer runs, so a signer that answers after it has passed yields a token that is
     * already expired. Such a renewal counts as a failure (back-off, logged once); the token as stored now is served if
     * another writer left a usable one, otherwise 503 with {@code Retry-After}.
     */
    private Served usableRenewalCwt(String listId, StoredEnvelope renewed) {
        if (freshnessCwt(listId, renewed) != Freshness.UNUSABLE) {
            return servedAsStored(renewed);
        }
        IllegalStateException stale = new IllegalStateException("CWT token status list " + listId
                + " was signed again but had expired by the time the signer answered");
        failed(listId, stale);
        return servedAsStoredCwt(listId, latestCwt(listId, renewed), properties.renewBackoff(), stale);
    }

    /** The CWT list as stored now (a status update may have replaced it while this request waited), else {@code fallback}. */
    private StoredEnvelope latestCwt(String listId, StoredEnvelope fallback) {
        try {
            return repository.findById(listId)
                    .filter(row -> TYPE_CWT.equals(row.getCredentialType()))
                    .map(row -> envelope(row.getVcDocument()))
                    .orElse(fallback);
        } catch (RuntimeException e) {
            log.debug("CWT token status list {} could not be read again; judging the document read first", listId, e);
            return fallback;
        }
    }

    /**
     * Signs the stored bits again with the list's pinned signer and stores the result unless the list changed meanwhile,
     * in which case it is read again (the compare-and-set {@link #renew} uses).
     *
     * @throws StatusListRetiredException when the pinned signer is past its {@code notAfter} (or in its last second)
     */
    private StoredEnvelope renewCwt(String listId) {
        for (int attempt = 0; attempt < 5; attempt++) {
            StatusListCredential row = repository.findById(listId)
                    .orElseThrow(() -> new IllegalStateException("Token status list " + listId + " disappeared"));
            StoredEnvelope current = envelope(row.getVcDocument());
            if (freshnessCwt(listId, current) == Freshness.FRESH) {
                return current; // signed again by a status update, another request or another instance
            }
            StoredEnvelope renewed = resignCwt(listId, current);
            if (repository.replaceDocument(listId, row.getVcDocument(), document(renewed)) == 1) {
                log.info("CWT token status list {} signed again (exp or sub was stale), bits unchanged", listId);
                return renewed;
            }
        }
        throw new IllegalStateException("CWT token status list " + listId + " kept changing while it was signed again");
    }

    /** The stored token re-signed with the bits it already carries. */
    private StoredEnvelope resignCwt(String listId, StoredEnvelope stored) {
        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(token(stored));
        return resignCwt(listId, stored, decoded.x5chain().get(0), decoded.lst());
    }

    /** The token re-signed with {@code bits} by the list's pinned signer, whose leaf the stored token names. */
    private StoredEnvelope resignCwt(String listId, StoredEnvelope stored, byte[] bits) {
        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(token(stored));
        return resignCwt(listId, stored, decoded.x5chain().get(0), bits);
    }

    /**
     * The token re-signed with {@code bits} by the list's pinned signer: {@code StatusListSigners.resolve} judges the
     * <em>stored</em> signer certificate first (retirement, then that the resolved key is still that certificate), and
     * {@code encode} holds it to the policy before anything is signed. {@code exp} is capped at the signer's
     * {@code validUntil} exactly as at creation.
     *
     * @throws StatusListRetiredException when the pinned certificate is past its {@code notAfter}, or in its last second
     *                                    where no token valid for a second exists
     */
    private StoredEnvelope resignCwt(String listId, StoredEnvelope stored, X509Certificate storedLeaf, byte[] bits) {
        StatusListSigners.Pinned pinned = new StatusListSigners.Pinned(
                KeyRef.parse(stored.signer().keyRef()), stored.signer().x5tS256());
        SigningContext signing = signers.resolve(pinned, storedLeaf);
        Instant now = clock.instant();
        Duration ttl = properties.ttl();
        Instant exp = cap(now.plus(ttl).plus(ttl), signerPolicy.validUntil(signing));
        byte[] token = TokenStatusListCwt.encode(uri(listId), now, exp, ttl, bits, signing, signerPolicy, now,
                StatusListSignerPolicy.Mode.DOCUMENT_SIGNER);
        return new StoredEnvelope(ENVELOPE_VERSION, stored.signer(), tokenBase64(token));
    }

    /** The section 4.4 envelope of a freshly pinned list. */
    private StoredEnvelope envelope(StatusListSigners.Pinned pinned, byte[] token) {
        return new StoredEnvelope(ENVELOPE_VERSION,
                new SignerBinding(SIGNER_DOCUMENT, pinned.keyRef().toString(), pinned.x5tS256()), tokenBase64(token));
    }

    /** Reads a {@link #TYPE_CWT} row's document back; a row that is not the section 4.4 envelope is refused. */
    public StoredEnvelope envelope(String document) {
        StoredEnvelope envelope;
        try {
            envelope = objectMapper.readValue(document, StoredEnvelope.class);
        } catch (Exception e) {
            throw new IllegalStateException("Stored CWT token status list is not the section 4.4 envelope", e);
        }
        if (envelope.v() != ENVELOPE_VERSION) {
            throw new IllegalStateException("Stored CWT token status list carries envelope version " + envelope.v()
                    + "; this build writes and reads version " + ENVELOPE_VERSION);
        }
        return envelope;
    }

    /** Serialises the envelope exactly as section 4.4 reads it: {@code v}, {@code signer}, {@code token}. */
    private String document(StoredEnvelope envelope) {
        try {
            return objectMapper.writeValueAsString(envelope);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot serialise the CWT token status list envelope", e);
        }
    }

    private static byte[] token(StoredEnvelope envelope) {
        return Base64.getUrlDecoder().decode(envelope.token());
    }

    private static String tokenBase64(byte[] token) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    /** The SHA-256 the list's envelope pins, from the cache when it is known (a list's signer never changes). */
    private String pinnedSigner(StatusListCredential list) {
        return pinnedSigners.computeIfAbsent(list.getId(), id -> envelope(list.getVcDocument()).signer().x5tS256());
    }

    /** The earlier of two instants: {@code exp = min(iat + 2·ttl, validUntil)} (section 4.1). */
    private static Instant cap(Instant candidate, Instant validUntil) {
        return candidate.isBefore(validUntil) ? candidate : validUntil;
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
        if (TYPE_CWT.equals(list.getCredentialType())) {
            updateCwt(list, statuses);
            return;
        }
        byte[] bits = bits(list.getVcDocument());
        statuses.forEach((idx, value) -> set(bits, idx, Boolean.TRUE.equals(value)));
        list.setVcDocument(sign(list.getId(), bits));
        list.setUpdatedDtimes(LocalDateTime.now());
        repository.save(list);
    }

    /**
     * The batch job's CWT path: the bit is set and the list is re-signed by its own pinned signer, never by whatever the
     * provider resolves for the alias today — a rotated Document Signer keeps signing its own lists until its
     * {@code notAfter} (section 4.3).
     *
     * @throws StatusListRetiredException when the pinned signer is past its {@code notAfter}: the revocation cannot be
     *                                    published because no mDL on the list can still be valid (D-M11-7)
     */
    private void updateCwt(StatusListCredential list, Map<Long, Boolean> statuses) {
        StoredEnvelope stored = envelope(list.getVcDocument());
        byte[] bits = TokenStatusListCwt.decode(token(stored)).lst();
        statuses.forEach((idx, value) -> set(bits, idx, Boolean.TRUE.equals(value)));
        list.setVcDocument(document(resignCwt(list.getId(), stored, bits)));
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
