package io.mosip.certify.status;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Token Status Lists (draft-ietf-oauth-status-list): rows of {@code status_list_credential} whose type is
 * {@link #TYPE}, the document being the signed list itself ({@code typ statuslist+jwt}, {@code sub} its URI,
 * {@code status_list.bits} 1, {@code status_list.lst} the zlib-compressed bit array, least significant bit first).
 * Indices come from the same {@code status_list_available_indices} rows as the Bitstring lists.
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

    public TokenStatusListService(StatusListCredentialRepository repository, StatusListCredentialService bitstringLists,
                                  StatusListIndexProvider indexProvider, KeyProviderRegistry keyProviders,
                                  TokenStatusListProperties properties, ObjectMapper objectMapper, Environment environment) {
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

    public Optional<String> jwt(String listId) {
        return repository.findById(listId).filter(l -> TYPE.equals(l.getCredentialType())).map(StatusListCredential::getVcDocument);
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
        Instant now = Instant.now();
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

    static String encode(byte[] bits) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(bits);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        deflater.end();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
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
