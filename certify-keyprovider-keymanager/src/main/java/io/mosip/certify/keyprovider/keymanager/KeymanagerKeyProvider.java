package io.mosip.certify.keyprovider.keymanager;

import com.nimbusds.jose.jwk.Curve;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.service.SignatureServicev2;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link KeyProvider} over the embedded MOSIP kernel-keymanager. Signing goes through
 * {@link SignatureServicev2#signv2}, which signs the given bytes with the key's private key (RSA PKCS#1 v1.5 or PSS,
 * ECDSA with the signature transcoded to the JOSE concatenation, Ed25519) and returns the raw signature base64url
 * encoded; the key id is keymanager's certificate thumbprint. Certificates are read through
 * {@link KeymanagerService#getAllCertificates} and cached briefly, so a key rotated in keymanager is picked up
 * within {@code cacheTtl}.
 */
public class KeymanagerKeyProvider implements KeyProvider {

    public static final String ID = "keymanager";
    /** Purpose recorded on every descriptor; keymanager has no purpose notion of its own. */
    public static final String PURPOSE_VC_SIGNING = "vc-signing";
    /** Keymanager's {@code generateMasterKey}/{@code generateECSignKey} object type that yields a self-signed certificate. */
    static final String OBJECT_TYPE_CERTIFICATE = "certificate";
    private static final Set<SignatureAlgorithm> SUPPORTED = EnumSet.of(SignatureAlgorithm.RS256, SignatureAlgorithm.PS256,
            SignatureAlgorithm.ES256, SignatureAlgorithm.ES256K, SignatureAlgorithm.EdDSA);

    private final KeymanagerService keymanagerService;
    private final SignatureServicev2 signatureService;
    private final List<KeymanagerAlias> knownAliases;
    private final Clock clock;
    private final Duration cacheTtl;
    private final Map<KeymanagerAlias, CachedCertificates> cache = new ConcurrentHashMap<>();

    public KeymanagerKeyProvider(KeymanagerService keymanagerService, SignatureServicev2 signatureService,
                                 List<KeymanagerAlias> knownAliases, Clock clock, Duration cacheTtl) {
        this.keymanagerService = keymanagerService;
        this.signatureService = signatureService;
        this.knownAliases = List.copyOf(knownAliases);
        this.clock = clock;
        this.cacheTtl = cacheTtl;
    }

    @Override
    public String id() {
        return ID;
    }

    /**
     * Resolves the alias to its current certificate: the one with the latest expiry among those valid now, or the
     * certificate whose key id equals the {@link KeyRef#version()} when one is pinned.
     */
    @Override
    public SigningKey resolve(KeyRef ref) {
        if (!ID.equals(ref.provider())) {
            throw new SigningException("KeyRef " + ref + " is not for provider " + ID);
        }
        KeymanagerAlias alias = KeymanagerAlias.of(ref);
        List<PublicKeyDescriptor> descriptors = descriptors(alias);
        Instant now = clock.instant();
        Optional<PublicKeyDescriptor> chosen = ref.versionOpt()
                .map(kid -> descriptors.stream().filter(d -> d.kid().equals(kid)).findFirst()
                        .orElseThrow(() -> new SigningException("No certificate with key id " + kid + " for " + alias)))
                .or(() -> descriptors.stream().filter(d -> d.isValidAt(now)).max(Comparator.comparing(PublicKeyDescriptor::notAfter)));
        PublicKeyDescriptor descriptor = chosen.orElseThrow(() -> new SigningException("No valid certificate for keymanager key " + alias));
        return new SigningKey(ref, descriptor, alias);
    }

    @Override
    public List<PublicKeyDescriptor> publicKeys(KeyFilter filter) {
        KeyFilter f = filter == null ? KeyFilter.ALL : filter;
        List<PublicKeyDescriptor> out = new ArrayList<>();
        for (KeymanagerAlias alias : knownAliases) {
            descriptors(alias).stream().filter(f::matches).forEach(out::add);
        }
        return out;
    }

    /** The aliases this provider publishes (from configuration); any other alias can still be resolved on demand. */
    public List<KeymanagerAlias> knownAliases() {
        return knownAliases;
    }

    @Override
    public Set<SignatureAlgorithm> supportedAlgorithms() {
        return SUPPORTED;
    }

    /**
     * Creates the keys keymanager does not have yet, the way {@code AppConfig.initKeys} did: an RSA key is a
     * self-signed master key of its application id; an EC or Ed25519 key needs its application id's master key
     * first (keymanager wraps the EC private key under it) and is then generated with {@code generateECSignKey}.
     * Keymanager itself skips keys that already exist, so this is idempotent.
     */
    @Override
    public void ensureKeys(List<KeyRequirement> required) {
        for (KeyRequirement requirement : required) {
            KeymanagerAlias alias = KeymanagerAlias.parse(requirement.alias());
            if (requirement.algorithm().isRsa()) {
                KeyPairGenerateRequestDto request = request(alias.applicationId(), alias.referenceId());
                request.setForce(false);
                keymanagerService.generateMasterKey(OBJECT_TYPE_CERTIFICATE, request);
            } else {
                keymanagerService.generateMasterKey(OBJECT_TYPE_CERTIFICATE, request(alias.applicationId(), ""));
                keymanagerService.generateECSignKey(OBJECT_TYPE_CERTIFICATE, request(alias.applicationId(), alias.referenceId()));
            }
            cache.remove(alias);
        }
    }

    @Override
    public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
        if (!(key.providerHandle() instanceof KeymanagerAlias alias)) {
            throw new SigningException("Key " + key.ref() + " was not resolved by provider " + ID);
        }
        if (!SUPPORTED.contains(algorithm)) {
            throw new SigningException("kernel-keymanager cannot sign with " + algorithm.joseName() + "; it supports " + SUPPORTED);
        }
        checkKeyMatches(key, algorithm);
        SignRequestDtoV2 request = new SignRequestDtoV2();
        request.setApplicationId(alias.applicationId());
        request.setReferenceId(alias.referenceId());
        request.setSignAlgorithm(algorithm.joseName());
        request.setDataToSign(Base64.getUrlEncoder().withoutPadding().encodeToString(data));
        request.setResponseEncodingFormat("base64url");
        try {
            String signature = signatureService.signv2(request).getSignature();
            return Base64.getUrlDecoder().decode(signature);
        } catch (RuntimeException e) {
            throw new SigningException("Signing with " + key.ref() + " failed in keymanager", e);
        }
    }

    /** Drops cached certificates so the next resolve sees a rotation immediately. */
    public void evict() {
        cache.clear();
    }

    static KeyPairGenerateRequestDto request(String applicationId, String referenceId) {
        KeyPairGenerateRequestDto request = new KeyPairGenerateRequestDto();
        request.setApplicationId(applicationId);
        request.setReferenceId(referenceId);
        return request;
    }

    private List<PublicKeyDescriptor> descriptors(KeymanagerAlias alias) {
        Instant now = clock.instant();
        CachedCertificates cached = cache.get(alias);
        if (cached != null && cached.fetchedAt().plus(cacheTtl).isAfter(now)) {
            return cached.descriptors();
        }
        AllCertificatesDataResponseDto response = keymanagerService.getAllCertificates(alias.applicationId(),
                Optional.of(alias.referenceId()));
        List<PublicKeyDescriptor> descriptors = new ArrayList<>();
        if (response != null && response.getAllCertificates() != null) {
            Arrays.stream(response.getAllCertificates())
                    .filter(dto -> dto != null && dto.getKeyId() != null && dto.getCertificateData() != null)
                    .map(this::descriptor)
                    .forEach(descriptors::add);
        }
        cache.put(alias, new CachedCertificates(List.copyOf(descriptors), now));
        return descriptors;
    }

    private PublicKeyDescriptor descriptor(CertificateDataResponseDto dto) {
        X509Certificate certificate = parseCertificate(dto.getCertificateData());
        PublicKey publicKey = certificate.getPublicKey();
        return new PublicKeyDescriptor(dto.getKeyId(), algorithmFor(publicKey), publicKey, CertificateChain.of(certificate),
                toInstant(dto.getIssuedAt(), certificate.getNotBefore().toInstant()),
                toInstant(dto.getExpiryAt(), certificate.getNotAfter().toInstant()), PURPOSE_VC_SIGNING);
    }

    private static Instant toInstant(LocalDateTime keymanagerTime, Instant fallback) {
        return keymanagerTime == null ? fallback : keymanagerTime.toInstant(ZoneOffset.UTC);
    }

    static X509Certificate parseCertificate(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new SigningException("Keymanager returned a certificate that does not parse", e);
        }
    }

    /** The JOSE algorithm a key naturally signs with; RSA keys default to RS256 and may also be used with PS256. */
    static SignatureAlgorithm algorithmFor(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return SignatureAlgorithm.RS256;
        }
        if (publicKey instanceof ECPublicKey ec) {
            Curve curve = Curve.forECParameterSpec(ec.getParams());
            if (curve == null) {
                throw new SigningException("Unknown EC curve on keymanager certificate");
            }
            return switch (curve.getName()) {
                case "P-256" -> SignatureAlgorithm.ES256;
                case "secp256k1" -> SignatureAlgorithm.ES256K;
                case "P-384" -> SignatureAlgorithm.ES384;
                case "P-521" -> SignatureAlgorithm.ES512;
                default -> throw new SigningException("Unsupported EC curve " + curve.getName());
            };
        }
        if ("Ed25519".equalsIgnoreCase(publicKey.getAlgorithm()) || "EdDSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return SignatureAlgorithm.EdDSA;
        }
        throw new SigningException("Unsupported key type " + publicKey.getAlgorithm());
    }

    private static void checkKeyMatches(SigningKey key, SignatureAlgorithm algorithm) {
        SignatureAlgorithm natural = key.algorithm();
        boolean ok = switch (algorithm) {
            case RS256, PS256 -> natural.isRsa();
            default -> natural == algorithm;
        };
        if (!ok) {
            throw new SigningException("Key " + key.ref() + " (" + natural.joseName() + ") cannot sign with " + algorithm.joseName());
        }
    }

    private record CachedCertificates(List<PublicKeyDescriptor> descriptors, Instant fetchedAt) {}
}
