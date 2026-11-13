package io.mosip.certify.keyprovider.keymanager;

import com.nimbusds.jose.jwk.Curve;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TrustAnchorRegistry;
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
import java.util.function.Supplier;

/**
 * {@link KeyProvider} over the embedded MOSIP kernel-keymanager. Signing goes through
 * {@link SignatureServicev2#signv2}, which signs the given bytes with the key's private key (RSA PKCS#1 v1.5 or PSS,
 * ECDSA with the signature transcoded to the JOSE concatenation, Ed25519) and returns the raw signature base64url
 * encoded; the key id is keymanager's certificate thumbprint. Certificates are read through
 * {@link KeymanagerService#getAllCertificates} and cached briefly, so a key rotated in keymanager is picked up
 * within {@code cacheTtl}. An alias without certificates (not provisioned yet) is cached for at most
 * {@link #MAX_NEGATIVE_TTL}, so the JWKS and every resolve do not call keymanager on each request, while a key
 * provisioned later is seen at once: {@link #ensureKeys} and {@link #evict} (called after the master keys) drop it.
 *
 * <p>Keymanager returns a certificate alone. When a configured {@link TrustAnchorRegistry} IACA issued it (a Document
 * Signer key whose CSR an IACA signed and an operator uploaded, docs/design/20-mdl-issuer.md M-06/M-07), the chain is
 * completed to {@code [DSC, IACA]} so the mDoc DSC policy can check it and {@code without-anchor} still carries the DSC
 * alone; any other certificate (keymanager's own self-signed or master-signed ones) keeps its one-certificate chain,
 * so a deployment without trust anchors sees the same chains, headers and bytes as before. What this provider publishes
 * ({@link #publicKeys(KeyFilter)} for the JWKS, {@link #publicKeys(KeyRef)} for DID documents) leaves the IACA out,
 * as before the completion: an IACA is a trust anchor, published at {@code /mdoc/iaca} (M-08) and never in a JWKS
 * (M-05), so a completed key's {@code x5c} stays the DSC alone.
 */
public class KeymanagerKeyProvider implements KeyProvider {

    public static final String ID = "keymanager";
    /** Purpose recorded on every descriptor; keymanager has no purpose notion of its own. */
    public static final String PURPOSE_VC_SIGNING = "vc-signing";
    /** Keymanager's {@code generateMasterKey}/{@code generateECSignKey} object type that yields a self-signed certificate. */
    static final String OBJECT_TYPE_CERTIFICATE = "certificate";
    private static final Set<SignatureAlgorithm> SUPPORTED = EnumSet.of(SignatureAlgorithm.RS256, SignatureAlgorithm.PS256,
            SignatureAlgorithm.ES256, SignatureAlgorithm.ES256K, SignatureAlgorithm.EdDSA);
    /** The longest an empty answer (an alias keymanager holds no certificate for) is cached. */
    static final Duration MAX_NEGATIVE_TTL = Duration.ofSeconds(30);

    private final KeymanagerService keymanagerService;
    private final SignatureServicev2 signatureService;
    private final List<KeymanagerAlias> knownAliases;
    private final Clock clock;
    private final Duration cacheTtl;
    private final Duration negativeTtl;
    private final Map<KeymanagerAlias, CachedCertificates> cache = new ConcurrentHashMap<>();
    private final Supplier<TrustAnchorRegistry> trustAnchors;

    public KeymanagerKeyProvider(KeymanagerService keymanagerService, SignatureServicev2 signatureService,
                                 List<KeymanagerAlias> knownAliases, Clock clock, Duration cacheTtl) {
        this(keymanagerService, signatureService, knownAliases, clock, cacheTtl, () -> null);
    }

    /**
     * @param trustAnchors the registry leaf-only chains are completed from, read when certificates are (re)loaded; it may
     *                     supply {@code null} when the application registers none
     */
    public KeymanagerKeyProvider(KeymanagerService keymanagerService, SignatureServicev2 signatureService,
                                 List<KeymanagerAlias> knownAliases, Clock clock, Duration cacheTtl,
                                 Supplier<TrustAnchorRegistry> trustAnchors) {
        this.trustAnchors = trustAnchors == null ? () -> null : trustAnchors;
        this.keymanagerService = keymanagerService;
        this.signatureService = signatureService;
        this.knownAliases = List.copyOf(knownAliases);
        this.clock = clock;
        this.cacheTtl = cacheTtl;
        this.negativeTtl = cacheTtl.compareTo(MAX_NEGATIVE_TTL) < 0 ? cacheTtl : MAX_NEGATIVE_TTL;
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
            descriptors(alias).stream().filter(f::matches).map(KeymanagerKeyProvider::published).forEach(out::add);
        }
        return out;
    }

    /** All certificates keymanager holds for the alias, expired ones included (the DID document lists rotated keys). */
    @Override
    public List<PublicKeyDescriptor> publicKeys(KeyRef ref) {
        if (!ID.equals(ref.provider())) {
            throw new SigningException("KeyRef " + ref + " is not for provider " + ID);
        }
        return descriptors(KeymanagerAlias.of(ref)).stream().map(KeymanagerKeyProvider::published).toList();
    }

    /** A key as published: without the IACA a completed chain ends at (the trust anchor is not part of the key). */
    private static PublicKeyDescriptor published(PublicKeyDescriptor descriptor) {
        CertificateChain chain = descriptor.chain().withoutAnchor();
        return chain == descriptor.chain() ? descriptor : new PublicKeyDescriptor(descriptor.kid(), descriptor.algorithm(),
                descriptor.publicKey(), chain, descriptor.notBefore(), descriptor.notAfter(), descriptor.purpose());
    }

    /** The aliases this provider publishes (from configuration); any other alias can still be resolved on demand. */
    public List<KeymanagerAlias> knownAliases() {
        return knownAliases;
    }

    /** The known aliases as references, {@code keymanager:APPID[/REFID]}. */
    @Override
    public List<KeyRef> keyRefs() {
        return knownAliases.stream().map(KeymanagerAlias::toKeyRef).toList();
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
        if (cached != null && cached.fetchedAt().plus(cached.descriptors().isEmpty() ? negativeTtl : cacheTtl).isAfter(now)) {
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
        // an empty answer (a key not provisioned yet) is cached for the short negative TTL only, and provisioning
        // (ensureKeys, evict after the master keys) drops it, so the key is visible as soon as it exists
        cache.put(alias, new CachedCertificates(List.copyOf(descriptors), now));
        return descriptors;
    }

    private PublicKeyDescriptor descriptor(CertificateDataResponseDto dto) {
        X509Certificate certificate = parseCertificate(dto.getCertificateData());
        PublicKey publicKey = certificate.getPublicKey();
        return new PublicKeyDescriptor(dto.getKeyId(), algorithmFor(publicKey), publicKey, chainOf(certificate),
                toInstant(dto.getIssuedAt(), certificate.getNotBefore().toInstant()),
                toInstant(dto.getExpiryAt(), certificate.getNotAfter().toInstant()), PURPOSE_VC_SIGNING);
    }

    /**
     * The certificate with the configured IACA that issued it ({@link CertificateLinks#issuedBy}: authority key
     * identifier equal to the IACA's subject key identifier, else the issuer name, and the signature verifies), or the
     * certificate alone. Keymanager's self-signed and master-signed certificates are issued by no IACA and stay alone.
     */
    private CertificateChain chainOf(X509Certificate certificate) {
        TrustAnchorRegistry registry = CertificateLinks.selfIssued(certificate) ? null : trustAnchors.get();
        if (registry == null) {
            return CertificateChain.of(certificate);
        }
        return CertificateLinks.issuerAmong(certificate, registry.anchors(TrustAnchorRegistry.MDOC_IACA))
                .map(iaca -> CertificateChain.of(certificate, iaca))
                .orElseGet(() -> CertificateChain.of(certificate));
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
