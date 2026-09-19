package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.oid4vci.Oid4vciProperties;
import io.mosip.certify.spi.ProofValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Key attestations in JWT format (OpenID4VCI 1.0 Appendix D): {@code typ key-attestation+jwt}, signed by a wallet
 * provider or key storage component the deployment trusts, attesting the {@code attested_keys} a credential may be
 * bound to and their {@code key_storage} and {@code user_authentication} attack potential resistance (Appendix D.2).
 * Attesters are configured under {@code certify.protocol.oid4vci-v1.key-attestation.attesters.<id>}: a JWK Set
 * ({@code jwks}) the attestation's key is in, or a PEM trust anchor ({@code trust-anchor}) its {@code x5c} chains to.
 * A configuration states what it accepts in {@code proof_types_supported.<type>.key_attestations_required}.
 */
@Slf4j
@Component
public class KeyAttestationValidator {

    public static final String TYP = "key-attestation+jwt";
    public static final String CLAIM_ATTESTED_KEYS = "attested_keys";
    public static final String CLAIM_KEY_STORAGE = "key_storage";
    public static final String CLAIM_USER_AUTHENTICATION = "user_authentication";
    public static final String ERROR_INVALID_PROOF = "invalid_proof";

    private final Oid4vciProperties.KeyAttestation settings;
    private final Clock clock;
    private final DefaultJWSVerifierFactory verifiers = new DefaultJWSVerifierFactory();

    @org.springframework.beans.factory.annotation.Autowired
    public KeyAttestationValidator(Oid4vciProperties properties) {
        this(properties.keyAttestation(), Clock.systemUTC());
    }

    public KeyAttestationValidator(Oid4vciProperties.KeyAttestation settings, Clock clock) {
        this.settings = settings == null ? new Oid4vciProperties.KeyAttestation(Map.of(), java.time.Duration.ofSeconds(60)) : settings;
        this.clock = clock;
    }

    /** A verified key attestation: the keys it attests and the claims a policy checks. */
    public record KeyAttestation(SignedJWT jwt, List<JWK> attestedKeys, List<String> keyStorage, List<String> userAuthentication, String nonce) {
        /** Whether {@code key} (public part) is one of the attested keys, by JWK thumbprint. */
        public boolean attests(JWK key) {
            try {
                String thumbprint = key.toPublicJWK().computeThumbprint().toString();
                for (JWK attested : attestedKeys) {
                    if (thumbprint.equals(attested.toPublicJWK().computeThumbprint().toString())) {
                        return true;
                    }
                }
            } catch (JOSEException e) {
                log.warn("Could not compute a JWK thumbprint: {}", e.getMessage());
            }
            return false;
        }
    }

    public boolean configured() {
        return settings.attesters() != null && !settings.attesters().isEmpty();
    }

    /**
     * Parses and verifies one key attestation.
     *
     * @param compact           the JWT
     * @param allowedAlgorithms {@code proof_signing_alg_values_supported} of the proof type it arrives with (Appendix F: the attestation's alg must be one of them)
     * @param required          the configuration's {@code key_attestations_required} object, or {@code null} when attestations are optional
     * @param expRequired       whether {@code exp} must be present (true with the {@code jwt} proof type, Appendix D.1)
     */
    public KeyAttestation validate(String compact, List<String> allowedAlgorithms, Map<String, Object> required, boolean expRequired) throws ProofValidationException {
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(compact);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation is not a signed JWT: " + e.getMessage());
        }
        if (jwt.getHeader().getType() == null || !TYP.equals(jwt.getHeader().getType().getType())) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation typ must be " + TYP);
        }
        String alg = jwt.getHeader().getAlgorithm() == null ? null : jwt.getHeader().getAlgorithm().getName();
        if (alg == null || "none".equals(alg) || (allowedAlgorithms != null && !allowedAlgorithms.isEmpty() && !allowedAlgorithms.contains(alg))) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation alg " + alg + " is not in proof_signing_alg_values_supported");
        }
        if (!configured()) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "No key attester is configured (certify.protocol.oid4vci-v1.key-attestation.attesters)");
        }
        if (!signedByAnAttester(jwt)) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation is not signed by a trusted attester");
        }
        Instant now = clock.instant();
        long skew = settings.clockSkew() == null ? 0 : settings.clockSkew().getSeconds();
        if (claims.getIssueTime() == null) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation needs iat");
        }
        if (claims.getIssueTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation iat is in the future");
        }
        if (claims.getExpirationTime() == null && expRequired) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation needs exp with the jwt proof type");
        }
        if (claims.getExpirationTime() != null && claims.getExpirationTime().toInstant().isBefore(now.minusSeconds(skew))) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation has expired");
        }
        List<JWK> attestedKeys = attestedKeys(claims);
        List<String> keyStorage = strings(claims.getClaim(CLAIM_KEY_STORAGE), CLAIM_KEY_STORAGE);
        List<String> userAuthentication = strings(claims.getClaim(CLAIM_USER_AUTHENTICATION), CLAIM_USER_AUTHENTICATION);
        if (required != null) {
            requireOneOf(required.get(CLAIM_KEY_STORAGE), keyStorage, CLAIM_KEY_STORAGE);
            requireOneOf(required.get(CLAIM_USER_AUTHENTICATION), userAuthentication, CLAIM_USER_AUTHENTICATION);
        }
        Object nonce = claims.getClaim("nonce");
        return new KeyAttestation(jwt, attestedKeys, keyStorage, userAuthentication, nonce == null ? null : nonce.toString());
    }

    /** {@code accepted} (from key_attestations_required) is satisfied when the attestation asserts at least one of its values. */
    private static void requireOneOf(Object accepted, List<String> asserted, String claim) throws ProofValidationException {
        if (!(accepted instanceof Collection<?> values) || values.isEmpty()) {
            return;
        }
        for (Object value : values) {
            if (asserted.contains(String.valueOf(value))) {
                return;
            }
        }
        throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation " + claim + " " + asserted + " is not among the accepted values " + values);
    }

    private static List<JWK> attestedKeys(JWTClaimsSet claims) throws ProofValidationException {
        Object raw = claims.getClaim(CLAIM_ATTESTED_KEYS);
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation needs a non-empty attested_keys array");
        }
        List<JWK> keys = new ArrayList<>();
        for (Object entry : list) {
            if (!(entry instanceof Map<?, ?> map)) {
                throw new ProofValidationException(ERROR_INVALID_PROOF, "attested_keys entries must be JWK objects");
            }
            try {
                @SuppressWarnings("unchecked")
                JWK key = JWK.parse((Map<String, Object>) map);
                if (key.isPrivate()) {
                    throw new ProofValidationException(ERROR_INVALID_PROOF, "attested_keys must not carry private keys");
                }
                keys.add(key);
            } catch (ParseException e) {
                throw new ProofValidationException(ERROR_INVALID_PROOF, "attested_keys entry is not a JWK: " + e.getMessage());
            }
        }
        return keys;
    }

    private static List<String> strings(Object raw, String claim) throws ProofValidationException {
        if (raw == null) {
            return List.of();
        }
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            throw new ProofValidationException(ERROR_INVALID_PROOF, "Key attestation " + claim + " must be a non-empty array");
        }
        return list.stream().map(String::valueOf).toList();
    }

    /** {@code x5c}: the leaf signs and chains to a configured trust anchor; otherwise a key of a configured JWK Set signs. */
    private boolean signedByAnAttester(SignedJWT jwt) {
        List<Base64> x5c = jwt.getHeader().getX509CertChain();
        if (x5c != null && !x5c.isEmpty()) {
            return signedByAChainToATrustAnchor(jwt, x5c);
        }
        for (Map.Entry<String, Oid4vciProperties.Attester> entry : settings.attesters().entrySet()) {
            if (entry.getValue().jwks() == null || entry.getValue().jwks().isBlank()) {
                continue;
            }
            try {
                for (JWK key : JWKSet.parse(entry.getValue().jwks()).getKeys()) {
                    if (jwt.getHeader().getKeyID() != null && key.getKeyID() != null && !jwt.getHeader().getKeyID().equals(key.getKeyID())) {
                        continue;
                    }
                    if (verifies(jwt, key)) {
                        log.debug("Key attestation verified with attester {}", entry.getKey());
                        return true;
                    }
                }
            } catch (ParseException e) {
                log.error("Attester {} has an unparsable jwks: {}", entry.getKey(), e.getMessage());
            }
        }
        return false;
    }

    private boolean signedByAChainToATrustAnchor(SignedJWT jwt, List<Base64> x5c) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<>();
            for (Base64 encoded : x5c) {
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded.decode())));
            }
            Set<TrustAnchor> anchors = trustAnchors(factory);
            if (anchors.isEmpty()) {
                log.warn("Key attestation carries x5c but no attester has a trust-anchor configured");
                return false;
            }
            if (!verifies(jwt, JWK.parse(chain.get(0)))) {
                return false;
            }
            // the chain as sent, minus any anchor the wallet included: PKIX finds the anchor among the configured ones
            List<X509Certificate> path = new ArrayList<>(chain);
            path.removeIf(certificate -> anchors.stream().anyMatch(anchor -> anchor.getTrustedCert().equals(certificate)));
            if (path.isEmpty()) {
                return false;
            }
            PKIXParameters parameters = new PKIXParameters(anchors);
            parameters.setRevocationEnabled(false);
            parameters.setDate(java.util.Date.from(clock.instant()));
            CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(path), parameters);
            return true;
        } catch (Exception e) {
            log.warn("Key attestation x5c does not chain to a configured trust anchor: {}", e.getMessage());
            return false;
        }
    }

    private Set<TrustAnchor> trustAnchors(CertificateFactory factory) throws java.security.cert.CertificateException {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (Oid4vciProperties.Attester attester : settings.attesters().values()) {
            if (attester.trustAnchor() == null || attester.trustAnchor().isBlank()) {
                continue;
            }
            for (java.security.cert.Certificate certificate : factory.generateCertificates(new ByteArrayInputStream(attester.trustAnchor().getBytes(java.nio.charset.StandardCharsets.US_ASCII)))) {
                anchors.add(new TrustAnchor((X509Certificate) certificate, null));
            }
        }
        return anchors;
    }

    private boolean verifies(SignedJWT jwt, JWK key) {
        try {
            JWSVerifier verifier;
            if (key instanceof OctetKeyPair okp) {
                verifier = new Ed25519Verifier(okp.toPublicJWK());
            } else if (key instanceof com.nimbusds.jose.jwk.ECKey ec) {
                verifier = verifiers.createJWSVerifier(jwt.getHeader(), ec.toECPublicKey());
            } else if (key instanceof com.nimbusds.jose.jwk.RSAKey rsa) {
                verifier = verifiers.createJWSVerifier(jwt.getHeader(), rsa.toRSAPublicKey());
            } else {
                return false;
            }
            return jwt.verify(verifier);
        } catch (JOSEException e) {
            return false; // a key of another algorithm
        }
    }
}
