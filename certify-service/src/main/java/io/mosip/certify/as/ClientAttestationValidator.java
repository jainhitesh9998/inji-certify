package io.mosip.certify.as;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.services.OAuthAuthorizationServerMetadataService;
import io.mosip.certify.services.VCICacheService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth 2.0 attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth, HAIP Appendix E):
 * {@code OAuth-Client-Attestation} is a JWT ({@code typ oauth-client-attestation+jwt}) signed by a trusted attester
 * with {@code sub} = client_id and the wallet instance key in {@code cnf.jwk}; {@code OAuth-Client-Attestation-PoP}
 * ({@code typ oauth-client-attestation-pop+jwt}) is signed by that key with {@code aud} = this authorization server,
 * a single-use {@code jti} and a fresh {@code iat}. Attesters are configured under
 * {@code certify.as.client-attestation.attesters.<id>.jwks}; {@code required=true} refuses unauthenticated calls
 * (the HAIP rule), otherwise the headers are validated when present.
 */
@Slf4j
@Component
public class ClientAttestationValidator {

    public static final String HEADER_ATTESTATION = "OAuth-Client-Attestation";
    public static final String HEADER_POP = "OAuth-Client-Attestation-PoP";
    public static final String TYP_ATTESTATION = "oauth-client-attestation+jwt";
    public static final String TYP_POP = "oauth-client-attestation-pop+jwt";
    public static final String AUTH_METHOD = "attest_jwt_client_auth";
    static final String ERROR_INVALID_CLIENT = "invalid_client";

    private final AsProperties properties;
    private final OAuthAuthorizationServerMetadataService metadata;
    private final VCICacheService cache;
    private final DefaultJWSVerifierFactory verifiers = new DefaultJWSVerifierFactory();

    public ClientAttestationValidator(AsProperties properties, OAuthAuthorizationServerMetadataService metadata, VCICacheService cache) {
        this.properties = properties;
        this.metadata = metadata;
        this.cache = cache;
    }

    public boolean configured() {
        AsProperties.ClientAttestation attestation = properties.clientAttestation();
        return attestation != null && attestation.attesters() != null && !attestation.attesters().isEmpty();
    }

    /** Validates the two headers for the client the request names; answers the attested client id, or empty when no attestation was presented and none is required. */
    public Optional<String> validate(HttpServletRequest request, String expectedClientId) {
        String attestation = request.getHeader(HEADER_ATTESTATION);
        String pop = request.getHeader(HEADER_POP);
        boolean required = properties.clientAttestation() != null && properties.clientAttestation().required();
        if (attestation == null && pop == null) {
            if (required) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation is required (" + HEADER_ATTESTATION + " and " + HEADER_POP + ")");
            }
            return Optional.empty();
        }
        if (attestation == null || pop == null) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "Both " + HEADER_ATTESTATION + " and " + HEADER_POP + " are required");
        }
        if (!configured()) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "No client attester is configured");
        }
        try {
            SignedJWT attestationJwt = SignedJWT.parse(attestation);
            requireType(attestationJwt, TYP_ATTESTATION);
            if (!verifiesWithAnAttester(attestationJwt)) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation is not signed by a trusted attester");
            }
            JWTClaimsSet attestationClaims = attestationJwt.getJWTClaimsSet();
            String clientId = attestationClaims.getSubject();
            if (clientId == null || (expectedClientId != null && !clientId.equals(expectedClientId))) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation sub must be the client_id");
            }
            requireNotExpired(attestationClaims.getExpirationTime(), "Client attestation");
            JWK instanceKey = confirmationKey(attestationClaims);

            SignedJWT popJwt = SignedJWT.parse(pop);
            requireType(popJwt, TYP_POP);
            JWSVerifier popVerifier = verifiers.createJWSVerifier(popJwt.getHeader(),
                    instanceKey instanceof com.nimbusds.jose.jwk.ECKey ec ? ec.toECPublicKey() : instanceKey.toRSAKey().toRSAPublicKey());
            if (!popJwt.verify(popVerifier)) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation PoP is not signed by the attested key");
            }
            JWTClaimsSet popClaims = popJwt.getJWTClaimsSet();
            String issuer = metadata.getOAuthAuthorizationServerMetadata().getIssuer();
            List<String> audience = popClaims.getAudience();
            if (issuer == null || audience == null || !audience.contains(issuer)) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation PoP aud must be the authorization server issuer " + issuer);
            }
            if (popClaims.getJWTID() == null || popClaims.getJWTID().isBlank()) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation PoP needs a jti");
            }
            Date issuedAt = popClaims.getIssueTime();
            long skew = properties.clientAttestation().clockSkew().getSeconds();
            long maxAge = properties.clientAttestation().popMaxAge().getSeconds();
            long now = Instant.now().getEpochSecond();
            if (issuedAt == null || issuedAt.getTime() / 1000 > now + skew || issuedAt.getTime() / 1000 < now - maxAge - skew) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation PoP iat is missing or stale");
            }
            requireNotExpired(popClaims.getExpirationTime(), "Client attestation PoP");
            if (!cache.claimClientAttestationJti(popClaims.getJWTID(), maxAge + skew)) {
                throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation PoP jti was already used");
            }
            return Optional.of(clientId);
        } catch (ParseException e) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation headers are not JWTs: " + e.getMessage());
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation could not be verified: " + e.getMessage());
        }
    }

    private boolean verifiesWithAnAttester(SignedJWT jwt) throws com.nimbusds.jose.JOSEException, ParseException {
        for (Map.Entry<String, AsProperties.Attester> entry : properties.clientAttestation().attesters().entrySet()) {
            JWKSet set = JWKSet.parse(entry.getValue().jwks());
            for (JWK key : set.getKeys()) {
                if (jwt.getHeader().getKeyID() != null && key.getKeyID() != null && !jwt.getHeader().getKeyID().equals(key.getKeyID())) {
                    continue;
                }
                try {
                    JWSVerifier verifier = key instanceof com.nimbusds.jose.jwk.ECKey ec ? verifiers.createJWSVerifier(jwt.getHeader(), ec.toECPublicKey())
                            : verifiers.createJWSVerifier(jwt.getHeader(), key.toRSAKey().toRSAPublicKey());
                    if (jwt.verify(verifier)) {
                        log.debug("Client attestation verified with attester {}", entry.getKey());
                        return true;
                    }
                } catch (com.nimbusds.jose.JOSEException ignored) {
                    // a key of another algorithm; try the next one
                }
            }
        }
        return false;
    }

    private static JWK confirmationKey(JWTClaimsSet claims) throws ParseException {
        Object cnf = claims.getClaim("cnf");
        if (!(cnf instanceof Map<?, ?> map) || !(map.get("jwk") instanceof Map<?, ?> jwk)) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "Client attestation needs cnf.jwk");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkMap = (Map<String, Object>) jwk;
        return JWK.parse(jwkMap);
    }

    private static void requireType(SignedJWT jwt, String typ) {
        JOSEObjectType type = jwt.getHeader().getType();
        if (type == null || !typ.equals(type.getType())) {
            throw new AsException(401, ERROR_INVALID_CLIENT, "JWT typ must be " + typ);
        }
    }

    private static void requireNotExpired(Date expiration, String what) {
        if (expiration == null) {
            throw new AsException(401, ERROR_INVALID_CLIENT, what + " needs exp");
        }
        if (expiration.toInstant().isBefore(Instant.now())) {
            throw new AsException(401, ERROR_INVALID_CLIENT, what + " has expired");
        }
    }
}
