/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.*;

import static io.mosip.certify.core.constants.ErrorConstants.UNSUPPORTED_ALGORITHM;
import static io.mosip.certify.proof.DIDkeysProofManager.DID_KEY_PREFIX;

@Slf4j
@Component
public class JwtProofValidator implements ProofValidator {

    private static final String HEADER_TYP = "openid4vci-proof+jwt";
    private static final String DID_JWK_PREFIX = "did:jwk:";

    @Value("${mosip.certify.identifier}")
    private String credentialIdentifier;

    /** Present only when did:web holders are enabled (DidWebHolderConfiguration). */
    @Autowired(required = false)
    private DIDwebProofManager didWebProofManager;

    @Override
    public String getProofType() {
        return "jwt";
    }

    private static final Set<JWSAlgorithm> allowedSignatureAlgorithms;

    private static final Set<String> DEFAULT_REQUIRED_CLAIMS = Set.of("aud", "iat");

    static {
        allowedSignatureAlgorithms = new HashSet<>();
        allowedSignatureAlgorithms.addAll(List.of(JWSAlgorithm.Family.SIGNATURE.toArray(new JWSAlgorithm[0])));
    }

    @Override
    public boolean validate(String clientId, String cNonce, String proofJwt, Map<String, Object> proofConfiguration) {
        return validate(clientId, cNonce, proofJwt, proofConfiguration, credentialIdentifier);
    }

    /** Same checks with an explicit expected audience (the new surface has its own issuer identifier). */
    public boolean validate(String clientId, String cNonce, String proofJwt, Map<String, Object> proofConfiguration, String expectedAudience) {
        if(proofJwt == null || proofJwt.isBlank()) {
            log.error("Found invalid jwt in the credential proof");
            return false;
        }

        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(proofJwt);
            Map<String, Object> jwtConfiguration;
            if(proofConfiguration.get("jwt") != null) {
                jwtConfiguration =(Map<String, Object>) proofConfiguration.get("jwt");
            } else {
                throw new InvalidRequestException(UNSUPPORTED_ALGORITHM);
            }
            List<String> algorithms = (List<String>) jwtConfiguration.getOrDefault("proof_signing_alg_values_supported", List.of());
            validateHeaderClaims(jwt.getHeader(), algorithms);
            JwtProofKeyManager jpkm = getInstance(jwt.getHeader().getKeyID());
            JWK jwk = jpkm.getKeyFromHeader(jwt.getHeader())
                    .orElseThrow(() -> new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY));
            if(jwk.isPrivate()) {
                log.error("Provided key material contains private key! Rejecting proof.");
                throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
            }

            if (StringUtils.isEmpty(cNonce) && jwt.getJWTClaimsSet().getClaim("nonce") != null) {
                log.error("Nonce claim is present in proof JWT but no c_nonce is expected");
                return false;
            }

            JWTClaimsSet.Builder proofJwtClaimsBuilder = new JWTClaimsSet.Builder()
                    .audience(expectedAudience == null ? credentialIdentifier : expectedAudience);
            if (!StringUtils.isEmpty(cNonce)) {
                proofJwtClaimsBuilder = proofJwtClaimsBuilder
                        .claim("nonce", cNonce);
            }

            // OpenID4VCI 1.0 F.1: iss, when present, is the client_id; it is omitted in the anonymous pre-authorized code
            // flow. Wallets in the field (Inji, for issuers that expose a nonce endpoint) put their own holder DID there
            // instead; that names the very key that signs the proof, so it is accepted when no client_id is known.
            Set<String> requiredClaims = new HashSet<>(DEFAULT_REQUIRED_CLAIMS);
            String proofIssuer = jwt.getJWTClaimsSet().getIssuer();
            if (proofIssuer != null) {
                if (!StringUtils.isEmpty(clientId)) {
                    proofJwtClaimsBuilder.issuer(clientId);
                } else if (!proofIssuer.equals(holderDidWithoutFragment(jwt.getHeader()))) {
                    log.error("Proof iss {} is neither a client_id nor the holder's own DID", proofIssuer);
                    return false;
                }
            }
            if(jwt.getJWTClaimsSet().getClaim("exp") != null) {
                requiredClaims.add("exp");
            }

            DefaultJWTClaimsVerifier claimsSetVerifier = new DefaultJWTClaimsVerifier(proofJwtClaimsBuilder.build(), requiredClaims);

            claimsSetVerifier.setMaxClockSkew(0);
            JWSKeySelector keySelector;
            if(JWSAlgorithm.ES256K.equals(jwt.getHeader().getAlgorithm())) {
                ECDSAVerifier verifier = new ECDSAVerifier((com.nimbusds.jose.jwk.ECKey) jwk);
                verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else if (JWSAlgorithm.EdDSA.equals(jwt.getHeader().getAlgorithm()))
            {
                Ed25519Verifier verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else {
                keySelector = new JWSVerificationKeySelector(allowedSignatureAlgorithms,
                        new ImmutableJWKSet(new JWKSet(jwk)));
                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(keySelector);
                jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType(HEADER_TYP)));
                jwtProcessor.setJWTClaimsSetVerifier(claimsSetVerifier);
                jwtProcessor.process(proofJwt, null);
                return true;
            }
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (BadJOSEException | JOSEException e) {
            log.error("JWT proof verification failed", e);
        }
        return false;
    }


    /** The DID the proof header names (did:jwk of its jwk, or the kid) without a fragment, or null. */
    private String holderDidWithoutFragment(JWSHeader header) {
        String did = getInstance(header.getKeyID()).getDID(header).orElse(null);
        if (did == null) {
            return null;
        }
        int fragment = did.indexOf('#');
        return fragment < 0 ? did : did.substring(0, fragment);
    }

    /**
     * @param proofJwt from the credential request.
     * @return the key material from the proof in a did:jwk or did:key format
     */
    @Override
    public String getKeyMaterial(String proofJwt) {
        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(proofJwt);
            JwtProofKeyManager jpkm = getInstance(jwt.getHeader().getKeyID());
            return jpkm.getDID(jwt.getHeader()).get();
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        }
        throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
    }

    private void validateHeaderClaims(JWSHeader jwsHeader, List<String> algorithms) {
        if(Objects.isNull(jwsHeader.getType()) || !HEADER_TYP.equals(jwsHeader.getType().getType()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_TYP);

        if(Objects.isNull(jwsHeader.getAlgorithm()) || !algorithms.contains(jwsHeader.getAlgorithm().getName()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_ALG);

        if ((Objects.isNull(jwsHeader.getKeyID()) && Objects.isNull(jwsHeader.getJWK()))
                ||
                (Objects.isNull(jwsHeader.getJWK()) && Objects.nonNull(jwsHeader.getKeyID()) &&
                        !(jwsHeader.getKeyID().startsWith(DID_KEY_PREFIX) || jwsHeader.getKeyID().startsWith(DID_JWK_PREFIX)
                                || (didWebProofManager != null && jwsHeader.getKeyID().startsWith(DIDwebProofManager.DID_WEB_PREFIX)))))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);

        // both cannot be present, either one of them is only allowed
        if(Objects.nonNull(jwsHeader.getKeyID()) && Objects.nonNull(jwsHeader.getJWK()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY);

        //TODO x5c and trust_chain validation
    }

    public JwtProofKeyManager getInstance(String kid) {
        if (kid == null || kid.startsWith(DID_JWK_PREFIX)) {
            return new DIDjwkProofManager();
        } else if (kid.startsWith("did:key:")) {
            return new DIDkeysProofManager();
        } else if (kid.startsWith(DIDwebProofManager.DID_WEB_PREFIX) && didWebProofManager != null) {
            return didWebProofManager; // certify.protocol.oid4vci-v1.did-web-holders.enabled
        } else {
            return new DIDjwkProofManager();
        }
    }
}