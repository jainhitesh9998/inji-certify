package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real holder proofs, as a wallet builds them, through the SPI adapter over the legacy validator. */
class JwtProofValidatorAdapterTest {

    static final String AUDIENCE = "https://issuer.example/v1/certify";
    final JwtProofValidator legacy = new JwtProofValidator();
    final JwtProofValidatorAdapter adapter = new JwtProofValidatorAdapter(legacy);
    final IssuanceContext context = new IssuanceContext(TenantContext.DEFAULT, null, List.of(), ProtocolVersion.OID4VCI_1_0, "c", null, Map.of());
    ECKey holder;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(legacy, "credentialIdentifier", AUDIENCE);
        holder = new ECKeyGenerator(Curve.P_256).generate();
    }

    String proof(String typ, String audience, String nonce, JWSAlgorithm alg) throws Exception {
        JWSHeader header = new JWSHeader.Builder(alg).type(typ == null ? null : new JOSEObjectType(typ)).jwk(holder.toPublicJWK()).build();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().audience(audience).issueTime(new Date());
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }
        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    ProofValidator.ProofPolicy policy(String... algorithms) {
        return new ProofValidator.ProofPolicy(List.of(algorithms), AUDIENCE, true, "wallet", Map.of());
    }

    @Test
    void validProofYieldsTheHolderAsDidJwk() throws Exception {
        String jwt = proof("openid4vci-proof+jwt", AUDIENCE, "n-1", JWSAlgorithm.ES256);
        List<String> seen = new java.util.ArrayList<>();

        HolderBinding holder = adapter.validate(new ProofValidator.ProofInput("jwt", jwt), policy("ES256", "EdDSA"), seen::add, context);

        assertEquals(HolderBinding.Kind.DID, holder.kind());
        assertTrue(holder.value().startsWith("did:jwk:"), holder.value());
        String jwk = new String(Base64.getUrlDecoder().decode(holder.value().substring("did:jwk:".length()).replace("#0", "")));
        assertTrue(jwk.contains(this.holder.getX().toString()), "the did:jwk carries the holder's public key");
        assertEquals("jwt", holder.proofType());
        assertEquals(List.of("n-1"), seen, "the nonce store is consulted with the proof's nonce");
    }

    @Test
    void nonceStoreRejectionWins() throws Exception {
        String jwt = proof("openid4vci-proof+jwt", AUDIENCE, "stale", JWSAlgorithm.ES256);
        ProofValidator.NonceCheck store = n -> { throw new ProofValidationException("invalid_nonce", "unknown nonce " + n); };

        ProofValidationException e = assertThrows(ProofValidationException.class, () -> adapter.validate(new ProofValidator.ProofInput("jwt", jwt), policy("ES256"), store, context));

        assertEquals("invalid_nonce", e.getErrorCode());
    }

    @Test
    void missingNonceIsRejectedWhenRequired() throws Exception {
        String jwt = proof("openid4vci-proof+jwt", AUDIENCE, null, JWSAlgorithm.ES256);
        ProofValidationException e = assertThrows(ProofValidationException.class, () -> adapter.validate(new ProofValidator.ProofInput("jwt", jwt), policy("ES256"), ProofValidator.NonceCheck.NONE, context));
        assertEquals("invalid_nonce", e.getErrorCode());
    }

    @Test
    void headerRulesAreEnforced() throws Exception {
        ProofValidationException typ = assertThrows(ProofValidationException.class, () -> adapter.validate(
                new ProofValidator.ProofInput("jwt", proof("JWT", AUDIENCE, "n", JWSAlgorithm.ES256)), policy("ES256"), ProofValidator.NonceCheck.NONE, context));
        assertEquals(ErrorConstants.PROOF_HEADER_INVALID_TYP, typ.getErrorCode());

        ProofValidationException alg = assertThrows(ProofValidationException.class, () -> adapter.validate(
                new ProofValidator.ProofInput("jwt", proof("openid4vci-proof+jwt", AUDIENCE, "n", JWSAlgorithm.ES256)), policy("EdDSA"), ProofValidator.NonceCheck.NONE, context));
        assertEquals(ErrorConstants.PROOF_HEADER_INVALID_ALG, alg.getErrorCode());
    }

    @Test
    void wrongAudienceAndGarbageAreInvalidProofs() throws Exception {
        ProofValidationException aud = assertThrows(ProofValidationException.class, () -> adapter.validate(
                new ProofValidator.ProofInput("jwt", proof("openid4vci-proof+jwt", "https://other", "n", JWSAlgorithm.ES256)), policy("ES256"), ProofValidator.NonceCheck.NONE, context));
        assertEquals("invalid_proof", aud.getErrorCode());
        ProofValidationException garbage = assertThrows(ProofValidationException.class, () -> adapter.validate(
                new ProofValidator.ProofInput("jwt", "not.a.jwt"), policy("ES256"), ProofValidator.NonceCheck.NONE, context));
        assertEquals("invalid_proof", garbage.getErrorCode());
    }
}
