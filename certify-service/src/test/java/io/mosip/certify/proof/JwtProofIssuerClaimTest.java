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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code iss} claim of a jwt proof: the client_id when the wallet authenticated as a client; in the anonymous
 * pre-authorized code flow (no client_id) only the holder's own DID is tolerated (what Inji Wallet sends to issuers
 * that expose a nonce endpoint), anything else is refused (F-07).
 */
class JwtProofIssuerClaimTest {

    static final String AUDIENCE = "https://issuer.example/v1/certify";
    static final Map<String, Object> CONFIG = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256")));
    final JwtProofValidator validator = new JwtProofValidator();
    ECKey holder;
    String didJwk;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(validator, "credentialIdentifier", AUDIENCE);
        holder = new ECKeyGenerator(Curve.P_256).generate();
        didJwk = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(holder.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void anonymousProofMayNameItsOwnHolderDidAsIss() throws Exception {
        assertTrue(validator.validate(null, "n-1", proof(didJwk, true), CONFIG), "kid did:jwk#0 with iss = did:jwk");
        assertTrue(validator.validate(null, "n-1", proof(didJwk, false), CONFIG), "jwk header with iss = did:jwk");
        assertTrue(validator.validate(null, "n-1", proof(null, false), CONFIG), "no iss at all, as the specification says");
    }

    @Test
    void anonymousProofWithAnyOtherIssIsRefused() throws Exception {
        assertFalse(validator.validate(null, "n-1", proof("did:jwk:c29tZW9uZS1lbHNl", true), CONFIG), "another DID");
        assertFalse(validator.validate(null, "n-1", proof("wallet-client", false), CONFIG), "a client id nobody presented");
    }

    @Test
    void clientProofMustStillNameTheClientId() throws Exception {
        assertTrue(validator.validate("wallet-client", "n-1", proof("wallet-client", false), CONFIG));
        assertFalse(validator.validate("wallet-client", "n-1", proof(didJwk, false), CONFIG), "the holder DID is not the client_id");
    }

    private String proof(String iss, boolean kidForm) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"));
        if (kidForm) {
            header.keyID(didJwk + "#0");
        } else {
            header.jwk(holder.toPublicJWK());
        }
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().audience(AUDIENCE).issueTime(new Date()).claim("nonce", "n-1");
        if (iss != null) {
            claims.issuer(iss);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }
}
