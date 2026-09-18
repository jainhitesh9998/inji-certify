package io.mosip.certify.keyprovider.jca;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KidStrategy;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every JWS produced by the envelope builder is verified with Nimbus, not with Certify code. */
class JwsEnvelopeTest {

    private static final JcaKeyProvider PROVIDER = JcaKeyProvider.devMode();
    private static final String PAYLOAD = "{\"iss\":\"https://issuer.example\",\"vct\":\"FarmerCredential\"}";

    static JWSVerifier verifierFor(SigningKey key) throws Exception {
        JWK jwk = key.descriptor().toJwk();
        if (jwk instanceof RSAKey rsa) {
            return new RSASSAVerifier(rsa);
        }
        if (jwk instanceof ECKey ec) {
            ECDSAVerifier verifier = new ECDSAVerifier(ec);
            verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return verifier;
        }
        return new Ed25519Verifier((OctetKeyPair) jwk);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"ES256", "EdDSA", "RS256", "PS256", "ES256K"})
    void compactJwsVerifiesWithNimbus(SignatureAlgorithm alg) throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-" + alg.joseName().toLowerCase()));
        String compact = JwsEnvelope.sign(PAYLOAD, JwsHeaderPolicy.compact("JWT"), key, PROVIDER);

        JWSObject jws = JWSObject.parse(compact);
        assertEquals(alg.joseName(), jws.getHeader().getAlgorithm().getName());
        assertEquals("JWT", jws.getHeader().getType().getType());
        assertEquals(key.kid(), jws.getHeader().getKeyID());
        assertEquals(PAYLOAD, jws.getPayload().toString());
        assertTrue(jws.verify(verifierFor(key)), "signature must verify for " + alg);
    }

    @Test
    void sdJwtVcPolicyCarriesTypX5cAndThumbprint() throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-es256"));
        String compact = JwsEnvelope.sign(PAYLOAD, JwsHeaderPolicy.sdJwtVc(), key, PROVIDER);
        JWSObject jws = JWSObject.parse(compact);
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertEquals(1, jws.getHeader().getX509CertChain().size());
        assertEquals(KidStrategy.X5T_S256.kidFor(key), jws.getHeader().getX509CertSHA256Thumbprint().toString());
        assertTrue(jws.verify(verifierFor(key)));
    }

    @Test
    void jwkThumbprintKidMatchesRfc7638() throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-eddsa"));
        String compact = JwsEnvelope.sign(PAYLOAD, JwsHeaderPolicy.compact(null).withKid(KidStrategy.JWK_THUMBPRINT), key, PROVIDER);
        JWSObject jws = JWSObject.parse(compact);
        assertEquals(key.descriptor().toJwk().computeThumbprint().toString(), jws.getHeader().getKeyID());
        assertTrue(jws.getHeader().getType() == null);
    }

    @Test
    void detachedUnencodedPayloadJwsVerifiesWithNimbus() throws Exception {
        SigningKey key = PROVIDER.resolve(KeyRef.parse("jca:dev-rs256"));
        byte[] payload = "canonicalized-document-hash".getBytes(StandardCharsets.UTF_8);
        String compact = JwsEnvelope.sign(payload, JwsHeaderPolicy.detachedUnencoded(), key, PROVIDER);

        String[] parts = compact.split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[1], "payload segment is empty for a detached JWS");
        JWSObject jws = JWSObject.parse(compact, new Payload(payload));
        assertEquals(Boolean.FALSE, jws.getHeader().isBase64URLEncodePayload());
        assertTrue(jws.getHeader().getCriticalParams().contains("b64"));
        assertNotNull(jws.getSignature());
        assertTrue(jws.verify(verifierFor(key)));
    }
}
