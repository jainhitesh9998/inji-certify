package io.mosip.certify.keyprovider;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.keyprovider.keymanager.KeymanagerKeyProvider;
import io.mosip.certify.services.JwksServiceImpl;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boots the real service (H2, PKCS#12-backed keymanager) and proves the {@link KeymanagerKeyProvider} bean signs
 * with the keys the startup provisioning created and publishes the same key ids the JWKS endpoint publishes.
 * Signatures are verified with Nimbus against the provider's own public key.
 */
@SpringBootTest
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}"
})
class KeymanagerKeyProviderWiringTest {

    @MockBean DataProviderPlugin dataProviderPlugin;
    @Autowired KeymanagerKeyProvider keymanagerKeyProvider;
    @Autowired List<KeyProvider> keyProviders;
    @Autowired JwksServiceImpl jwksService;

    static JWSVerifier verifierFor(SigningKey key) throws Exception {
        JWK jwk = key.descriptor().toJwk();
        if (jwk instanceof RSAKey rsa) return new RSASSAVerifier(rsa);
        if (jwk instanceof ECKey ec) {
            ECDSAVerifier verifier = new ECDSAVerifier(ec);
            verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return verifier;
        }
        return new Ed25519Verifier((OctetKeyPair) jwk);
    }

    @ParameterizedTest
    @ValueSource(strings = {"keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "keymanager:CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN",
            "keymanager:CERTIFY_VC_SIGN_EC_K1/EC_SECP256K1_SIGN", "keymanager:CERTIFY_VC_SIGN_RSA"})
    void provisionedKeysSignVerifiableJws(String ref) throws Exception {
        SigningKey key = keymanagerKeyProvider.resolve(KeyRef.parse(ref));
        String payload = "{\"iss\":\"https://issuer.example\",\"ref\":\"" + ref + "\"}";

        String compact = JwsEnvelope.sign(payload, JwsHeaderPolicy.compact("JWT"), key, keymanagerKeyProvider);

        JWSObject jws = JWSObject.parse(compact);
        assertEquals(key.algorithm().joseName(), jws.getHeader().getAlgorithm().getName());
        assertEquals(key.kid(), jws.getHeader().getKeyID());
        assertTrue(jws.verify(verifierFor(key)), "keymanager-signed JWS must verify for " + ref);
    }

    @Test
    @SuppressWarnings("unchecked")
    void providerPublishesTheKeyIdsTheJwksEndpointPublishes() {
        Set<String> providerKids = keymanagerKeyProvider.publicKeys(KeyFilter.validNow()).stream().map(PublicKeyDescriptor::kid).collect(java.util.stream.Collectors.toSet());
        List<Map<String, Object>> jwks = (List<Map<String, Object>>) jwksService.getJwks().get("keys");
        Set<String> jwksKids = jwks.stream().map(k -> (String) k.get("kid")).collect(java.util.stream.Collectors.toSet());

        assertEquals(jwksKids, providerKids, "the provider and today's JWKS endpoint must agree on the published keys");
        assertTrue(providerKids.size() >= 5, "four signing keys plus CERTIFY_SERVICE, got " + providerKids);
    }

    @Test
    void keymanagerIsTheOnlyKeyProviderBean() {
        assertEquals(1, keyProviders.size());
        assertEquals("keymanager", keyProviders.get(0).id());
    }
}
