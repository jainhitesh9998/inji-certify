package io.mosip.certify.keyprovider;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.keyprovider.keymanager.KeymanagerKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every ECDSA signature the keymanager provider hands out must be the fixed-width JOSE concatenation
 * ({@code R || S}, 64 bytes for P-256 and secp256k1) and verify with plain JCA: a converter that drops or keeps a
 * leading zero byte of R or S produces a wrong signature roughly once in a hundred, which no single golden run sees.
 */
@SpringBootTest
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class KeymanagerEcdsaSignatureFormatTest {

    static final int ROUNDS = 400;

    @MockBean DataProviderPlugin dataProviderPlugin;
    @Autowired KeymanagerKeyProvider keymanagerKeyProvider;

    @ParameterizedTest
    @CsvSource({"keymanager:CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN, ES256", "keymanager:CERTIFY_VC_SIGN_EC_K1/EC_SECP256K1_SIGN, ES256K"})
    void everyEcdsaSignatureIsFixedWidthAndVerifies(String ref, String alg) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(alg).orElseThrow();
        SigningKey key = keymanagerKeyProvider.resolve(KeyRef.parse(ref)).withAlgorithm(algorithm);
        ECKey jwk = (ECKey) key.descriptor().toJwk();
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        SecureRandom random = new SecureRandom();
        Map<Integer, Integer> lengths = new TreeMap<>();
        int failures = 0;
        for (int i = 0; i < ROUNDS; i++) {
            byte[] data = new byte[32];
            random.nextBytes(data);
            byte[] signature = keymanagerKeyProvider.signRaw(data, key, algorithm);
            lengths.merge(signature.length, 1, Integer::sum);
            boolean ok = false;
            if (signature.length == 64) {
                verifier.initVerify(jwk.toECPublicKey());
                verifier.update(data);
                ok = verifier.verify(ECDSA.transcodeSignatureToDER(signature));
            }
            if (!ok) {
                failures++;
            }
        }
        assertEquals(Map.of(64, ROUNDS), lengths, ref + ": signature lengths seen " + lengths);
        assertTrue(failures == 0, ref + ": " + failures + " of " + ROUNDS + " signatures did not verify (lengths " + lengths + ")");
    }
}
