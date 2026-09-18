package io.mosip.certify.keyprovider.jca;

import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JcaKeyProviderTest {

    @Test
    void devModeGeneratesOneKeyPerAlgorithmWithSelfSignedCertificates() {
        JcaKeyProvider provider = JcaKeyProvider.devMode();
        assertEquals(List.of("dev-es256", "dev-eddsa", "dev-rs256", "dev-ps256", "dev-es256k"), List.copyOf(provider.aliases()));
        List<PublicKeyDescriptor> keys = provider.publicKeys(KeyFilter.validNow());
        assertEquals(5, keys.size());
        for (PublicKeyDescriptor key : keys) {
            assertEquals(1, key.chain().leafFirst().size());
            assertTrue(key.isValidAt(Instant.now()));
            assertNotNull(key.toJwk().getKeyID());
            assertEquals(1, key.toJwk().getX509CertChain().size());
        }
        assertEquals(1, provider.publicKeys(new KeyFilter(null, SignatureAlgorithm.EdDSA, null)).size());
    }

    @Test
    void resolveReturnsTheJcaPrivateKeyAsHandle() {
        JcaKeyProvider provider = JcaKeyProvider.devMode();
        SigningKey key = provider.resolve(KeyRef.parse("jca:dev-es256"));
        assertEquals(SignatureAlgorithm.ES256, key.algorithm());
        assertTrue(key.providerHandle() instanceof java.security.PrivateKey);
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("jca:missing")));
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("keymanager:dev-es256")));
    }

    @Test
    void ensureKeysCreatesMissingAliasesOnly() {
        JcaKeyProvider provider = new JcaKeyProvider();
        provider.ensureKeys(List.of(new KeyRequirement("issuer", SignatureAlgorithm.ES256, "vc-signing"),
                new KeyRequirement("token", SignatureAlgorithm.RS256, "access-token")));
        assertEquals(2, provider.aliases().size());
        provider.ensureKeys(List.of(new KeyRequirement("issuer", SignatureAlgorithm.ES256, "vc-signing")));
        assertEquals(2, provider.aliases().size());
        assertEquals(1, provider.publicKeys(KeyFilter.purpose("access-token")).size());
    }

    @Test
    void pkcs12RoundTripKeepsKeysAndChains(@TempDir Path dir) {
        JcaKeyProvider generated = JcaKeyProvider.devMode();
        Path file = dir.resolve("dev.p12");
        generated.saveAsPkcs12(file, "secret".toCharArray());

        JcaKeyProvider loaded = JcaKeyProvider.fromPkcs12(file, "secret".toCharArray());
        assertEquals(generated.aliases(), loaded.aliases());
        for (String alias : loaded.aliases()) {
            SigningKey a = generated.resolve(new KeyRef("jca", alias));
            SigningKey b = loaded.resolve(new KeyRef("jca", alias));
            assertEquals(a.descriptor().publicKey(), b.descriptor().publicKey());
            assertEquals(a.chain().leafFirst(), b.chain().leafFirst());
        }
        // PS256 and RS256 share a key type; the loaded algorithm is derived from the key, so PS256 becomes RS256
        assertEquals(SignatureAlgorithm.RS256, loaded.resolve(new KeyRef("jca", "dev-ps256")).algorithm());
    }

    @Test
    void signingWithTheWrongAlgorithmForTheKeyIsRefused() {
        JcaKeyProvider provider = JcaKeyProvider.devMode();
        SigningKey ed = provider.resolve(KeyRef.parse("jca:dev-eddsa"));
        assertThrows(SigningException.class, () -> provider.signRaw(new byte[]{1}, ed, SignatureAlgorithm.ES256));
    }
}
