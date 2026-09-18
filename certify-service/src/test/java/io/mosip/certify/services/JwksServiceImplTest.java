package io.mosip.certify.services;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyPublisher;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** JWKS built from key providers; the field set per key is the one the keymanager-backed publisher produced. */
public class JwksServiceImplTest {

    /** A provider whose descriptors the test controls (validity windows, keys without certificates). */
    static final class FakeKeyProvider implements KeyProvider {
        final List<PublicKeyDescriptor> descriptors = new ArrayList<>();
        public String id() { return "fake"; }
        public SigningKey resolve(KeyRef ref) { throw new UnsupportedOperationException(); }
        public List<PublicKeyDescriptor> publicKeys(KeyFilter filter) { return descriptors.stream().filter((filter == null ? KeyFilter.ALL : filter)::matches).toList(); }
        public Set<SignatureAlgorithm> supportedAlgorithms() { return EnumSet.allOf(SignatureAlgorithm.class); }
        public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) { throw new UnsupportedOperationException(); }
    }

    final JcaKeyProvider jca = new JcaKeyProvider("keymanager");
    final FakeKeyProvider fake = new FakeKeyProvider();
    final JwksServiceImpl jwksService = new JwksServiceImpl();

    @Before
    public void setUp() {
        jca.generate("CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", SignatureAlgorithm.ES256, "CN=r1", "vc-signing");
        jca.generate("CERTIFY_VC_SIGN_RSA", SignatureAlgorithm.RS256, "CN=rsa", "vc-signing");
        jca.generate("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", SignatureAlgorithm.EdDSA, "CN=ed", "vc-signing");
        ReflectionTestUtils.setField(jwksService, "keyPublisher", new KeyPublisher(List.of(jca, fake)));
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> keys() {
        return (List<Map<String, Object>>) jwksService.getJwks().get("keys");
    }

    private Map<String, Object> key(String kty) {
        return keys().stream().filter(k -> kty.equals(k.get("kty"))).findFirst().orElseThrow();
    }

    @Test
    public void ecKeyHasTheKeymanagerFieldSet() {
        Map<String, Object> ec = key("EC");
        assertEquals(Set.of("kid", "kty", "use", "exp", "x5c", "x5t#S256", "x", "y", "crv"), ec.keySet());
        assertEquals("P-256", ec.get("crv"));
        assertEquals("sig", ec.get("use"));
        assertEquals(1, ((List<?>) ec.get("x5c")).size());
        assertEquals("CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", ec.get("kid"));
    }

    @Test
    public void rsaKeyHasTheKeymanagerFieldSet() {
        Map<String, Object> rsa = key("RSA");
        assertEquals(Set.of("kid", "kty", "use", "exp", "x5c", "x5t#S256", "e", "n"), rsa.keySet());
        assertEquals("AQAB", rsa.get("e"));
    }

    @Test
    public void ed25519KeyIsAnOkpJwk() {
        Map<String, Object> okp = key("OKP");
        assertEquals(Set.of("kid", "kty", "use", "exp", "x5c", "x5t#S256", "x", "crv"), okp.keySet());
        assertEquals("Ed25519", okp.get("crv"));
        assertEquals("sig", okp.get("use"));
    }

    @Test
    public void expiredAndNotYetValidKeysAreNotPublished() {
        PublicKeyDescriptor current = jca.resolve(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_RSA")).descriptor();
        fake.descriptors.add(new PublicKeyDescriptor("expired", current.algorithm(), current.publicKey(), current.chain(),
                Instant.now().minus(Duration.ofDays(400)), Instant.now().minus(Duration.ofDays(1)), "vc-signing"));
        fake.descriptors.add(new PublicKeyDescriptor("future", current.algorithm(), current.publicKey(), current.chain(),
                Instant.now().plus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(400)), "vc-signing"));

        List<Object> kids = keys().stream().map(k -> k.get("kid")).toList();

        assertFalse(kids.contains("expired"));
        assertFalse(kids.contains("future"));
        assertEquals(3, kids.size());
    }

    @Test
    public void keysWithoutCertificateStillPublishTheirParameters() {
        PublicKeyDescriptor current = jca.resolve(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN")).descriptor();
        fake.descriptors.add(new PublicKeyDescriptor("bare", current.algorithm(), current.publicKey(), CertificateChain.EMPTY, null, null, "vc-signing"));

        Map<String, Object> bare = keys().stream().filter(k -> "bare".equals(k.get("kid"))).findFirst().orElseThrow();

        assertEquals(Set.of("kid", "kty", "use", "x", "y", "crv"), bare.keySet());
        assertNull(bare.get("exp"));
    }

    @Test
    public void aggregatesEveryProvider() {
        PublicKeyDescriptor current = jca.resolve(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_RSA")).descriptor();
        fake.descriptors.add(new PublicKeyDescriptor("other-provider", current.algorithm(), current.publicKey(), current.chain(),
                current.notBefore(), current.notAfter(), "vc-signing"));
        assertEquals(4, keys().size());
        assertNotNull(keys().stream().filter(k -> "other-provider".equals(k.get("kid"))).findFirst().orElse(null));
    }

    @Test
    public void noProvidersGiveAnEmptyKeySet() {
        ReflectionTestUtils.setField(jwksService, "keyPublisher", new KeyPublisher(List.of()));
        assertTrue(keys().isEmpty());
    }
}
