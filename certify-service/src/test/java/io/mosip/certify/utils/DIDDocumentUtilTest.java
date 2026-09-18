package io.mosip.certify.utils;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
class DIDDocumentUtilTest {


    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    private DIDDocumentUtil didDocumentUtil;
    private FakeKeyProvider fake;

    /** A "keymanager"-named provider fed with the test certificates; publicKeys(ref) returns every certificate of an alias. */
    static final class FakeKeyProvider implements io.mosip.certify.signing.KeyProvider {
        final Map<String, List<io.mosip.certify.signing.PublicKeyDescriptor>> byAlias = new java.util.HashMap<>();

        void add(String alias, String kid, String pem) {
            try {
                java.security.cert.X509Certificate c = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                add(alias, new io.mosip.certify.signing.PublicKeyDescriptor(kid, algorithmFor(c.getPublicKey()), c.getPublicKey(),
                        io.mosip.certify.signing.CertificateChain.of(c), c.getNotBefore().toInstant(), c.getNotAfter().toInstant(), "vc-signing"));
            } catch (java.security.cert.CertificateException e) {
                throw new IllegalArgumentException(e);
            }
        }

        void add(String alias, io.mosip.certify.signing.PublicKeyDescriptor descriptor) {
            byAlias.computeIfAbsent(alias, k -> new java.util.ArrayList<>()).add(descriptor);
        }

        static io.mosip.certify.signing.SignatureAlgorithm algorithmFor(java.security.PublicKey key) {
            if (key instanceof java.security.interfaces.RSAPublicKey) return io.mosip.certify.signing.SignatureAlgorithm.RS256;
            if (key instanceof java.security.interfaces.ECPublicKey ec) {
                com.nimbusds.jose.jwk.Curve curve = com.nimbusds.jose.jwk.Curve.forECParameterSpec(ec.getParams());
                return curve != null && "secp256k1".equals(curve.getName()) ? io.mosip.certify.signing.SignatureAlgorithm.ES256K : io.mosip.certify.signing.SignatureAlgorithm.ES256;
            }
            return io.mosip.certify.signing.SignatureAlgorithm.EdDSA;
        }

        public String id() { return "keymanager"; }

        public io.mosip.certify.signing.SigningKey resolve(io.mosip.certify.signing.KeyRef ref) {
            java.time.Instant now = java.time.Instant.now();
            return byAlias.getOrDefault(ref.alias(), List.of()).stream().filter(d -> d.isValidAt(now))
                    .max(java.util.Comparator.comparing(io.mosip.certify.signing.PublicKeyDescriptor::notAfter))
                    .map(d -> new io.mosip.certify.signing.SigningKey(ref, d, "fake"))
                    .orElseThrow(() -> new io.mosip.certify.signing.SigningException("No valid certificate for " + ref));
        }

        public List<io.mosip.certify.signing.PublicKeyDescriptor> publicKeys(io.mosip.certify.signing.KeyRef ref) {
            return byAlias.getOrDefault(ref.alias(), List.of());
        }

        public List<io.mosip.certify.signing.PublicKeyDescriptor> publicKeys(io.mosip.certify.signing.KeyFilter filter) {
            return byAlias.values().stream().flatMap(List::stream).toList();
        }

        public java.util.Set<io.mosip.certify.signing.SignatureAlgorithm> supportedAlgorithms() { return java.util.EnumSet.allOf(io.mosip.certify.signing.SignatureAlgorithm.class); }

        public byte[] signRaw(byte[] data, io.mosip.certify.signing.SigningKey key, io.mosip.certify.signing.SignatureAlgorithm algorithm) { throw new UnsupportedOperationException(); }
    }

    private AutoCloseable mocks;

    private static final String DID_URL = "did:example:123";

    private static final String ED25519_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";

    private static final String RSA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";

    private static final String SECP256K1_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIBnTCCAUSgAwIBAgIUEcbuA3qSx7zhVZzPgWxLrUp0c4owCgYIKoZIzj0EAwIw\nJjELMAkGA1UEBhMCSU4xFzAVBgNVBAMMDlRFU1RfU0VDUDI1NksxMB4XDTI2MDYw\nMTE1MzcwM1oXDTI5MDUzMTE1MzcwM1owJjELMAkGA1UEBhMCSU4xFzAVBgNVBAMM\nDlRFU1RfU0VDUDI1NksxMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEPKSAr1B+Tms1\nEfsHb/eF968n6vbmuY/5Ef+WDtijm6Bbu35kBAfZcXFT2OHGjRl+YPlHJVrTUbkg\nbe2X8/rcQ6NTMFEwHQYDVR0OBBYEFKsFre7gFjbnOjK18dy65IG71rDnMB8GA1Ud\nIwQYMBaAFKsFre7gFjbnOjK18dy65IG71rDnMA8GA1UdEwEB/wQFMAMBAf8wCgYI\nKoZIzj0EAwIDRwAwRAIgIDiBAHUEjlaGPyiYx5WzxeFpUUB5C/m2JeQwRppt+fkC\nIFU+j6AbYYT+plCUyAzfFZAXqVfOEw8zixmlNywW+7gf\n-----END CERTIFICATE-----\n";

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        fake = new FakeKeyProvider();
        didDocumentUtil = new DIDDocumentUtil(new io.mosip.certify.issuance.KeyProviderRegistry(List.of(fake)), credentialConfigRepository);
        LinkedHashMap<String, List<String>> signingMap = new LinkedHashMap<>();
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(JWSAlgorithm.EdDSA));
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(JWSAlgorithm.EdDSA));
        ReflectionTestUtils.setField(didDocumentUtil, "credentialSigningAlgValuesSupportedMap", signingMap);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testGenerateVerificationMethodEd25519Signature2020ViaReflection() {
        Map<String, Object> verificationMethod = ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.EdDSA,
                SignatureAlg.ED25519_SIGNATURE_SUITE_2020,
                ED25519_CERTIFICATE,
                DID_URL,
                "kid-2020"
        );

        assertNotNull(verificationMethod);
        assertEquals("Ed25519VerificationKey2020", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-2020", verificationMethod.get("id"));
        assertNotNull(verificationMethod.get("publicKeyMultibase"));
    }

    @Test
    void testGenerateVerificationMethodEd25519Signature2018ViaReflection() {
        Map<String, Object> verificationMethod = ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.EdDSA,
                SignatureAlg.ED25519_SIGNATURE_SUITE_2018,
                ED25519_CERTIFICATE,
                DID_URL,
                "kid-2018"
        );

        assertNotNull(verificationMethod);
        assertEquals("Ed25519VerificationKey2018", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-2018", verificationMethod.get("id"));
        assertNotNull(verificationMethod.get("publicKeyMultibase"));
    }

    @Test
    void testGenerateVerificationMethodRSASignature2018ViaReflection() {
        Map<String, Object> verificationMethod = ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.RS256,
                null,
                RSA_CERTIFICATE,
                DID_URL,
                "kid-rsa"
        );

        assertNotNull(verificationMethod);
        assertEquals("RsaVerificationKey2018", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-rsa", verificationMethod.get("id"));
        assertTrue(((String) verificationMethod.get("publicKeyPem")).startsWith("-----BEGIN PUBLIC KEY-----"));
    }

    @Test
    void testGenerateVerificationMethodUnsupportedAlgorithmViaReflection() {
        CertifyException exception = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(
                        didDocumentUtil,
                        "generateVerificationMethod",
                        "UnsupportedAlgorithm",
                        null,
                        ED25519_CERTIFICATE,
                        DID_URL,
                        "kid-invalid"
                )
        );

        assertEquals(ErrorConstants.UNSUPPORTED_ALGORITHM, exception.getErrorCode());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentAddsEd25519Context() {
        CredentialConfig config = new CredentialConfig();
        config.setKeyManagerAppId("ed-app");
        config.setKeyManagerRefId("ed-ref");
        config.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2020);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        fake.add("ed-app/ed-ref", "ed-kid", ED25519_CERTIFICATE);

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);
        List<String> contexts = (List<String>) didDocument.get("@context");

        assertNotNull(didDocument);
        assertTrue(contexts.contains("https://www.w3.org/ns/did/v1"));
        assertTrue(contexts.contains("https://w3id.org/security/suites/ed25519-2020/v1"));
    }


    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentDeduplicatesSecurityContext() {
        CredentialConfig edConfig = new CredentialConfig();
        edConfig.setKeyManagerAppId("ed-app");
        edConfig.setKeyManagerRefId("ed-ref");
        edConfig.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2018);

        CredentialConfig rsaConfig = new CredentialConfig();
        rsaConfig.setKeyManagerAppId("rsa-app");
        rsaConfig.setKeyManagerRefId("rsa-ref");
        rsaConfig.setSignatureAlgo(JWSAlgorithm.RS256);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(edConfig, rsaConfig));
        fake.add("ed-app/ed-ref", "ed-kid", ED25519_CERTIFICATE);
        fake.add("rsa-app/rsa-ref", "rsa-kid", RSA_CERTIFICATE);

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);
        List<String> contexts = (List<String>) didDocument.get("@context");

        assertNotNull(didDocument);
        assertTrue(contexts.contains("https://www.w3.org/ns/did/v1"));
        assertEquals(1, contexts.stream().filter("https://w3id.org/security/v1"::equals).count());
    }

    @Test
    void testGetCertificateDataResponseDtoSuccess() {
        io.mosip.certify.signing.PublicKeyDescriptor current = new io.mosip.certify.keyprovider.jca.JcaKeyProvider("x")
                .generate("k", io.mosip.certify.signing.SignatureAlgorithm.ES256, "CN=k", "vc-signing").descriptor();
        fake.add("app/ref", new io.mosip.certify.signing.PublicKeyDescriptor("kid-expired", current.algorithm(), current.publicKey(), current.chain(),
                java.time.Instant.now().minus(java.time.Duration.ofDays(400)), java.time.Instant.now().minus(java.time.Duration.ofDays(1)), "vc-signing"));
        fake.add("app/ref", new io.mosip.certify.signing.PublicKeyDescriptor("kid-valid", current.algorithm(), current.publicKey(), current.chain(),
                current.notBefore(), current.notAfter(), "vc-signing"));

        CertificateResponseDTO response = didDocumentUtil.getCertificateDataResponseDto("app", "ref");

        assertEquals("kid-valid", response.getKeyId());
        assertTrue(response.getCertificateData().startsWith("-----BEGIN CERTIFICATE-----"));
    }

    @Test
    void testGetCertificateDataResponseDtoNoCertificatesFound() {
        CertifyException e = assertThrows(CertifyException.class, () -> didDocumentUtil.getCertificateDataResponseDto("missing", "ref"));
        assertTrue(e.getMessage().contains("No valid certificates found"));
    }

    @Test
    void testGenerateVerificationMethodES256KDoesNotContainContext() {
        Map<String, Object> verificationMethod = ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.ES256K,
                null,
                SECP256K1_CERTIFICATE, // secp256k1 test certificate constant
                DID_URL,
                "kid-ec-k1"
        );
        assertNotNull(verificationMethod);
        assertEquals("EcdsaSecp256k1VerificationKey2019", verificationMethod.get("type"));
        assertFalse(verificationMethod.containsKey("@context"),
                "@context must not appear inside a verificationMethod per W3C DID Core 1.0");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentAddsSecp256k1ContextAtTopLevel() {
        CredentialConfig config = new CredentialConfig();
        config.setKeyManagerAppId("ec-app");
        config.setKeyManagerRefId("ec-ref");
        config.setSignatureAlgo(JWSAlgorithm.ES256K);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        fake.add("ec-app/ec-ref", "ec-kid", SECP256K1_CERTIFICATE);

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);
        List<String> contexts = (List<String>) didDocument.get("@context");
        List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>)
                didDocument.get("verificationMethod");

        assertTrue(contexts.contains("https://w3id.org/security/v1"),
                "Top-level @context must include the secp256k1 security context");
        assertFalse(verificationMethods.get(0).containsKey("@context"),
                "@context must not appear inside verificationMethod");
    }
}
