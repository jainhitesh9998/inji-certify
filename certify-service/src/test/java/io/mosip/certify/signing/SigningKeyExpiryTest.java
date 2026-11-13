package io.mosip.certify.signing;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.jca.MdocIacaSpec;
import io.mosip.certify.pki.IsoMdocProfiles;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * M-05 expiry visibility: the warning and the {@code certify.signing.key.expires_in_days} gauge live in the service
 * configuration, over every provider, so the key-provider modules stay free of Micrometer. Review findings: nothing is
 * read while beans are created (keymanager provisions its keys later), gauges hold their own state and follow keys
 * that appear and disappear, and rotated-out certificates are not reported.
 */
class SigningKeyExpiryTest {

    private static final String CRL = "https://credentials.example.test/iaca.crl";

    @Test
    void creatingTheBeanReadsNoProviderTheReadyEventDoes() {
        KeyProvider provider = mock(KeyProvider.class);
        @SuppressWarnings("unchecked") ObjectProvider<MeterRegistry> registries = mock(ObjectProvider.class);
        when(registries.getIfAvailable()).thenReturn(new SimpleMeterRegistry());

        SigningKeyExpiry expiry = new SigningBeans().signingKeyExpiry(List.of(provider), registries,
                new SigningKeyExpiryProperties(30, Duration.ZERO));

        verifyNoInteractions(provider);
        when(provider.id()).thenReturn("kms");
        when(provider.keyRefs()).thenReturn(List.of());
        when(provider.publicKeys(any(KeyFilter.class))).thenReturn(List.of());
        expiry.onApplicationEvent(mock(ApplicationReadyEvent.class));
        org.mockito.Mockito.verify(provider).publicKeys(any(KeyFilter.class));
        expiry.close();
    }

    @Test
    void warnsAboutAndMeasuresTheCurrentKeyOfEveryAlias() {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateIaca("iaca", new MdocIacaSpec(SignatureAlgorithm.ES256, "IN", null, "Demo IACA",
                "https://credentials.example.test/mdoc/iaca", null, CRL, null));
        provider.generateMdocDsc("mdl-dsc@2026-11", SignatureAlgorithm.ES256, "Demo DSC", 20, "iaca");
        provider.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca");
        provider.generateSignedBy("issuer-es256", SignatureAlgorithm.ES256, "CN=VC issuer", "vc-signing", "dev-ca");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS);

        assertEquals(List.of("x509-file:mdl-dsc@2026-11"), expiry.reconcile(),
                "only the 20-day Document Signer is inside the 30-day warning window");

        double days = gauge(registry, "x509-file:mdl-dsc@2026-11").value();
        assertTrue(days > 18 && days <= 20.1, "days left on the Document Signer: " + days);
        assertTrue(gauge(registry, "x509-file:iaca").value() > 7000, "the IACA has years left");
        assertEquals(Set.of("x509-file:iaca", "x509-file:mdl-dsc@2026-11", "x509-file:dev-ca", "x509-file:issuer-es256"),
                expiry.gauged(), "one gauge per alias, tagged with the reference that pins its current key");
        for (String keyRef : expiry.gauged()) {
            assertEquals("x509-file", KeyRef.parse(keyRef).provider(), "every tag parses as a KeyRef: " + keyRef);
        }
    }

    /** Keymanager keeps every rotated certificate of an alias: only the current one is reported, tagged APP/REF@kid. */
    @Test
    void expiredRotatedCertificatesAreNotReportedAndKeymanagerTagsParseAsKeyRefs() throws Exception {
        KeyRef alias = KeyRef.parse("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN");
        PublicKeyDescriptor old = descriptor("OLDKID", Instant.now().minus(800, ChronoUnit.DAYS),
                Instant.now().minus(70, ChronoUnit.DAYS));
        PublicKeyDescriptor current = descriptor("NEWKID", Instant.now().minus(70, ChronoUnit.DAYS),
                Instant.now().plus(10, ChronoUnit.DAYS));
        KeyProvider keymanager = mock(KeyProvider.class);
        when(keymanager.id()).thenReturn("keymanager");
        when(keymanager.keyRefs()).thenReturn(List.of(alias));
        when(keymanager.publicKeys(alias)).thenReturn(List.of(old, current));
        when(keymanager.resolve(alias)).thenReturn(new SigningKey(alias, current, "handle"));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        List<String> expiring = new SigningKeyExpiry(List.of(keymanager), registry, SigningKeyExpiryProperties.DEFAULTS)
                .reconcile();

        String tag = "keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN@NEWKID";
        assertEquals(List.of(tag), expiring, "the current key is about to expire; the expired rotated one is not news");
        assertEquals(new KeyRef("keymanager", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "NEWKID"), KeyRef.parse(tag));
        assertEquals(1, registry.find(SigningKeyExpiry.METRIC).gauges().size(), "no gauge for the rotated-out kid");
        assertTrue(gauge(registry, tag).value() > 9);
    }

    @Test
    void anAliasLeftWithoutAValidKeyReportsItsLastOneAsExpired() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeys).notBefore(Instant.now().minus(900, ChronoUnit.DAYS))
                .country("IN").commonName("Demo IACA").issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(CRL).build();
        KeyPair dscKeys = ecKeyPair();
        X509Certificate dsc = IsoMdocProfiles.ds(dscKeys, iaca, iacaKeys).commonName("Demo DSC")
                .notBefore(Instant.now().minus(500, ChronoUnit.DAYS)).validity(Duration.ofDays(400)).build();
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.add("mdl-dsc", dscKeys.getPrivate(), CertificateChain.of(dsc, iaca), SignatureAlgorithm.ES256, "mdoc-dsc");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        assertEquals(List.of("x509-file:mdl-dsc"),
                new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS).reconcile());
        assertTrue(gauge(registry, "x509-file:mdl-dsc").value() < -99, "expired 100 days ago, and visible as such");
    }

    /** Round 3: a rotation gap (expired version + a successor not valid yet) is an expired key, not +460 days. */
    @Test
    void aRotationGapReportsTheExpiredVersionNotTheFutureOne() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys);
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        addDsc(provider, "mdl-dsc@2025-04", iaca, iacaKeys, Instant.now().minus(410, ChronoUnit.DAYS), 400);
        addDsc(provider, "mdl-dsc@2026-12", iaca, iacaKeys, Instant.now().plus(5, ChronoUnit.DAYS), 457);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        try (CapturedLog log = new CapturedLog()) {
            assertEquals(List.of("x509-file:mdl-dsc@2025-04"),
                    new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS).reconcile());
            double days = gauge(registry, "x509-file:mdl-dsc@2025-04").value();
            assertTrue(days < -9 && days > -11, "expired ten days ago: " + days);
            assertEquals(1, registry.find(SigningKeyExpiry.METRIC).gauges().size(), "no gauge for the future version");
            assertTrue(log.messages().stream().anyMatch(m -> m.contains("x509-file:mdl-dsc@2025-04 expired at")
                    && m.contains("next version valid from")), log.messages().toString());
        }
    }

    @Test
    void anAliasWhoseOnlyVersionsAreInTheFutureReportsZeroAndWarnsAtEveryReconciliation() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys);
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        Instant first = Instant.now().plus(3, ChronoUnit.DAYS);
        addDsc(provider, "mdl-dsc@2026-12", iaca, iacaKeys, first, 300);
        addDsc(provider, "mdl-dsc@2027-03", iaca, iacaKeys, first.plus(90, ChronoUnit.DAYS), 300);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS);

        try (CapturedLog log = new CapturedLog()) {
            assertEquals(List.of("x509-file:mdl-dsc@2026-12"), expiry.reconcile());
            assertEquals(0.0, gauge(registry, "x509-file:mdl-dsc@2026-12").value(), "no key valid now: 0 days");
            assertEquals(Set.of("x509-file:mdl-dsc@2026-12"), expiry.gauged(), "the earliest future version only");
            expiry.reconcile();
            List<String> warnings = log.messages().stream()
                    .filter(m -> m.contains("alias x509-file:mdl-dsc has no key valid now; next version valid from "
                            + first.truncatedTo(ChronoUnit.SECONDS)))
                    .toList();
            assertEquals(2, warnings.size(), "once per reconciliation: " + log.messages());
        }
    }

    @Test
    void aSingleDocumentSignerThatIsNotValidYetReportsZero() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys);
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        addDsc(provider, "mdl-dsc", iaca, iacaKeys, Instant.now().plus(10, ChronoUnit.DAYS), 300);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        try (CapturedLog log = new CapturedLog()) {
            assertEquals(List.of("x509-file:mdl-dsc"),
                    new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS).reconcile());
            assertEquals(0.0, gauge(registry, "x509-file:mdl-dsc").value(), "not +310 days: it cannot sign yet");
            assertTrue(log.messages().stream().anyMatch(m -> m.contains("has no key valid now")), log.messages().toString());
        }
    }

    @Test
    void gaugesKeepTheirValueWhenAProviderReplacesItsDescriptorsAndFollowNewAndGoneKeys() {
        Instant now = Instant.now();
        MutableProvider provider = new MutableProvider("keymanager");
        provider.put("CERTIFY_SERVICE", now.minus(1, ChronoUnit.DAYS), now.plus(100, ChronoUnit.DAYS));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS);

        expiry.reconcile();
        String service = "keymanager:CERTIFY_SERVICE@CERTIFY_SERVICE-kid";
        // a cache refresh: every read builds new descriptor objects, and nobody else holds the old ones
        for (int i = 0; i < 3; i++) {
            provider.publicKeys(KeyFilter.ALL);
            System.gc();
        }
        double value = gauge(registry, service).value();
        assertFalse(Double.isNaN(value), "the gauge does not depend on a descriptor the provider dropped");
        assertTrue(value > 99 && value <= 100.1, "days left: " + value);

        provider.put("CERTIFY_VC_SIGN_RSA", now.minus(1, ChronoUnit.DAYS), now.plus(5, ChronoUnit.DAYS));
        assertEquals(List.of("keymanager:CERTIFY_VC_SIGN_RSA@CERTIFY_VC_SIGN_RSA-kid"), expiry.reconcile(),
                "a key that appears later is reported at the next reconciliation");
        assertNotNull(registry.find(SigningKeyExpiry.METRIC)
                .tag("keyRef", "keymanager:CERTIFY_VC_SIGN_RSA@CERTIFY_VC_SIGN_RSA-kid").gauge());

        provider.remove("CERTIFY_VC_SIGN_RSA");
        expiry.reconcile();
        assertNull(registry.find(SigningKeyExpiry.METRIC)
                .tag("keyRef", "keymanager:CERTIFY_VC_SIGN_RSA@CERTIFY_VC_SIGN_RSA-kid").gauge(), "a gone key loses its gauge");
        assertEquals(Set.of(service), expiry.gauged());

        provider.failing.set(true);
        assertDoesNotThrow(expiry::reconcile);
        assertEquals(Set.of(service), expiry.gauged(), "a provider that does not answer keeps its previous gauges");
    }

    @Test
    void aProviderUnavailableAtStartupIsPickedUpByThePeriodicReconciliation() throws Exception {
        Instant now = Instant.now();
        MutableProvider provider = new MutableProvider("vault");
        provider.failing.set(true);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(provider), registry,
                new SigningKeyExpiryProperties(30, Duration.ofMillis(50)));

        assertDoesNotThrow(() -> expiry.onApplicationEvent(mock(ApplicationReadyEvent.class)));
        assertEquals(Set.of(), expiry.gauged());

        provider.put("issuer", now.minus(1, ChronoUnit.DAYS), now.plus(200, ChronoUnit.DAYS));
        provider.failing.set(false);
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (expiry.gauged().isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        expiry.close();
        assertEquals(Set.of("vault:issuer@issuer-kid"), expiry.gauged());
        assertTrue(gauge(registry, "vault:issuer@issuer-kid").value() > 199);
    }

    @Test
    void aKeyWithoutACertificateExpiryGetsNoGauge() {
        KeyProvider provider = mock(KeyProvider.class);
        when(provider.id()).thenReturn("kms");
        when(provider.keyRefs()).thenReturn(List.of());
        when(provider.publicKeys(any(KeyFilter.class))).thenReturn(List.of(
                new PublicKeyDescriptor("remote", SignatureAlgorithm.ES256, mock(PublicKey.class), null, null, null,
                        "vc-signing")));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        // a KMS key with a public key but no dates: nothing to measure, and no gauge that would report NaN
        assertDoesNotThrow(() -> new SigningKeyExpiry(List.of(provider), registry, SigningKeyExpiryProperties.DEFAULTS)
                .reconcile());
        assertTrue(registry.find(SigningKeyExpiry.METRIC).gauges().isEmpty());
    }

    private static X509Certificate iaca(KeyPair iacaKeys) throws Exception {
        return IsoMdocProfiles.iaca(iacaKeys).notBefore(Instant.now().minus(900, ChronoUnit.DAYS))
                .country("IN").commonName("Demo IACA").issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .crlDistributionPoint(CRL).build();
    }

    private static void addDsc(JcaKeyProvider provider, String alias, X509Certificate iaca, KeyPair iacaKeys,
                               Instant notBefore, int days) throws Exception {
        KeyPair keys = ecKeyPair();
        X509Certificate dsc = IsoMdocProfiles.ds(keys, iaca, iacaKeys).commonName("Demo DSC").notBefore(notBefore)
                .validity(Duration.ofDays(days)).build();
        provider.add(alias, keys.getPrivate(), CertificateChain.of(dsc, iaca), SignatureAlgorithm.ES256, "mdoc-dsc");
    }

    /** The WARNs {@link SigningKeyExpiry} logs while open. */
    private static final class CapturedLog implements AutoCloseable {
        private final ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(SigningKeyExpiry.class);
        private final ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();

        CapturedLog() {
            appender.start();
            logger.addAppender(appender);
        }

        List<String> messages() {
            return appender.list.stream().map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).toList();
        }

        @Override
        public void close() {
            logger.detachAppender(appender);
        }
    }

    private static Gauge gauge(MeterRegistry registry, String keyRef) {
        return registry.get(SigningKeyExpiry.METRIC).tag("keyRef", keyRef).gauge();
    }

    private static PublicKeyDescriptor descriptor(String kid, Instant notBefore, Instant notAfter) throws Exception {
        return new PublicKeyDescriptor(kid, SignatureAlgorithm.ES256, ecKeyPair().getPublic(), null, notBefore, notAfter,
                "vc-signing");
    }

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** A provider shaped like keymanager: kid is not the alias, and every read builds fresh descriptors. */
    private static final class MutableProvider implements KeyProvider {
        private final String id;
        private final Map<String, Instant[]> keys = new ConcurrentHashMap<>();
        private final PublicKey publicKey;
        final AtomicBoolean failing = new AtomicBoolean();

        MutableProvider(String id) {
            this.id = id;
            try {
                this.publicKey = ecKeyPair().getPublic();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        void put(String alias, Instant notBefore, Instant notAfter) {
            keys.put(alias, new Instant[]{notBefore, notAfter});
        }

        void remove(String alias) {
            keys.remove(alias);
        }

        private PublicKeyDescriptor fresh(String alias) {
            Instant[] dates = keys.get(alias);
            return new PublicKeyDescriptor(alias + "-kid", SignatureAlgorithm.ES256, publicKey, null, dates[0], dates[1],
                    "vc-signing");
        }

        private void check() {
            if (failing.get()) {
                throw new SigningException(id + " is down");
            }
        }

        @Override public String id() { return id; }

        @Override public List<KeyRef> keyRefs() {
            check();
            return keys.keySet().stream().sorted().map(alias -> new KeyRef(id, alias)).toList();
        }

        @Override public SigningKey resolve(KeyRef ref) {
            check();
            return new SigningKey(ref, fresh(ref.alias()), "handle");
        }

        @Override public List<PublicKeyDescriptor> publicKeys(KeyRef ref) {
            check();
            return keys.containsKey(ref.alias()) ? List.of(fresh(ref.alias())) : List.of();
        }

        @Override public List<PublicKeyDescriptor> publicKeys(KeyFilter filter) {
            check();
            List<PublicKeyDescriptor> out = new ArrayList<>();
            keys.keySet().forEach(alias -> out.add(fresh(alias)));
            return out;
        }

        @Override public Set<SignatureAlgorithm> supportedAlgorithms() { return Set.of(SignatureAlgorithm.ES256); }

        @Override public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
            throw new UnsupportedOperationException();
        }
    }
}
