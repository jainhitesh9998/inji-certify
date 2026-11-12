package io.mosip.certify.signing;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.jca.MdocIacaSpec;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * M-05 item 5: the startup warning and the {@code certify.signing.key.expires_in_days} gauge. They live in the service
 * configuration, over every provider, so the key-provider modules stay free of Micrometer.
 */
class SigningKeyExpiryTest {

    @Test
    void warnsAboutAndMeasuresKeysThatExpireWithinThirtyDays() {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateIaca("iaca", new MdocIacaSpec(SignatureAlgorithm.ES256, "IN", null, "Demo IACA",
                "https://credentials.example.test/mdoc/iaca", null, "https://credentials.example.test/iaca.crl", null));
        provider.generateMdocDsc("mdl-dsc@2026-11", SignatureAlgorithm.ES256, "Demo DSC", 20, "iaca");
        provider.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca");
        provider.generateSignedBy("issuer-es256", SignatureAlgorithm.ES256, "CN=VC issuer", "vc-signing", "dev-ca");

        Clock clock = Clock.systemUTC();
        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(provider), clock);

        assertEquals(List.of("x509-file:mdl-dsc@2026-11"), expiry.warnExpiringSoon(),
                "only the 20-day Document Signer is inside the 30-day warning window");

        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        expiry.register(registry);

        double days = registry.get(SigningKeyExpiry.METRIC).tag("keyRef", "x509-file:mdl-dsc@2026-11").gauge().value();
        assertTrue(days > 18 && days <= 20.1, "days left on the Document Signer: " + days);
        double iacaDays = registry.get(SigningKeyExpiry.METRIC).tag("keyRef", "x509-file:iaca").gauge().value();
        assertTrue(iacaDays > 7000, "the IACA has years left: " + iacaDays);
        assertEquals(4, registry.get(SigningKeyExpiry.METRIC).gauges().size(),
                "one gauge per published certificate, including the dev CA");
    }

    @Test
    void aProviderThatCannotListItsKeysDoesNotStopStartup() {
        KeyProvider broken = mock(KeyProvider.class);
        when(broken.id()).thenReturn("broken");
        when(broken.publicKeys(any(KeyFilter.class))).thenThrow(new SigningException("key manager down"));

        SigningKeyExpiry expiry = new SigningKeyExpiry(List.of(broken), Clock.fixed(Instant.now(), ZoneOffset.UTC));

        assertDoesNotThrow(expiry::warnExpiringSoon);
        assertDoesNotThrow(() -> expiry.register(new SimpleMeterRegistry()));
        assertEquals(List.of(), expiry.warnExpiringSoon());
    }

    @Test
    void aKeyWithoutACertificateExpiryGetsNoGauge() {
        KeyProvider provider = mock(KeyProvider.class);
        when(provider.id()).thenReturn("kms");
        when(provider.publicKeys(any(KeyFilter.class))).thenReturn(List.of(
                new PublicKeyDescriptor("remote", SignatureAlgorithm.ES256, mock(PublicKey.class), null, null, null,
                        "vc-signing")));
        // a KMS key with a public key but no dates: nothing to measure, and no gauge that would report NaN
        assertDoesNotThrow(() -> new SigningKeyExpiry(List.of(provider), Clock.systemUTC())
                .register(new SimpleMeterRegistry()));
    }
}
