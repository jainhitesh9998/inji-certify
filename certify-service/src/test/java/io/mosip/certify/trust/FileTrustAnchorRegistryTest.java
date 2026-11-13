package io.mosip.certify.trust;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.jca.MdocIacaSpec;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.TrustAnchorRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link FileTrustAnchorRegistry}: what it loads, how it names anchors, what refuses startup, and CRL refresh (M-06/M-08). */
class FileTrustAnchorRegistryTest {

    static final Instant START = Instant.now().minus(1, ChronoUnit.HOURS);

    @TempDir
    Path dir;

    record Iaca(KeyPair keys, X509Certificate certificate) {}

    static Iaca iaca(String commonName, String crlUri) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();
        return new Iaca(keys, IsoMdocProfiles.iaca(keys).country("IN").commonName(commonName)
                .issuerAltUri("https://credentials.example.test").crlDistributionPoint(crlUri).notBefore(START).build());
    }

    static X509CRL crl(Iaca iaca, long number, BigInteger... revoked) {
        CrlBuilder builder = CrlBuilder.forIaca(iaca.certificate(), iaca.keys()).crlNumber(BigInteger.valueOf(number))
                .thisUpdate(Instant.now().minusSeconds(60));
        for (BigInteger serial : revoked) {
            builder.revoke(serial, Instant.now().minusSeconds(120));
        }
        return builder.build();
    }

    static PkiProperties properties(PkiProperties.AnchorSpec... specs) {
        return new PkiProperties(new PkiProperties.TrustAnchors(List.of(specs), Duration.ofMinutes(5), Duration.ofDays(7)), null);
    }

    Path write(String name, String text) throws Exception {
        return Files.writeString(dir.resolve(name), text);
    }

    @Test
    void anchorsAreNamedByTheConfiguredIdTheirPublishedCrlPathOrTheirKeyIdentifier() throws Exception {
        Iaca named = iaca("Configured Id IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/whatever.crl");
        Iaca published = iaca("Published IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/lorem-ipsum-demo-iaca.crl");
        Iaca elsewhere = iaca("Elsewhere IACA", "https://pki.example.test/crl/iaca.crl");
        Path der = Files.write(dir.resolve("elsewhere.der"), elsewhere.certificate().getEncoded());
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("operator-iaca", write("named.pem", Pem.writeCertificate(named.certificate())), null),
                new PkiProperties.AnchorSpec(null, write("published.pem", Pem.writeCertificate(published.certificate())), null),
                new PkiProperties.AnchorSpec(" ", der, null)), List.of(), null, Clock.systemUTC());

        List<TrustAnchorRegistry.Anchor> anchors = registry.entries(TrustAnchorRegistry.MDOC_IACA);
        assertEquals(List.of("operator-iaca", "lorem-ipsum-demo-iaca",
                CertificateLinks.subjectKeyIdentifierHex(elsewhere.certificate()).orElseThrow()),
                anchors.stream().map(TrustAnchorRegistry.Anchor::id).toList());
        assertEquals(elsewhere.certificate(), anchors.get(2).certificate(), "DER is read as well as PEM");
        assertEquals(List.of(), registry.entries("sd-jwt"), "nothing for another purpose");
        assertTrue(registry.crl("operator-iaca").isEmpty());
    }

    @Test
    void theX509FileIacasJoinTheConfiguredOnesAndAConfiguredEntryWins() throws Exception {
        Iaca configured = iaca("Configured IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/configured.crl");
        Iaca provider = iaca("Provider IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/provider.crl");
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("chosen", write("configured.pem", Pem.writeCertificate(configured.certificate())), null)),
                List.of(configured.certificate(), provider.certificate()), null, Clock.systemUTC());
        assertEquals(List.of("chosen", "provider"), registry.entries(TrustAnchorRegistry.MDOC_IACA).stream()
                .map(TrustAnchorRegistry.Anchor::id).toList());
    }

    @Test
    void anythingAVerifierCouldNotTrustRefusesStartup() throws Exception {
        Iaca good = iaca("Good IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/good.crl");
        Iaca other = iaca("Other IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/other.crl");
        // a CA that is no Annex B IACA (the P3-08 dev CA)
        JcaKeyProvider jca = new JcaKeyProvider("jca");
        X509Certificate devCa = jca.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca").chain().leaf().orElseThrow();
        IllegalStateException notIaca = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec(null, write("dev-ca.pem", Pem.writeCertificate(devCa)), null)), List.of(), null, Clock.systemUTC()));
        assertTrue(notIaca.getMessage().contains("IACA_CRL_DP_MISSING"), notIaca.getMessage());

        IllegalStateException two = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec(null, write("two.pem", Pem.writeCertificates(List.of(good.certificate(), other.certificate()))), null)),
                List.of(), null, Clock.systemUTC()));
        assertTrue(two.getMessage().contains("exactly the IACA certificate"), two.getMessage());

        IllegalStateException foreignCrl = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("good", write("good.pem", Pem.writeCertificate(good.certificate())),
                        write("other.crl", Pem.writeCrl(crl(other, 1))))), List.of(), null, Clock.systemUTC()));
        assertTrue(foreignCrl.getMessage().contains("CRL_ISSUER_MISMATCH") || foreignCrl.getMessage().contains("CRL_SIGNATURE_INVALID"),
                foreignCrl.getMessage());

        IllegalStateException duplicate = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("same", write("good2.pem", Pem.writeCertificate(good.certificate())), null),
                new PkiProperties.AnchorSpec("same", write("other2.pem", Pem.writeCertificate(other.certificate())), null)),
                List.of(), null, Clock.systemUTC()));
        assertTrue(duplicate.getMessage().contains("already used"), duplicate.getMessage());

        assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec(null, dir.resolve("missing.pem"), null)), List.of(), null, Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> new PkiProperties.AnchorSpec("../escape", dir.resolve("x.pem"), null));
        assertThrows(IllegalArgumentException.class, () -> new PkiProperties.AnchorSpec("Upper", dir.resolve("x.pem"), null));
    }

    @Test
    void aChangedCrlFileReplacesTheCurrentOneOnlyWhenItValidates() throws Exception {
        Iaca iaca = iaca("Refreshed IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/refreshed.crl");
        Iaca other = iaca("Other IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/other.crl");
        Path crlFile = Files.write(dir.resolve("refreshed.crl"), crl(iaca, 1).getEncoded()); // DER
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(new PkiProperties.AnchorSpec(null,
                write("refreshed.pem", Pem.writeCertificate(iaca.certificate())), crlFile)), List.of(), null, Clock.systemUTC());
        assertEquals(BigInteger.ONE, FileTrustAnchorRegistry.crlNumber(registry.crl("refreshed").orElseThrow()));

        BigInteger serial = BigInteger.valueOf(0x1234_5678_9abcL);
        Files.writeString(crlFile, Pem.writeCrl(crl(iaca, 2, serial))); // PEM this time
        Files.setLastModifiedTime(crlFile, FileTime.from(Instant.now().plusSeconds(5)));
        registry.refresh();
        X509CRL reloaded = registry.crl("refreshed").orElseThrow();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(reloaded));
        assertTrue(reloaded.getRevokedCertificate(serial) != null);

        Files.writeString(crlFile, Pem.writeCrl(crl(other, 3))); // signed by another IACA: refused, the previous CRL stays
        Files.setLastModifiedTime(crlFile, FileTime.from(Instant.now().plusSeconds(10)));
        registry.refresh();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(registry.crl("refreshed").orElseThrow()));
        Files.writeString(crlFile, "not a CRL");
        registry.refresh();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(registry.crl("refreshed").orElseThrow()));
    }

    @Test
    void devModeIssuesTheCrlOfAnIacaWhoseKeyItHolds() throws Exception {
        JcaKeyProvider devMode = new JcaKeyProvider("x509-file");
        X509Certificate iaca = devMode.generateIaca("iaca", new MdocIacaSpec(SignatureAlgorithm.ES256, "IN", null,
                "Lorem Ipsum Demo IACA", "https://credentials.example.test", null,
                "https://credentials.example.test/v1/certify/mdoc/iaca/demo-iaca.crl", null)).chain().leaf().orElseThrow();
        Instant before = Instant.now();
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(), List.of(iaca), devMode::issueEmptyCrl, Clock.systemUTC());

        X509CRL crl = registry.crl("demo-iaca").orElseThrow();
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, iaca, Instant.now()));
        assertEquals(Duration.ofDays(7), Duration.between(crl.getThisUpdate().toInstant(), crl.getNextUpdate().toInstant()));
        assertTrue(FileTrustAnchorRegistry.crlNumber(crl).longValue() >= before.getEpochSecond(),
                "the issuing second: the number increases across restarts");
        assertTrue(crl.getRevokedCertificates() == null, "empty");

        // an IACA whose key is not held (production: the IACA key stays offline, D3) has no generated CRL
        Iaca offline = iaca("Offline IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/offline.crl");
        FileTrustAnchorRegistry production = new FileTrustAnchorRegistry(properties(), List.of(offline.certificate()),
                devMode::issueEmptyCrl, Clock.systemUTC());
        assertFalse(production.crl("offline").isPresent());
        assertEquals(Optional.empty(), new FileTrustAnchorRegistry(properties(), List.of(), null, Clock.systemUTC()).crl("demo-iaca"));
    }

    @Test
    void aDevCrlIsReissuedPastHalfItsValidityWithALargerNumber() throws Exception {
        // the IACA started 30 days ago, so the registry's clock can run in the past where CrlBuilder accepts thisUpdate
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();
        X509Certificate iaca = IsoMdocProfiles.iaca(keys).country("IN").commonName("Past IACA").issuerAltUri("https://credentials.example.test")
                .crlDistributionPoint("https://credentials.example.test/v1/certify/mdoc/iaca/past.crl")
                .notBefore(Instant.now().minus(30, ChronoUnit.DAYS)).build();
        FileTrustAnchorRegistry.DevCrlIssuer issuer = (certificate, number, thisUpdate, nextUpdate) -> Optional.of(
                CrlBuilder.forIaca(certificate, keys).crlNumber(number).thisUpdate(thisUpdate).nextUpdate(nextUpdate).build());
        MutableClock clock = new MutableClock(Instant.now().minus(7, ChronoUnit.DAYS));
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(), List.of(iaca), issuer, clock);
        X509CRL first = registry.crl("past").orElseThrow();
        BigInteger firstNumber = FileTrustAnchorRegistry.crlNumber(first);

        clock.set(first.getThisUpdate().toInstant().plus(Duration.ofDays(3)));
        registry.refresh();
        assertEquals(firstNumber, FileTrustAnchorRegistry.crlNumber(registry.crl("past").orElseThrow()), "not yet half way");
        clock.set(first.getThisUpdate().toInstant().plus(Duration.ofDays(3).plusHours(12)));
        registry.refresh();
        X509CRL second = registry.crl("past").orElseThrow();
        assertTrue(FileTrustAnchorRegistry.crlNumber(second).compareTo(firstNumber) > 0, "a re-issued CRL has a larger number");
        assertEquals(clock.instant().truncatedTo(ChronoUnit.SECONDS), second.getThisUpdate().toInstant());
        assertEquals(List.of(), AnnexBValidator.validateCrl(second, iaca, clock.instant()));
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant instant) {
            now = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
