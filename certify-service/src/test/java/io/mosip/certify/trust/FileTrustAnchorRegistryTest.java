package io.mosip.certify.trust;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.certify.format.mdoc.MdocDscPolicy;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.jca.MdocIacaSpec;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.FormatException;
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
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link FileTrustAnchorRegistry}: what it loads, how it names anchors, what refuses startup, and CRL refresh (M-06/M-08). */
class FileTrustAnchorRegistryTest {

    static final Instant START = Instant.now().minus(1, ChronoUnit.HOURS);

    @TempDir
    Path dir;

    record Iaca(KeyPair keys, X509Certificate certificate) {}

    static Iaca iaca(String commonName, String crlUri) throws Exception {
        return iaca(commonName, crlUri, START);
    }

    static Iaca iaca(String commonName, String crlUri, Instant notBefore) throws Exception {
        KeyPair keys = p256();
        return new Iaca(keys, IsoMdocProfiles.iaca(keys).country("IN").commonName(commonName)
                .issuerAltUri("https://credentials.example.test").crlDistributionPoint(crlUri).notBefore(notBefore).build());
    }

    static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** A CRL with chosen dates, so a test can hold a stale or an older list (the IACA must be valid from before thisUpdate). */
    static X509CRL crl(Iaca iaca, long number, Instant thisUpdate, Instant nextUpdate, BigInteger... revoked) {
        CrlBuilder builder = CrlBuilder.forIaca(iaca.certificate(), iaca.keys()).crlNumber(BigInteger.valueOf(number))
                .thisUpdate(thisUpdate).nextUpdate(nextUpdate);
        for (BigInteger serial : revoked) {
            builder.revoke(serial, thisUpdate.minusSeconds(60));
        }
        return builder.build();
    }

    static PkiProperties properties(Duration staleCrlGrace, PkiProperties.AnchorSpec... specs) {
        return new PkiProperties(new PkiProperties.TrustAnchors(List.of(specs), Duration.ofMinutes(5), Duration.ofDays(7)), null,
                staleCrlGrace);
    }

    /** The registry's log while {@code action} runs. */
    static <T> T logged(List<ILoggingEvent> events, Supplier<T> action) {
        Logger logger = (Logger) org.slf4j.LoggerFactory.getLogger(FileTrustAnchorRegistry.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            return action.get();
        } finally {
            logger.detachAppender(appender);
            events.addAll(appender.list);
        }
    }

    static boolean has(List<ILoggingEvent> events, Level level, String text) {
        return events.stream().anyMatch(event -> event.getLevel() == level && event.getFormattedMessage().contains(text));
    }

    /** Sets the file's modification time ahead, as a later write would, so the refresh sees a change. */
    static void touch(Path file, int seconds) throws Exception {
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(seconds)));
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
        Iaca named = iaca("Configured Id IACA", "https://pki.example.test/crl/configured.crl");
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
        Iaca configured = iaca("Configured IACA", "https://pki.example.test/crl/configured.crl");
        Iaca provider = iaca("Provider IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/provider.crl");
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("chosen", write("configured.pem", Pem.writeCertificate(configured.certificate())), null)),
                List.of(configured.certificate(), provider.certificate()), null, Clock.systemUTC());
        assertEquals(List.of("chosen", "provider"), registry.entries(TrustAnchorRegistry.MDOC_IACA).stream()
                .map(TrustAnchorRegistry.Anchor::id).toList());
    }

    /**
     * Review round 1, item 4: an IACA whose CRL distribution point is {@code …/mdoc/iaca/<x>.crl} is served at
     * {@code /mdoc/iaca/<id>.crl}, so {@code <x>} must be a valid id and the anchor's id, or verifiers get a 404 at the
     * URL every DSC under it copies; startup is refused, naming both.
     */
    @Test
    void anIdThatIsNotTheOneTheCrlDistributionPointNamesRefusesStartup() throws Exception {
        Iaca iaca = iaca("Mismatched IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/lorem-iaca.crl");
        Path pem = write("mismatched.pem", Pem.writeCertificate(iaca.certificate()));
        IllegalStateException mismatch = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(
                properties(new PkiProperties.AnchorSpec("operator-iaca", pem, null)), List.of(), null, Clock.systemUTC()));
        assertTrue(mismatch.getMessage().contains("'lorem-iaca'") && mismatch.getMessage().contains("'operator-iaca'")
                && mismatch.getMessage().contains("404"), mismatch.getMessage());
        // the same id, or none, starts
        assertEquals("lorem-iaca", new FileTrustAnchorRegistry(properties(new PkiProperties.AnchorSpec("lorem-iaca", pem, null)),
                List.of(), null, Clock.systemUTC()).entries(TrustAnchorRegistry.MDOC_IACA).get(0).id());

        for (String bad : List.of("Lorem_IACA", "-lorem", "lorem%20iaca")) {
            Iaca invalid = iaca("Invalid Id IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/" + bad + ".crl");
            IllegalStateException configured = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(
                    properties(new PkiProperties.AnchorSpec(null, write("invalid.pem", Pem.writeCertificate(invalid.certificate())), null)),
                    List.of(), null, Clock.systemUTC()), bad);
            assertTrue(configured.getMessage().contains("is not a valid anchor id") && configured.getMessage().contains(PkiProperties.ID.pattern())
                    && configured.getMessage().contains("--crl-uri"), configured.getMessage());
            // an x509-file IACA too: its CRL distribution point is certify.keyprovider.x509-file.iaca.crl-uri
            IllegalStateException provider = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(
                    properties(), List.of(invalid.certificate()), null, Clock.systemUTC()), bad);
            assertTrue(provider.getMessage().contains("the x509-file IACA") && provider.getMessage().contains("is not a valid anchor id"),
                    provider.getMessage());
        }
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

        Iaca first = iaca("First IACA", "https://pki.example.test/crl/first.crl");
        Iaca second = iaca("Second IACA", "https://pki.example.test/crl/second.crl");
        IllegalStateException duplicate = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(properties(
                new PkiProperties.AnchorSpec("same", write("first.pem", Pem.writeCertificate(first.certificate())), null),
                new PkiProperties.AnchorSpec("same", write("second.pem", Pem.writeCertificate(second.certificate())), null)),
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
        touch(crlFile, 5);
        registry.refresh();
        X509CRL reloaded = registry.crl("refreshed").orElseThrow();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(reloaded));
        assertTrue(reloaded.getRevokedCertificate(serial) != null);

        Files.writeString(crlFile, Pem.writeCrl(crl(other, 3))); // signed by another IACA: refused, the previous CRL stays
        touch(crlFile, 10);
        registry.refresh();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(registry.crl("refreshed").orElseThrow()));
        Files.writeString(crlFile, "not a CRL");
        registry.refresh();
        assertEquals(BigInteger.TWO, FileTrustAnchorRegistry.crlNumber(registry.crl("refreshed").orElseThrow()));
    }

    /**
     * Review round 1, item 1 (reproduced): a replacement that goes back (a lower cRLNumber, the same number with other
     * content, an earlier thisUpdate) would un-revoke a Document Signer. It is refused with an ERROR and the current CRL
     * stays; the same CRL written again changes nothing; a renewal that moves forward is taken.
     */
    @Test
    void aReplacementCrlThatGoesBackIsRefusedAndOneThatMovesForwardIsTaken() throws Exception {
        Instant since = Instant.now().minus(30, ChronoUnit.DAYS);
        Iaca iaca = iaca("Rollback IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/rollback.crl", since);
        BigInteger revoked = BigInteger.valueOf(0x5eed_0001L);
        Instant day = Instant.now().minus(2, ChronoUnit.DAYS);
        X509CRL older = crl(iaca, 4, day.minus(1, ChronoUnit.DAYS), day.plus(30, ChronoUnit.DAYS)); // before the revocation
        X509CRL current = crl(iaca, 5, day, day.plus(30, ChronoUnit.DAYS), revoked);
        Path crlFile = Files.write(dir.resolve("rollback.crl"), current.getEncoded());
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(new PkiProperties.AnchorSpec(null,
                write("rollback.pem", Pem.writeCertificate(iaca.certificate())), crlFile)), List.of(), null, Clock.systemUTC());
        X509CRL loaded = registry.crl("rollback").orElseThrow();
        assertTrue(loaded.getRevokedCertificate(revoked) != null);

        List<ILoggingEvent> events = new java.util.ArrayList<>();
        Files.write(crlFile, older.getEncoded()); // a lower cRLNumber: the old list, without the revocation
        touch(crlFile, 5);
        logged(events, () -> { registry.refresh(); return null; });
        assertSame(loaded, registry.crl("rollback").orElseThrow(), "the DSC stays revoked");
        assertTrue(has(events, Level.ERROR, "cRLNumber 4 is lower than the current 5"), events.toString());

        events.clear();
        Files.write(crlFile, crl(iaca, 5, day, day.plus(30, ChronoUnit.DAYS)).getEncoded()); // number 5 again, without the entry
        touch(crlFile, 10);
        logged(events, () -> { registry.refresh(); return null; });
        assertSame(loaded, registry.crl("rollback").orElseThrow());
        assertTrue(has(events, Level.ERROR, "is the current one's, but its content differs"), events.toString());

        events.clear();
        Files.write(crlFile, crl(iaca, 6, day.minus(1, ChronoUnit.HOURS), day.plus(30, ChronoUnit.DAYS)).getEncoded());
        touch(crlFile, 15);
        logged(events, () -> { registry.refresh(); return null; });
        assertSame(loaded, registry.crl("rollback").orElseThrow(), "a larger number with an earlier thisUpdate is refused too");
        assertTrue(has(events, Level.ERROR, "is earlier than the current"), events.toString());

        events.clear();
        Files.write(crlFile, current.getEncoded()); // the current CRL written again (a redeploy, a touch)
        touch(crlFile, 20);
        logged(events, () -> { registry.refresh(); return null; });
        assertSame(loaded, registry.crl("rollback").orElseThrow(), "unchanged: nothing happens");
        assertTrue(events.stream().noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.INFO)), events.toString());

        Files.write(crlFile, crl(iaca, 6, Instant.now().minusSeconds(60), Instant.now().plus(30, ChronoUnit.DAYS), revoked).getEncoded());
        touch(crlFile, 25);
        registry.refresh();
        assertEquals(BigInteger.valueOf(6), FileTrustAnchorRegistry.crlNumber(registry.crl("rollback").orElseThrow()), "renewal taken");
    }

    /**
     * Review round 1, item 2 (decision log 2026-11-13, refining D16): a CRL past its nextUpdate is logged on every tick,
     * unchanged file included; within certify.pki.stale-crl-grace signing continues with a WARN and known revocations
     * still apply; past it the DSC policy refuses CRL_STALE; a renewal recovers; the gauge counts down and goes negative.
     */
    @Test
    void aStaleCrlWarnsWithinTheGraceRefusesSigningPastItAndARenewalRecovers() throws Exception {
        Instant since = Instant.now().minus(30, ChronoUnit.DAYS);
        Iaca iaca = iaca("Stale IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/stale.crl", since);
        KeyPair dscKeys = p256();
        X509Certificate dsc = IsoMdocProfiles.ds(dscKeys, iaca.certificate(), iaca.keys()).commonName("Stale Test DSC").notBefore(since).build();
        Instant nextUpdate = Instant.now().minus(2, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);
        Path crlFile = Files.write(dir.resolve("stale.crl"), crl(iaca, 1, nextUpdate.minus(7, ChronoUnit.DAYS), nextUpdate).getEncoded());
        PkiProperties.AnchorSpec spec = new PkiProperties.AnchorSpec(null, write("stale.pem", Pem.writeCertificate(iaca.certificate())), crlFile);
        MutableClock clock = new MutableClock(Instant.now());

        List<ILoggingEvent> events = new java.util.ArrayList<>();
        FileTrustAnchorRegistry registry = logged(events, () -> new FileTrustAnchorRegistry(properties(Duration.ofHours(24), spec),
                List.of(), null, clock));
        assertTrue(has(events, Level.WARN, "passed its nextUpdate " + nextUpdate), "startup within the grace: WARN " + events);
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        registry.bindMetrics(meters);
        Gauge gauge = meters.get(FileTrustAnchorRegistry.METRIC).tag("anchor", "stale").gauge();
        assertEquals(-7200, gauge.value(), 5, "seconds to nextUpdate, negative once past");

        MdocDscPolicy policy = new MdocDscPolicy(registry);
        CertificateChain chain = CertificateChain.of(dsc, iaca.certificate());
        assertDoesNotThrow(() -> policy.check(chain, clock.instant()), "within the grace signing continues");
        events.clear();
        logged(events, () -> { registry.refresh(); return null; });
        assertTrue(has(events, Level.WARN, "passed its nextUpdate"), "every tick, the file unchanged: " + events);

        clock.set(nextUpdate.plus(24, ChronoUnit.HOURS).plusSeconds(1));
        FormatException refused = assertThrows(FormatException.class, () -> policy.check(chain, clock.instant()));
        assertEquals("certificate_chain_invalid", refused.getErrorCode());
        assertTrue(refused.getMessage().startsWith(MdocDscPolicy.CRL_STALE + ": "), refused.getMessage());
        events.clear();
        logged(events, () -> { registry.refresh(); return null; });
        assertTrue(has(events, Level.ERROR, "is refused (CRL_STALE)"), events.toString());

        // a renewal (a larger number, a later thisUpdate) recovers
        clock.set(Instant.now());
        Files.write(crlFile, crl(iaca, 2, Instant.now().minusSeconds(60), Instant.now().plus(7, ChronoUnit.DAYS)).getEncoded());
        touch(crlFile, 5);
        registry.refresh();
        assertDoesNotThrow(() -> policy.check(chain, clock.instant()), "a renewal recovers");
        assertTrue(gauge.value() > Duration.ofDays(6).toSeconds(), "the gauge follows the renewal: " + gauge.value());

        // PT0S: refused as soon as nextUpdate has passed
        Instant renewedNext = registry.crl("stale").orElseThrow().getNextUpdate().toInstant();
        FileTrustAnchorRegistry strict = new FileTrustAnchorRegistry(properties(Duration.ZERO, spec), List.of(), null, Clock.systemUTC());
        assertEquals(Duration.ZERO, strict.staleCrlGrace());
        assertDoesNotThrow(() -> new MdocDscPolicy(strict).check(chain, renewedNext));
        FormatException immediately = assertThrows(FormatException.class, () -> new MdocDscPolicy(strict).check(chain, renewedNext.plusSeconds(1)));
        assertTrue(immediately.getMessage().startsWith(MdocDscPolicy.CRL_STALE + ": "), immediately.getMessage());
        // startup past the grace is refused
        clock.set(renewedNext.plus(24, ChronoUnit.HOURS).plusSeconds(1));
        IllegalStateException startup = assertThrows(IllegalStateException.class, () -> new FileTrustAnchorRegistry(
                properties(Duration.ofHours(24), spec), List.of(), null, clock));
        assertTrue(startup.getMessage().contains("certify.pki.stale-crl-grace"), startup.getMessage());
        assertThrows(IllegalArgumentException.class, () -> properties(Duration.ofSeconds(-1)));
        assertEquals(Duration.ofHours(24), properties().staleCrlGrace(), "PT24H by default");
    }

    @Test
    void aRevocationInAStaleCrlWithinTheGraceStillApplies() throws Exception {
        Instant since = Instant.now().minus(30, ChronoUnit.DAYS);
        Iaca iaca = iaca("Revoking IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/revoking.crl", since);
        X509Certificate dsc = IsoMdocProfiles.ds(p256(), iaca.certificate(), iaca.keys()).commonName("Revoked Test DSC").notBefore(since).build();
        Instant nextUpdate = Instant.now().minus(1, ChronoUnit.HOURS);
        Path crlFile = Files.write(dir.resolve("revoking.crl"),
                crl(iaca, 1, nextUpdate.minus(7, ChronoUnit.DAYS), nextUpdate, dsc.getSerialNumber()).getEncoded());
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(new PkiProperties.AnchorSpec(null,
                write("revoking.pem", Pem.writeCertificate(iaca.certificate())), crlFile)), List.of(), null, Clock.systemUTC());
        FormatException refused = assertThrows(FormatException.class,
                () -> new MdocDscPolicy(registry).check(CertificateChain.of(dsc, iaca.certificate()), Instant.now()));
        assertTrue(refused.getMessage().startsWith(MdocDscPolicy.DSC_REVOKED + ": "), refused.getMessage());
    }

    /** With the refresh off, nothing renews a CRL: said once at startup, and signing still stops past the grace. */
    @Test
    void aDisabledRefreshIsLogged() throws Exception {
        JcaKeyProvider devMode = new JcaKeyProvider("x509-file");
        X509Certificate iaca = devMode.generateIaca("iaca", new MdocIacaSpec(SignatureAlgorithm.ES256, "IN", null,
                "Lorem Ipsum No Refresh IACA", "https://credentials.example.test", null,
                "https://credentials.example.test/v1/certify/mdoc/iaca/no-refresh.crl", null)).chain().leaf().orElseThrow();
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties(), List.of(iaca), devMode::issueEmptyCrl, Clock.systemUTC());
        List<ILoggingEvent> events = new java.util.ArrayList<>();
        logged(events, () -> { registry.scheduleRefresh(Duration.ZERO); return null; });
        assertTrue(has(events, Level.WARN, "is never re-issued (dev mode)") && has(events, Level.WARN, "CRL_STALE"), events.toString());
        registry.close();
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

    /**
     * Review round 1, item 3: the dev CRL's number is recorded per IACA next to the keystore, so a restart in the same
     * second, or after the clock went back, never reuses or lowers it; the file is replaced atomically.
     */
    @Test
    void devCrlNumbersSurviveARestartInTheSameSecondAndAClockSetBack() throws Exception {
        // valid for 30 days already, so the clock can be set back while CrlBuilder still accepts thisUpdate
        Iaca numbered = iaca("Lorem Ipsum Numbered IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/numbered.crl",
                Instant.now().minus(30, ChronoUnit.DAYS));
        X509Certificate iaca = numbered.certificate();
        FileTrustAnchorRegistry.DevCrlIssuer devMode = (certificate, number, thisUpdate, nextUpdate) -> certificate.equals(iaca)
                ? Optional.of(CrlBuilder.forIaca(certificate, numbered.keys()).crlNumber(number).thisUpdate(thisUpdate).nextUpdate(nextUpdate).build())
                : Optional.empty();
        Path keystore = dir.resolve("keys/x509-file.p12");
        Path store = CrlNumberStore.nextTo(keystore);
        assertEquals(dir.resolve("keys/x509-file.p12.crl-numbers"), store);
        MutableClock clock = new MutableClock(Instant.now().truncatedTo(ChronoUnit.SECONDS));

        BigInteger first = FileTrustAnchorRegistry.crlNumber(new FileTrustAnchorRegistry(properties(), List.of(iaca), devMode,
                CrlNumberStore.file(store), clock).crl("numbered").orElseThrow());
        assertTrue(Files.readString(store).contains(CrlNumberStore.fingerprint(iaca) + "=" + first), Files.readString(store));
        BigInteger sameSecond = FileTrustAnchorRegistry.crlNumber(new FileTrustAnchorRegistry(properties(), List.of(iaca), devMode,
                CrlNumberStore.file(store), clock).crl("numbered").orElseThrow());
        assertEquals(first.add(BigInteger.ONE), sameSecond, "a restart in the same second takes the next number");
        clock.set(clock.instant().minus(1, ChronoUnit.HOURS));
        BigInteger setBack = FileTrustAnchorRegistry.crlNumber(new FileTrustAnchorRegistry(properties(), List.of(iaca), devMode,
                CrlNumberStore.file(store), clock).crl("numbered").orElseThrow());
        assertEquals(sameSecond.add(BigInteger.ONE), setBack, "a clock set back never lowers the number");
        try (var files = Files.list(store.getParent())) {
            assertEquals(List.of(store), files.toList(), "no temporary file left behind");
        }

        // an IACA whose key is not held records nothing; an unreadable store refuses startup
        Iaca offline = iaca("Offline Numbered IACA", "https://credentials.example.test/v1/certify/mdoc/iaca/offline-numbered.crl");
        new FileTrustAnchorRegistry(properties(), List.of(offline.certificate()), devMode, CrlNumberStore.file(store), clock);
        assertFalse(Files.readString(store).contains(CrlNumberStore.fingerprint(offline.certificate())));
        Files.writeString(store, CrlNumberStore.fingerprint(iaca) + "=not-a-number\n");
        IllegalStateException broken = assertThrows(IllegalStateException.class, () -> CrlNumberStore.file(store));
        assertTrue(broken.getMessage().contains(store.toString()), broken.getMessage());
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
