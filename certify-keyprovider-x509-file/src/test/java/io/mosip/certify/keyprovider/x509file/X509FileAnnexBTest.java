package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * M-05: the Annex B dev mode, PEM Document Signer import and versioned aliases of the {@code x509-file} provider, with
 * {@code openssl verify -x509_strict} as the independent verifier (OpenSSL is skipped without it locally and fails in
 * CI, as in {@code certify-pki}).
 */
class X509FileAnnexBTest {

    private static final String CRL_URI = "https://credentials.example.test/mdoc/iaca/lorem-ipsum-demo-iaca.crl";
    private static final String IACA_ALT_URI = "https://credentials.example.test/mdoc/iaca";

    @TempDir Path dir;

    private static X509FileProperties.IacaSpec iacaSpec() {
        return new X509FileProperties.IacaSpec("iaca", "IN", "Karnataka", "Lorem Ipsum Demo IACA", IACA_ALT_URI,
                CRL_URI, null, "ES256");
    }

    private X509FileProperties props(Path file, boolean devMode, List<X509FileProperties.KeySpec> keys,
                                     List<X509FileProperties.PemKeySpec> pemKeys, X509FileProperties.IacaSpec iaca) {
        return new X509FileProperties(true, "x509-file", file, "pw", devMode, keys, "vc-signing", "dev-ca",
                "CN=Inji Certify Dev CA", iaca, pemKeys);
    }

    @Test
    void devModeGeneratesAnAnnexBIacaAndDscThatPassTheValidatorAndOpenSsl() throws Exception {
        Path file = dir.resolve("mdl/issuer.p12");
        List<X509FileProperties.KeySpec> keys = List.of(
                new X509FileProperties.KeySpec("mdl-dsc@2027-02", "ES256", "CN=Lorem Ipsum Demo DSC", "mdoc-dsc", 400),
                new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=Inji Certify VC issuer"));

        JcaKeyProvider provider = X509FileKeyProviders.open(props(file, true, keys, null, iacaSpec()));
        SigningKey iacaKey = provider.resolve(KeyRef.parse("x509-file:iaca"));
        X509Certificate iaca = iacaKey.chain().leaf().orElseThrow();
        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca), "the generated IACA meets Annex B");
        assertTrue(iaca.getSubjectX500Principal().getName().contains("C=IN"), iaca.getSubjectX500Principal().getName());
        assertTrue(iaca.getSubjectX500Principal().getName().contains("CN=Lorem Ipsum Demo IACA"));

        SigningKey dscKey = provider.resolve(KeyRef.parse("x509-file:mdl-dsc"));
        X509Certificate dsc = dscKey.chain().leaf().orElseThrow();
        assertEquals(List.of(), AnnexBValidator.validateDs(dsc, iaca), "the generated DSC meets Annex B");
        assertEquals(2, dscKey.chain().leafFirst().size(), "the chain is [DSC, IACA]");
        assertEquals(iaca, dscKey.chain().root().orElseThrow());
        assertTrue(dsc.getSubjectX500Principal().getName().contains("C=IN"), dsc.getSubjectX500Principal().getName());
        assertTrue(dsc.getSubjectX500Principal().getName().contains("ST=Karnataka"));
        assertTrue(dsc.getSubjectX500Principal().getName().contains("CN=Lorem Ipsum Demo DSC"));
        assertTrue(dsc.getExtendedKeyUsage().contains(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE));
        assertTrue(dsc.getExtensionValue("2.5.29.31") != null, "the DSC carries a CRL distribution point");
        assertEquals(List.of(iaca), X509FileKeyProviders.iacaCertificates(provider),
                "the IACA is exposed for the trust-anchor registry (M-06)");
        assertEquals(64, provider.signRaw("mDL".getBytes(StandardCharsets.US_ASCII), dscKey, SignatureAlgorithm.ES256).length);

        // P3-08 is untouched for a plain key: it still chains to the dev CA, which is not an IACA
        SigningKey plain = provider.resolve(KeyRef.parse("x509-file:issuer-es256"));
        assertEquals("CN=Inji Certify Dev CA", plain.chain().root().orElseThrow().getSubjectX500Principal().getName());

        // a second start reuses the generated material, so an IACA URL stays the trust anchor it published
        JcaKeyProvider restarted = X509FileKeyProviders.open(props(file, false, keys, null, iacaSpec()));
        assertEquals(iaca, restarted.resolve(KeyRef.parse("x509-file:iaca")).chain().leaf().orElseThrow());
        assertEquals(dsc, restarted.resolve(KeyRef.parse("x509-file:mdl-dsc")).chain().leaf().orElseThrow());
        assertEquals(List.of(iaca), X509FileKeyProviders.iacaCertificates(restarted));

        opensslVerifiesStrictly(iaca, dsc);
    }

    @Test
    void pemKeysAreImportedPlainOrEncryptedWithTheirChain() throws Exception {
        KeyPair iacaKeyPair = keyPair();
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair).country("IN")
                .commonName("Lorem Ipsum Demo IACA").issuerAltUri(IACA_ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair firstKeyPair = keyPair();
        X509Certificate first = IsoMdocProfiles.ds(firstKeyPair, iaca, iacaKeyPair).commonName("Demo DSC 1").build();
        KeyPair secondKeyPair = keyPair();
        X509Certificate second = IsoMdocProfiles.ds(secondKeyPair, iaca, iacaKeyPair).commonName("Demo DSC 2").build();
        String chain = Pem.writeCertificates(List.of(first, iaca));
        Path firstKey = write("first.key.pem", Pem.writePrivateKey(firstKeyPair.getPrivate()));
        Path secondKey = write("second.key.pem", Pem.writeEncryptedPrivateKey(secondKeyPair.getPrivate(),
                "key-password".toCharArray()));
        Path firstChain = write("first.chain.pem", chain);
        Path secondChain = write("second.chain.pem", Pem.writeCertificates(List.of(second, iaca)));
        List<X509FileProperties.PemKeySpec> pemKeys = List.of(
                new X509FileProperties.PemKeySpec("mdl-dsc@2026-11", firstKey, null, firstChain),
                new X509FileProperties.PemKeySpec("mdl-dsc@2027-02", secondKey, "key-password", secondChain));

        JcaKeyProvider provider = X509FileKeyProviders.open(props(null, false, List.of(), pemKeys, null));

        SigningKey resolved = provider.resolve(KeyRef.parse("x509-file:mdl-dsc"));
        assertEquals(second, resolved.chain().leaf().orElseThrow(), "the later, currently valid version wins");
        assertEquals(List.of(second, iaca), resolved.chain().leafFirst());
        assertEquals(List.of(first, iaca),
                provider.resolve(KeyRef.parse("x509-file:mdl-dsc@2026-11")).chain().leafFirst(),
                "a versioned alias resolves to that version, the encrypted key included");
        assertEquals(List.of(iaca), X509FileKeyProviders.iacaCertificates(provider),
                "both chains end at the same IACA, listed once");
        assertEquals(64, provider.signRaw("mDL".getBytes(StandardCharsets.US_ASCII), resolved, SignatureAlgorithm.ES256).length);
    }

    @Test
    void aChainThatViolatesAnnexBRefusesStartup() throws Exception {
        KeyPair iacaKeyPair = keyPair();
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair).country("IN").commonName("Demo IACA")
                .issuerAltUri(IACA_ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair otherIacaKeyPair = keyPair();
        X509Certificate otherIaca = IsoMdocProfiles.iaca(otherIacaKeyPair).country("IN").commonName("Other IACA")
                .issuerAltUri(IACA_ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair dscKeyPair = keyPair();
        X509Certificate dsc = IsoMdocProfiles.ds(dscKeyPair, iaca, iacaKeyPair).commonName("Demo DSC").build();
        // the chain names an IACA that did not sign the Document Signer
        List<X509FileProperties.PemKeySpec> pemKeys = List.of(new X509FileProperties.PemKeySpec("mdl-dsc",
                write("wrong.key.pem", Pem.writePrivateKey(dscKeyPair.getPrivate())), null,
                write("wrong.chain.pem", Pem.writeCertificates(List.of(dsc, otherIaca)))));

        SigningException brokenChain = assertThrows(SigningException.class,
                () -> X509FileKeyProviders.open(props(null, false, List.of(), pemKeys, null)));
        assertTrue(brokenChain.getMessage().contains("DS_ISSUER_MISMATCH")
                || brokenChain.getMessage().contains("DS_SIGNATURE_INVALID"), brokenChain.getMessage());

        // an IACA alias that holds the P3-08 dev CA is not an IACA
        Path file = dir.resolve("plain.p12");
        X509FileKeyProviders.open(props(file, true, List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a")),
                null, null));
        X509FileProperties.IacaSpec devCaAsIaca = new X509FileProperties.IacaSpec("dev-ca", "IN", null, "Dev CA",
                IACA_ALT_URI, CRL_URI, null, "ES256");
        SigningException notAnIaca = assertThrows(SigningException.class,
                () -> X509FileKeyProviders.open(props(file, false, List.of(), null, devCaAsIaca)));
        assertTrue(notAnIaca.getMessage().contains("Annex B"), notAnIaca.getMessage());
        assertTrue(notAnIaca.getMessage().contains("IACA_"), notAnIaca.getMessage());
    }

    @Test
    void rotationPicksTheNewestValidVersionAndListsEveryVersion() throws Exception {
        KeyPair iacaKeyPair = keyPair();
        X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .notBefore(Instant.now().minus(500, ChronoUnit.DAYS))
                .country("IN").commonName("Demo IACA").issuerAltUri(IACA_ALT_URI).crlDistributionPoint(CRL_URI).build();
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        addVersion(provider, iaca, iacaKeyPair, "mdl-dsc@2026-11",
                Instant.now().minus(400, ChronoUnit.DAYS), 365);
        addVersion(provider, iaca, iacaKeyPair, "mdl-dsc@2027-02",
                Instant.now().minus(1, ChronoUnit.DAYS), 400);

        SigningKey current = provider.resolve(KeyRef.parse("x509-file:mdl-dsc"));
        assertEquals("mdl-dsc@2027-02", current.kid(), "the newest entry whose certificate is valid now");
        SigningKey pinned = provider.resolve(KeyRef.parse("x509-file:mdl-dsc@2026-11"));
        assertEquals("mdl-dsc@2026-11", pinned.kid(), "a versioned alias resolves exactly, expired or not");
        assertTrue(pinned.descriptor().notAfter().isBefore(Instant.now()));

        List<String> versions = provider.publicKeys(KeyRef.parse("x509-file:mdl-dsc")).stream()
                .map(descriptor -> descriptor.kid()).toList();
        assertEquals(List.of("mdl-dsc@2026-11", "mdl-dsc@2027-02"), versions,
                "publicKeys lists every version, for a JWKS that must verify old credentials");
        assertEquals(1, provider.publicKeys(KeyRef.parse("x509-file:mdl-dsc@2027-02")).size(),
                "a versioned reference names one version");
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("x509-file:mdl-dsc@2029-01")));
    }

    @Test
    void aDevCaWithoutAnIacaIsNotPublishedAsOne() {
        Path file = dir.resolve("no-iaca.p12");
        JcaKeyProvider provider = X509FileKeyProviders.open(props(file, true,
                List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a")), null, null));
        assertEquals(List.of(), X509FileKeyProviders.iacaCertificates(provider),
                "the P3-08 dev CA is not an Annex B IACA");
        assertNotEquals(null, provider.resolve(KeyRef.parse("x509-file:dev-ca")).chain().leaf().orElseThrow());
    }

    private static void addVersion(JcaKeyProvider provider, X509Certificate iaca, KeyPair iacaKeyPair, String alias,
                                   Instant notBefore, int validityDays) throws Exception {
        KeyPair keyPair = keyPair();
        X509Certificate dsc = IsoMdocProfiles.ds(keyPair, iaca, iacaKeyPair).commonName("Demo DSC")
                .notBefore(notBefore).validity(java.time.Duration.ofDays(validityDays)).build();
        provider.add(alias, keyPair.getPrivate(), CertificateChain.of(dsc, iaca), SignatureAlgorithm.ES256, "mdoc-dsc");
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private Path write(String name, String pem) throws IOException {
        return Files.writeString(dir.resolve(name), pem, StandardCharsets.US_ASCII);
    }

    private void opensslVerifiesStrictly(X509Certificate iaca, X509Certificate dsc) throws Exception {
        if (!opensslAvailable()) {
            if (System.getenv("CI") != null) {
                fail("openssl is not on the PATH and CI is set: the independent verifier must run");
            }
            org.junit.jupiter.api.Assumptions.abort("openssl is not on the PATH");
        }
        Path caFile = write("ca.pem", Pem.writeCertificate(iaca));
        Path dscFile = write("dsc.pem", Pem.writeCertificate(dsc));
        String output = openssl("verify", "-x509_strict", "-CAfile", caFile.toString(), dscFile.toString());
        assertTrue(output.contains("OK"), output);
    }

    private static boolean opensslAvailable() {
        try {
            return openssl("version") != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String openssl(String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("openssl");
        command.addAll(Arrays.asList(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "openssl did not finish");
        assertEquals(0, process.exitValue(), output);
        return output;
    }
}
