package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SigningException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-05 review findings on the {@code x509-file} provider: PEM key/certificate pairing, PEM keys never written to the
 * keystore, purposes kept across a restart, settings that changed after generation, and PEM chain shape.
 */
class X509FileRestartAndImportTest {

    private static final String CRL_URI = "https://credentials.example.test/mdoc/iaca/demo-iaca.crl";
    private static final String ALT_URI = "https://credentials.example.test/mdoc/iaca";

    @TempDir Path dir;

    private static X509FileProperties.IacaSpec iaca(String alias, String commonName, String altName, String crlUri,
                                                     Integer years, String algorithm) {
        return new X509FileProperties.IacaSpec(alias, "IN", "Karnataka", commonName, altName, crlUri, years, algorithm);
    }

    private static X509FileProperties.IacaSpec iaca() {
        return iaca("iaca", "Demo IACA", ALT_URI, CRL_URI, null, "ES256");
    }

    private static X509FileProperties.KeySpec dsc(String alias, String subject, String algorithm, Integer days) {
        return new X509FileProperties.KeySpec(alias, algorithm, subject, "mdoc-dsc", days);
    }

    private static X509FileProperties props(Path file, boolean devMode, List<X509FileProperties.KeySpec> keys,
                                            List<X509FileProperties.PemKeySpec> pemKeys, X509FileProperties.IacaSpec iaca) {
        return new X509FileProperties(true, "x509-file", file, "pw", devMode, keys, "vc-signing", "dev-ca",
                "CN=Inji Certify Dev CA", iaca, pemKeys);
    }

    // ---- item 2: the PEM private key must be the key the leaf certifies

    @Test
    void aPemKeyThatIsNotTheDocumentSignersKeyRefusesStartupPlainOrEncrypted() throws Exception {
        KeyPair iacaKeys = keyPair();
        X509Certificate iacaCertificate = IsoMdocProfiles.iaca(iacaKeys).country("IN").commonName("Demo IACA")
                .issuerAltUri(ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair dscKeys = keyPair();
        X509Certificate dscCertificate = IsoMdocProfiles.ds(dscKeys, iacaCertificate, iacaKeys)
                .commonName("Demo DSC").build();
        Path chain = write("dsc.chain.pem", Pem.writeCertificates(List.of(dscCertificate, iacaCertificate)));
        KeyPair other = keyPair();
        Path plainOther = write("other.key.pem", Pem.writePrivateKey(other.getPrivate()));
        Path encryptedOther = write("other.enc.key.pem",
                Pem.writeEncryptedPrivateKey(other.getPrivate(), "secret".toCharArray()));

        SigningException plain = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null, false,
                List.of(), List.of(new X509FileProperties.PemKeySpec("mdl-dsc", plainOther, null, chain)), null)));
        assertTrue(plain.getMessage().contains("does not match the public key of the leaf certificate"), plain.getMessage());
        SigningException encrypted = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null,
                false, List.of(), List.of(new X509FileProperties.PemKeySpec("mdl-dsc", encryptedOther, "secret", chain)),
                null)));
        assertTrue(encrypted.getMessage().contains("does not match"), encrypted.getMessage());
        // an RSA key against an EC certificate cannot even sign the challenge: the same refusal
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        Path rsaKey = write("rsa.key.pem", Pem.writePrivateKey(rsa.generateKeyPair().getPrivate()));
        assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null, false, List.of(),
                List.of(new X509FileProperties.PemKeySpec("mdl-dsc", rsaKey, null, chain)), null)));

        Path rightKey = write("dsc.key.pem", Pem.writeEncryptedPrivateKey(dscKeys.getPrivate(), "secret".toCharArray()));
        assertDoesNotThrow(() -> X509FileKeyProviders.open(props(null, false, List.of(),
                List.of(new X509FileProperties.PemKeySpec("mdl-dsc", rightKey, "secret", chain)), null)));
    }

    // ---- items 7 and 12: PEM keys stay out of the keystore; Annex B chains are exactly [DSC, IACA]

    @Test
    void pemKeysAreNeverWrittenIntoTheDevKeystore() throws Exception {
        PemDsc pem = pemDsc("pem");
        Path file = dir.resolve("issuer.p12");
        List<X509FileProperties.KeySpec> keys = List.of(dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 300),
                new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=VC issuer"));

        JcaKeyProvider provider = X509FileKeyProviders.open(props(file, true, keys,
                List.of(new X509FileProperties.PemKeySpec("mdl-dsc@2027-02", pem.key, null, pem.chain)), iaca()));
        assertTrue(provider.aliases().contains("mdl-dsc@2027-02"), "the PEM key is served");

        KeyStore stored = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            stored.load(in, "pw".toCharArray());
        }
        List<String> aliases = Collections.list(stored.aliases());
        assertFalse(aliases.contains("mdl-dsc@2027-02"), "the operator's PEM key is not copied: " + aliases);
        assertTrue(aliases.containsAll(List.of("iaca", "mdl-dsc@2026-11", "dev-ca", "issuer-es256")), aliases.toString());

        // a PEM key may not shadow a keystore entry
        SigningException clash = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(file, false,
                keys, List.of(new X509FileProperties.PemKeySpec("issuer-es256", pem.key, null, pem.chain)), iaca())));
        assertTrue(clash.getMessage().contains("already in the keystore"), clash.getMessage());
    }

    @Test
    void anMdlChainMustBeExactlyTheDocumentSignerAndItsIaca() throws Exception {
        PemDsc pem = pemDsc("long");
        Path tooLong = write("long3.chain.pem", Pem.writeCertificates(List.of(pem.dsc, pem.iaca, pem.iaca)));
        SigningException three = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null, false,
                List.of(), List.of(new X509FileProperties.PemKeySpec("mdl-dsc", pem.key, null, tooLong)), null)));
        assertTrue(three.getMessage().contains("exactly [DSC, IACA]"), three.getMessage());

        Path reversed = write("reversed.chain.pem", Pem.writeCertificates(List.of(pem.iaca, pem.dsc)));
        SigningException order = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null, false,
                List.of(), List.of(new X509FileProperties.PemKeySpec("mdl-dsc", pem.key, null, reversed)), null)));
        assertTrue(order.getMessage().contains("leaf first"), order.getMessage());
    }

    // ---- items 5 and 9: purposes after a restart

    @Test
    void purposesSurviveARestart() {
        Path file = dir.resolve("restart.p12");
        List<X509FileProperties.KeySpec> keys = List.of(dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 300),
                new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=VC issuer"));
        JcaKeyProvider first = X509FileKeyProviders.open(props(file, true, keys, null, iaca()));
        Map<String, String> expected = Map.of("iaca", "mdoc-iaca", "mdl-dsc@2026-11", "mdoc-dsc",
                "dev-ca", "dev-ca", "issuer-es256", "vc-signing");
        assertEquals(expected, purposes(first));

        JcaKeyProvider restarted = X509FileKeyProviders.open(props(file, false, keys, null, iaca()));

        assertEquals(expected, purposes(restarted), "the restart derives the same purposes from the certificates");
        assertEquals(List.of("iaca"), restarted.publicKeys(KeyFilter.ALL).stream()
                .filter(descriptor -> !descriptor.isSigningKey()).map(PublicKeyDescriptor::kid).toList(),
                "only the IACA is kept out of a JWKS or DID document");
        assertEquals(1, X509FileKeyProviders.iacaCertificates(restarted).size());
    }

    // ---- item 4: settings that shaped a stored certificate

    @Test
    void changedIacaSettingsRefuseStartupUntilRestoredOrRotatedToANewAlias() {
        Path file = dir.resolve("iaca.p12");
        List<X509FileProperties.KeySpec> keys = List.of(dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 300));
        X509Certificate original = X509FileKeyProviders.open(props(file, true, keys, null,
                iaca("iaca", "Demo IACA", ALT_URI, CRL_URI, 15, "ES256")))
                .resolve(KeyRef.parse("x509-file:iaca")).chain().leaf().orElseThrow();

        Map<String, UnaryOperator<X509FileProperties.IacaSpec>> changes = Map.of(
                "iaca.common-name", s -> iaca("iaca", "Renamed IACA", ALT_URI, CRL_URI, 15, "ES256"),
                "iaca.issuer-alt-name", s -> iaca("iaca", "Demo IACA", "pki@example.test", CRL_URI, 15, "ES256"),
                "iaca.crl-uri", s -> iaca("iaca", "Demo IACA", ALT_URI, CRL_URI + "?v=2", 15, "ES256"),
                "iaca.algorithm", s -> iaca("iaca", "Demo IACA", ALT_URI, CRL_URI, 15, "ES384"),
                "iaca.validity-years", s -> iaca("iaca", "Demo IACA", ALT_URI, CRL_URI, 10, "ES256"),
                "iaca.country", s -> new X509FileProperties.IacaSpec("iaca", "LK", "Karnataka", "Demo IACA", ALT_URI,
                        CRL_URI, 15, "ES256"),
                "iaca.state", s -> new X509FileProperties.IacaSpec("iaca", "IN", "Kerala", "Demo IACA", ALT_URI,
                        CRL_URI, 15, "ES256"));
        changes.forEach((property, change) -> {
            for (boolean devMode : List.of(true, false)) {
                SigningException refused = assertThrows(SigningException.class,
                        () -> X509FileKeyProviders.open(props(file, devMode, keys, null, change.apply(null))), property);
                assertTrue(refused.getMessage().contains(property), property + ": " + refused.getMessage());
                assertTrue(refused.getMessage().contains("never regenerated automatically")
                        && refused.getMessage().contains("new alias"), refused.getMessage());
            }
        });

        // restored settings start; settings left out are not compared (an IACA named only by its alias)
        assertDoesNotThrow(() -> X509FileKeyProviders.open(props(file, false, keys, null,
                iaca("iaca", "Demo IACA", ALT_URI, CRL_URI, 15, "ES256"))));
        assertDoesNotThrow(() -> X509FileKeyProviders.open(props(file, false, keys, null,
                new X509FileProperties.IacaSpec("iaca", null, null, null, null, null, null, null))));

        // rotating to a new alias generates a new IACA; the old Document Signer keeps validating against its own
        List<X509FileProperties.KeySpec> rotatedKeys = List.of(keys.get(0),
                dsc("mdl-dsc@2027-02", "CN=Demo DSC", "ES256", 300));
        JcaKeyProvider rotated = X509FileKeyProviders.open(props(file, true, rotatedKeys, null,
                iaca("iaca-2", "Renamed IACA", ALT_URI, CRL_URI, null, null)));
        X509Certificate second = rotated.resolve(KeyRef.parse("x509-file:iaca-2")).chain().leaf().orElseThrow();
        assertEquals(original, rotated.resolve(KeyRef.parse("x509-file:iaca")).chain().leaf().orElseThrow(),
                "the first IACA is kept, never regenerated");
        assertEquals(second, rotated.resolve(KeyRef.parse("x509-file:mdl-dsc@2027-02")).chain().root().orElseThrow());
        assertEquals(original, rotated.resolve(KeyRef.parse("x509-file:mdl-dsc@2026-11")).chain().root().orElseThrow());
        assertEquals(2, X509FileKeyProviders.iacaCertificates(rotated).size(), "both anchors are published");
    }

    @Test
    void changedDocumentSignerSettingsRefuseStartup() {
        Path file = dir.resolve("dsc.p12");
        X509FileKeyProviders.open(props(file, true, List.of(dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 300)),
                null, iaca()));

        Map<String, X509FileProperties.KeySpec> changes = Map.of(
                "keys[].subject", dsc("mdl-dsc@2026-11", "CN=Renamed DSC", "ES256", 300),
                "keys[].algorithm", dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES384", 300),
                "keys[].validity-days", dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 200));
        changes.forEach((property, key) -> {
            SigningException refused = assertThrows(SigningException.class,
                    () -> X509FileKeyProviders.open(props(file, true, List.of(key), null, iaca())), property);
            assertTrue(refused.getMessage().contains(property), refused.getMessage());
            assertTrue(refused.getMessage().contains("new version of the key"), refused.getMessage());
        });
        assertDoesNotThrow(() -> X509FileKeyProviders.open(props(file, false,
                List.of(dsc("mdl-dsc@2026-11", null, "ES256", null)), null, iaca())),
                "settings that are not given are not compared");
    }

    // ---- round 3: the IACA clamp excuses a shorter Document Signer only when validity-days reaches the IACA's end

    @Test
    void aDscClampedToItsIacaMatchesOnlyAValidityThatReachesTheIacaEnd() throws Exception {
        KeyPair iacaKeys = keyPair();
        // an IACA with 100 days left: a Document Signer issued now for 457 days ends with it
        X509Certificate iacaCertificate = IsoMdocProfiles.iaca(iacaKeys)
                .notBefore(java.time.Instant.now().minus(java.time.Duration.ofDays(1)))
                .validity(java.time.Duration.ofDays(101)).country("IN").commonName("Short IACA")
                .issuerAltUri(ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair dscKeys = keyPair();
        X509Certificate dscCertificate = IsoMdocProfiles.ds(dscKeys, iacaCertificate, iacaKeys)
                .commonName("Demo DSC").build();
        assertEquals(iacaCertificate.getNotAfter(), dscCertificate.getNotAfter(), "clamped to the IACA");
        JcaKeyProvider keystore = new JcaKeyProvider("x509-file");
        keystore.add("iaca", iacaKeys.getPrivate(), io.mosip.certify.signing.CertificateChain.of(iacaCertificate), null,
                "mdoc-iaca");
        keystore.add("mdl-dsc", dscKeys.getPrivate(),
                io.mosip.certify.signing.CertificateChain.of(dscCertificate, iacaCertificate), null, "mdoc-dsc");
        Path file = dir.resolve("clamped.p12");
        keystore.saveAsPkcs12(file, "pw".toCharArray());
        X509FileProperties.IacaSpec byAlias = new X509FileProperties.IacaSpec("iaca", null, null, null, null, null,
                null, null);

        SigningException refused = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(file,
                false, List.of(dsc("mdl-dsc", null, "ES256", 30)), null, byAlias)));
        assertTrue(refused.getMessage().contains("keys[].validity-days is 30")
                && refused.getMessage().contains("ending with its IACA"), refused.getMessage());

        for (int days : List.of(100, 200, 457)) {
            assertDoesNotThrow(() -> X509FileKeyProviders.open(props(file, false,
                    List.of(dsc("mdl-dsc", null, "ES256", days)), null, byAlias)), "validity-days " + days);
        }
        SigningException tooShort = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(file,
                false, List.of(dsc("mdl-dsc", null, "ES256", 99)), null, byAlias)));
        assertTrue(tooShort.getMessage().contains("keys[].validity-days is 99"), tooShort.getMessage());
    }

    // ---- round 3: a configured keystore must exist; dev mode needs a path to write what it generates

    @Test
    void aMissingKeystoreRefusesStartupEvenNextToPemKeys() throws Exception {
        PemDsc pem = pemDsc("missing");
        Path missing = dir.resolve("absent.p12");
        SigningException refused = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(missing,
                false, List.of(), List.of(new X509FileProperties.PemKeySpec("mdl-dsc", pem.key, null, pem.chain)),
                null)));
        assertTrue(refused.getMessage().contains(missing + " does not exist and dev mode is off"), refused.getMessage());
    }

    @Test
    void devModeWithoutAPathRefusesToGenerateAndNamesTheSetting() throws Exception {
        PemDsc pem = pemDsc("nopath");
        List<X509FileProperties.PemKeySpec> pemKeys =
                List.of(new X509FileProperties.PemKeySpec("mdl-dsc", pem.key, null, pem.chain));

        SigningException iacaRefused = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null,
                true, List.of(dsc("mdl-dsc@2026-11", "CN=Demo DSC", "ES256", 300)), pemKeys, iaca())));
        assertTrue(iacaRefused.getMessage().contains("set certify.keyprovider.x509-file.path"), iacaRefused.getMessage());
        SigningException plainRefused = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null,
                true, List.of(new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=VC issuer")), pemKeys, null)));
        assertTrue(plainRefused.getMessage().contains("set certify.keyprovider.x509-file.path"), plainRefused.getMessage());

        SigningException production = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null,
                false, List.of(new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=VC issuer")), pemKeys, null)));
        assertTrue(production.getMessage().contains("PEM-only configuration"), production.getMessage());
        assertFalse(production.getMessage().contains("null"), production.getMessage());

        // nothing to generate: PEM keys alone start in dev mode without a path
        assertDoesNotThrow(() -> X509FileKeyProviders.open(props(null, true, List.of(), pemKeys, null)));
        SigningException clash = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(null, false,
                List.of(), List.of(pemKeys.get(0), pemKeys.get(0)), null)));
        assertFalse(clash.getMessage().contains("null"), clash.getMessage());
    }

    private static Map<String, String> purposes(JcaKeyProvider provider) {
        return provider.publicKeys(KeyFilter.ALL).stream()
                .collect(Collectors.toMap(PublicKeyDescriptor::kid, PublicKeyDescriptor::purpose));
    }

    private record PemDsc(X509Certificate iaca, X509Certificate dsc, Path key, Path chain) {}

    private PemDsc pemDsc(String name) throws Exception {
        KeyPair iacaKeys = keyPair();
        X509Certificate iacaCertificate = IsoMdocProfiles.iaca(iacaKeys).country("IN").commonName("Operator IACA")
                .issuerAltUri(ALT_URI).crlDistributionPoint(CRL_URI).build();
        KeyPair dscKeys = keyPair();
        X509Certificate dscCertificate = IsoMdocProfiles.ds(dscKeys, iacaCertificate, iacaKeys)
                .commonName("Operator DSC").build();
        return new PemDsc(iacaCertificate, dscCertificate,
                write(name + ".key.pem", Pem.writePrivateKey(dscKeys.getPrivate())),
                write(name + ".chain.pem", Pem.writeCertificates(List.of(dscCertificate, iacaCertificate))));
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private Path write(String name, String pem) throws IOException {
        return Files.writeString(dir.resolve(name), pem, StandardCharsets.US_ASCII);
    }
}
