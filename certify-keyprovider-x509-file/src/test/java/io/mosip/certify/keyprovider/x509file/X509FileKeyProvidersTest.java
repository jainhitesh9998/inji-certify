package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509FileKeyProvidersTest {

    @TempDir Path dir;

    X509FileProperties props(Path file, boolean devMode, List<X509FileProperties.KeySpec> keys) {
        return new X509FileProperties(true, "x509-file", file, "pw", devMode, keys, "vc-signing", "dev-ca", "CN=Inji Certify Dev CA");
    }

    @Test
    void devModeGeneratesTheKeysAndTheFileAndTheFileIsReusedNext() {
        Path file = dir.resolve("keys/issuer.p12");
        List<X509FileProperties.KeySpec> keys = List.of(new X509FileProperties.KeySpec("issuer-es256", "ES256", "CN=mDL DSC"),
                new X509FileProperties.KeySpec("issuer-eddsa", "EdDSA", "CN=VC issuer"));

        JcaKeyProvider first = X509FileKeyProviders.open(props(file, true, keys));
        assertTrue(Files.exists(file), "the PKCS#12 file is created");
        assertEquals("x509-file", first.id());
        SigningKey es256 = first.resolve(KeyRef.parse("x509-file:issuer-es256"));
        assertEquals(SignatureAlgorithm.ES256, es256.algorithm());
        assertEquals("CN=mDL DSC", es256.chain().leaf().orElseThrow().getSubjectX500Principal().getName());

        JcaKeyProvider second = X509FileKeyProviders.open(props(file, false, keys));
        assertEquals(first.resolve(KeyRef.parse("x509-file:issuer-eddsa")).descriptor().publicKey(),
                second.resolve(KeyRef.parse("x509-file:issuer-eddsa")).descriptor().publicKey(), "the second start loads the same keys");
        assertEquals(3, second.publicKeys(KeyFilter.validNow()).size(), "the two keys and the dev CA that signed them");
        assertEquals(2, es256.chain().leafFirst().size(), "generated keys chain to the dev CA");
        assertEquals("CN=Inji Certify Dev CA", es256.chain().root().orElseThrow().getSubjectX500Principal().getName());
        assertTrue(second.aliases().contains("dev-ca"));
        byte[] signature = second.signRaw("data".getBytes(), es256, SignatureAlgorithm.ES256);
        assertEquals(64, signature.length, "ES256 concatenated R||S");
    }

    /**
     * F-10: the dev-mode keystore holds private keys, so it is created rw------- whatever the umask (the JVM cannot set
     * its own; the test first shows the umask in force would leave a plain file readable by group or others, as 022
     * does), and a keystore written by an older release with rw-r--r-- becomes rw------- when dev mode adds a key to it.
     */
    @Test
    void theDevModeKeystoreIsOwnerOnlyUnderAPermissiveUmask() throws Exception {
        Path keys = Files.createDirectories(dir.resolve("perm"));
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.getFileStore(keys).supportsFileAttributeView(java.nio.file.attribute.PosixFileAttributeView.class),
                "POSIX permissions");
        Path plain = keys.resolve("plain.bin");
        Files.write(plain, new byte[] {1});
        java.util.Set<java.nio.file.attribute.PosixFilePermission> umasked = Files.getPosixFilePermissions(plain);
        org.junit.jupiter.api.Assumptions.assumeTrue(umasked.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ)
                || umasked.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ), "a umask such as 022 that leaves new files readable: " + umasked);
        java.util.Set<java.nio.file.attribute.PosixFilePermission> ownerOnly = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");

        Path file = keys.resolve("issuer.p12");
        X509FileKeyProviders.open(props(file, true, List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a"))));
        assertEquals(ownerOnly, Files.getPosixFilePermissions(file), "created owner-only");

        Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")); // as an older release left it
        JcaKeyProvider grown = X509FileKeyProviders.open(props(file, true, List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a"),
                new X509FileProperties.KeySpec("b", "EdDSA", "CN=b"))));
        assertEquals(ownerOnly, Files.getPosixFilePermissions(file), "replaced owner-only");
        assertTrue(grown.aliases().containsAll(List.of("a", "b")));
        assertTrue(X509FileKeyProviders.open(props(file, false, List.of(new X509FileProperties.KeySpec("b", "EdDSA", "CN=b")))).aliases().contains("b"),
                "the replaced keystore loads");
        try (var listing = Files.list(keys)) {
            assertEquals(List.of("issuer.p12", "plain.bin"), listing.map(p -> p.getFileName().toString()).sorted().toList(), "no temporary file left");
        }
    }

    @Test
    void productionRefusesMissingFilesAndMissingKeys() {
        Path file = dir.resolve("prod.p12");
        assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(file, false, List.of())));
        X509FileKeyProviders.open(props(file, true, List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a"))));
        SigningException e = assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(file, false,
                List.of(new X509FileProperties.KeySpec("a", "ES256", "CN=a"), new X509FileProperties.KeySpec("b", "RS256", "CN=b")))));
        assertTrue(e.getMessage().contains("[b]"));
        assertThrows(SigningException.class, () -> X509FileKeyProviders.open(new X509FileProperties(true, "x509-file", null, "pw", true, List.of(), "p", "dev-ca", "CN=Inji Certify Dev CA")));
        assertThrows(SigningException.class, () -> X509FileKeyProviders.open(props(dir.resolve("x.p12"), true, List.of(new X509FileProperties.KeySpec("z", "HS256", "CN=z")))));
    }
}
