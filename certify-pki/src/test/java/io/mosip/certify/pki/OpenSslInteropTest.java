package io.mosip.certify.pki;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * OpenSSL is an independent implementation of X.509 path validation and CRL checking; {@code -x509_strict} turns on the
 * RFC 5280 strictness checks and {@code -crl_check} makes the CRL part of the decision.
 *
 * <p>It is also the independent implementation of encrypted PKCS#8: a key OpenSSL encrypts must be readable here, and
 * a key this library encrypts must be readable by {@code openssl pkey}, because the offline IACA key (D3) moves between
 * the two.
 *
 * <p>Where OpenSSL is missing the tests skip locally and fail in CI ({@code CI} set), so a build that cannot run the
 * independent verifier is never green.
 */
class OpenSslInteropTest {

    @Test
    void opensslVerifiesTheDocumentSignerInStrictModeAgainstTheCrl(@TempDir Path directory) throws Exception {
        requireOpenSsl();
        Fixture fixture = new Fixture();
        Path iaca = write(directory, "iaca.pem", Pem.writeCertificate(fixture.iaca));
        Path ds = write(directory, "ds.pem", Pem.writeCertificate(fixture.ds));
        Path crl = write(directory, "crl.pem", Pem.writeCrl(fixture.crl()));

        String output = openssl("verify", "-x509_strict", "-crl_check", "-CRLfile", crl.toString(),
                "-CAfile", iaca.toString(), ds.toString());
        assertTrue(output.contains("OK"), output);

        String revoked = openssl("crl", "-in", crl.toString(), "-CAfile", iaca.toString(), "-noout");
        assertTrue(revoked.contains("verify OK") || revoked.contains("OK"), revoked);
    }

    @Test
    void opensslRefusesARevokedDocumentSigner(@TempDir Path directory) throws Exception {
        requireOpenSsl();
        Fixture fixture = new Fixture();
        Path iaca = write(directory, "iaca.pem", Pem.writeCertificate(fixture.iaca));
        Path ds = write(directory, "ds.pem", Pem.writeCertificate(fixture.ds));
        Path crl = write(directory, "crl.pem", Pem.writeCrl(fixture.crl(fixture.ds.getSerialNumber(),
                java.time.Instant.now())));

        Process process = new ProcessBuilder(List.of("openssl", "verify", "-x509_strict", "-crl_check",
                "-CRLfile", crl.toString(), "-CAfile", iaca.toString(), ds.toString()))
                .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "openssl verify did not finish");
        assertEquals(2, process.exitValue(), () -> "a revoked certificate must not verify: " + output);
        assertTrue(output.contains("certificate revoked"), output);
    }

    /**
     * {@code openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256} output is read with the same password. With
     * OpenSSL's default of 2048 PBKDF2 iterations it is logged as weak; with the {@code -iter 200000} the warning
     * recommends it is read without a warning.
     */
    @Test
    void aKeyOpenSslEncryptsIsReadable(@TempDir Path directory) throws Exception {
        requireOpenSsl();
        Path password = write(directory, "password.txt", new String(PASSWORD) + "\n");
        Path key = directory.resolve("key.pem");
        Path encrypted = directory.resolve("key.enc.pem");
        Path reencrypted = directory.resolve("key.iter.pem");
        Path publicKey = directory.resolve("key.pub.pem");
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key.toString());
        openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-in", key.toString(),
                "-passout", "file:" + password, "-out", encrypted.toString());
        openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "200000",
                "-in", key.toString(), "-passout", "file:" + password, "-out", reencrypted.toString());
        openssl("pkey", "-in", key.toString(), "-pubout", "-out", publicKey.toString());
        java.security.PublicKey expected = Pem.readPublicKey(Files.readString(publicKey, StandardCharsets.US_ASCII));

        String pem = Files.readString(encrypted, StandardCharsets.US_ASCII);
        assertTrue(pem.contains("BEGIN ENCRYPTED PRIVATE KEY"), pem);
        assertTrue(Pem.isEncryptedPrivateKey(pem));
        List<String> warnings = PemTest.warnings(() -> assertSigns(Pem.readPrivateKey(pem, PASSWORD), expected));
        assertEquals(1, warnings.size(), warnings::toString);
        assertTrue(warnings.get(0).contains("(2048 iterations) and cipher aes-256-cbc: fewer than 10000 iterations"),
                warnings.get(0));

        String strong = Files.readString(reencrypted, StandardCharsets.US_ASCII);
        assertEquals(List.of(),
                PemTest.warnings(() -> assertSigns(Pem.readPrivateKey(strong, PASSWORD), expected)));
    }

    /** A key this library encrypts is decrypted by {@code openssl pkey} to the same key pair. */
    @Test
    void openSslDecryptsAKeyThisLibraryEncrypts(@TempDir Path directory) throws Exception {
        requireOpenSsl();
        java.security.KeyPair keyPair = BadCerts.ec(256);
        Path password = write(directory, "password.txt", new String(PASSWORD) + "\n");
        Path encrypted = write(directory, "key.enc.pem", Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), PASSWORD));
        Path decrypted = directory.resolve("key.pem");
        Path publicKey = directory.resolve("key.pub.pem");
        openssl("pkey", "-in", encrypted.toString(), "-passin", "file:" + password, "-out", decrypted.toString());
        openssl("pkey", "-in", encrypted.toString(), "-passin", "file:" + password, "-pubout", "-out", publicKey.toString());

        assertEquals(java.util.HexFormat.of().formatHex(keyPair.getPublic().getEncoded()),
                java.util.HexFormat.of().formatHex(Pem.readPublicKey(
                        Files.readString(publicKey, StandardCharsets.US_ASCII)).getEncoded()),
                "openssl derives the same public key from the decrypted private key");
        assertSigns(Pem.readPrivateKey(Files.readString(decrypted, StandardCharsets.US_ASCII)), keyPair.getPublic());
    }

    /** {@code openssl pkcs8 -topk8 -scrypt} output is refused with the scheme named, not a provider error. */
    @Test
    void anOpenSslScryptKeyIsRefusedByName(@TempDir Path directory) throws Exception {
        requireOpenSsl();
        Path password = write(directory, "password.txt", new String(PASSWORD) + "\n");
        Path key = directory.resolve("key.pem");
        Path encrypted = directory.resolve("key.scrypt.pem");
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key.toString());
        openssl("pkcs8", "-topk8", "-scrypt", "-in", key.toString(), "-passout", "file:" + password,
                "-out", encrypted.toString());

        String pem = Files.readString(encrypted, StandardCharsets.US_ASCII);
        PkiException exception = org.junit.jupiter.api.Assertions.assertThrows(PkiException.class,
                () -> Pem.readPrivateKey(pem, PASSWORD));
        assertTrue(exception.getMessage().startsWith("PEM_KEY_UNSUPPORTED: unsupported PBE scheme"), exception.getMessage());
        assertTrue(exception.getMessage().contains("scrypt"), exception.getMessage());
    }

    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    private static void assertSigns(java.security.PrivateKey privateKey, java.security.PublicKey publicKey)
            throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update("interop".getBytes(StandardCharsets.US_ASCII));
        byte[] signature = signer.sign();
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update("interop".getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(signature), "the private key signs for the public key");
    }

    private static Path write(Path directory, String name, String pem) throws IOException {
        return Files.writeString(directory.resolve(name), pem, StandardCharsets.US_ASCII);
    }

    /** Skip when OpenSSL is absent, unless this is CI, where an unverified build is not acceptable. */
    private static void requireOpenSsl() {
        if (opensslAvailable()) {
            return;
        }
        if (System.getenv("CI") != null) {
            fail("openssl is not on the PATH and CI is set: the independent verifier must run");
        }
        org.junit.jupiter.api.Assumptions.abort("openssl is not on the PATH");
    }

    private static boolean opensslAvailable() {
        try {
            return run(List.of("openssl", "version")) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String openssl(String... arguments) throws Exception {
        List<String> command = new java.util.ArrayList<>();
        command.add("openssl");
        command.addAll(java.util.Arrays.asList(arguments));
        String output = run(command);
        assertTrue(output != null, "openssl did not run");
        return output;
    }

    private static String run(List<String> command) throws Exception {
        Process process;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (IOException e) {
            return null;
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return null;
        }
        assertEquals(0, process.exitValue(), () -> String.join(" ", command) + " said: " + output);
        return output;
    }
}
