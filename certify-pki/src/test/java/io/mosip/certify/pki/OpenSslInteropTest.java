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
