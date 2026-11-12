package io.mosip.certify.pki;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509CRL;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * OpenSSL is an independent implementation of X.509 path validation and CRL verification; {@code -x509_strict} turns on
 * the RFC 5280 strictness checks. Skipped when {@code openssl} is not on the PATH.
 */
class OpenSslInteropTest {

    @Test
    void opensslVerifiesTheDocumentSignerInStrictMode(@TempDir Path directory) throws Exception {
        Assumptions.assumeTrue(opensslAvailable(), "openssl is not on the PATH");
        Fixture fixture = new Fixture();
        Path iaca = write(directory, "iaca.pem", Pem.writeCertificate(fixture.iaca));
        Path ds = write(directory, "ds.pem", Pem.writeCertificate(fixture.ds));

        String output = openssl("verify", "-x509_strict", "-CAfile", iaca.toString(), ds.toString());
        assertTrue(output.contains("OK"), output);
    }

    @Test
    void opensslVerifiesTheCrlSignature(@TempDir Path directory) throws Exception {
        Assumptions.assumeTrue(opensslAvailable(), "openssl is not on the PATH");
        Fixture fixture = new Fixture();
        X509CRL crl = fixture.crl();
        Path iaca = write(directory, "iaca.pem", Pem.writeCertificate(fixture.iaca));
        Path crlFile = write(directory, "iaca.crl.pem", Pem.writeCrl(crl));

        String output = openssl("crl", "-in", crlFile.toString(), "-CAfile", iaca.toString(), "-noout");
        assertTrue(output.contains("verify OK") || output.contains("OK"), output);
    }

    private static Path write(Path directory, String name, String pem) throws IOException {
        return Files.writeString(directory.resolve(name), pem, StandardCharsets.US_ASCII);
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
