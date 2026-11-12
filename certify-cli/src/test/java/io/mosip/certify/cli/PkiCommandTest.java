package io.mosip.certify.cli;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.Csr;
import io.mosip.certify.pki.Pem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Drives the {@code pki}, {@code keys csr} and {@code keys import} commands end to end in a temporary directory. Every
 * object a command writes is judged by {@link AnnexBValidator} and, where OpenSSL is on the PATH, by
 * {@code openssl verify -x509_strict -crl_check}: an independent implementation of RFC 5280 path and CRL validation.
 * A missing OpenSSL skips locally and fails under {@code CI}, as the {@code certify-pki} interop tests do.
 */
class PkiCommandTest {

    private static final String PASSWORD = "s3cret";

    @TempDir Path dir;
    ByteArrayOutputStream out;
    ByteArrayOutputStream err;

    @BeforeEach
    void setUp() {
        out = new ByteArrayOutputStream();
        err = new ByteArrayOutputStream();
    }

    // ------------------------------------------------------------------ harness

    int run(String... args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            return new CommandLine(new CertifyCli()).execute(args);
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    void reset() {
        out.reset();
        err.reset();
    }

    Path path(String name) {
        return dir.resolve(name);
    }

    /** An offline IACA in {@code iaca.p12}, with its certificate in {@code iaca.pem}, as the recipes create it. */
    Path iaca() throws Exception {
        int code = run("pki", "iaca", "create", "-k", path("iaca.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--state", "Karnataka", "--org", "Lorem Ipsum Demo",
                "--cn", "Lorem Ipsum Demo IACA", "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl",
                "--validity-years", "10");
        assertEquals(0, code, stderr());
        Files.writeString(path("iaca.pem"), stdout(), StandardCharsets.US_ASCII);
        reset();
        return path("iaca.p12");
    }

    /** `pki dsc issue --generate` into issuer.p12, chain [DSC, IACA] in dsc-chain.pem. */
    X509Certificate dsc(String alias) {
        int code = run("pki", "dsc", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--generate", "-k", path("issuer.p12").toString(), "-P", PASSWORD, "--alias", alias,
                "--cn", "Lorem Ipsum Demo DSC", "--out", path("dsc-chain.pem").toString());
        assertEquals(0, code, stderr());
        reset();
        return Pem.readCertificates(readString("dsc-chain.pem")).get(0);
    }

    String readString(String name) {
        try {
            return Files.readString(path(name), StandardCharsets.US_ASCII);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    List<X509Certificate> chain(String name) {
        return Pem.readCertificates(readString(name));
    }

    // ------------------------------------------------------------------ iaca create

    @Test
    void iacaCreatePrintsTheCertificateAndFingerprintAndRefusesToOverwriteTheAlias() throws Exception {
        iaca();
        String pem = readString("iaca.pem");
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"), pem);
        X509Certificate iaca = Pem.readCertificate(pem);
        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca), "the CLI output is an Annex B IACA");
        assertEquals("IN", new javax.naming.ldap.LdapName(iaca.getSubjectX500Principal().getName())
                .getRdns().stream().filter(r -> r.getType().equals("C")).findFirst().orElseThrow().getValue());

        assertEquals(0, run("pki", "check", "--chain", path("iaca.pem").toString(), "--profile", "iaca"), stderr());
        assertTrue(stdout().startsWith("ok iaca"), stdout());
        reset();

        assertEquals(2, run("pki", "iaca", "create", "-k", path("iaca.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA", "--issuer-alt-uri", "https://a.test",
                "--crl-uri", "https://a.test/iaca.crl"), "an existing alias is never replaced");
        assertTrue(stderr().contains("alias already exists"), stderr());
    }

    @Test
    void iacaCreatePrintsTheSha256FingerprintOnStderrOnly() {
        int code = run("pki", "iaca", "create", "-k", path("iaca.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/iaca.crl");
        assertEquals(0, code, stderr());
        assertTrue(stderr().contains("sha256="), stderr());
        String fingerprint = stderr().lines().filter(l -> l.startsWith("sha256=")).findFirst().orElseThrow()
                .substring("sha256=".length());
        assertTrue(fingerprint.matches("[0-9a-f]{64}"), fingerprint);
        X509Certificate iaca = Pem.readCertificate(stdout());
        assertEquals(fingerprint, PkiFiles.sha256(iaca), "the printed fingerprint is the certificate's");
    }

    // ------------------------------------------------------------------ dsc issue

    @Test
    void dscIssueGeneratesAKeyStoresTheChainAndPassesAnnexBAndOpenSsl() throws Exception {
        iaca();
        X509Certificate dsc = dsc("mdl-dsc@2026-11");
        List<X509Certificate> chain = chain("dsc-chain.pem");
        assertEquals(2, chain.size(), "[DSC, IACA]");
        assertEquals(dsc, chain.get(0));
        assertEquals(Pem.readCertificate(readString("iaca.pem")), chain.get(1));

        X509Certificate iaca = chain.get(1);
        assertEquals(List.of(), AnnexBValidator.validateIaca(iaca));
        assertEquals(List.of(), AnnexBValidator.validateDs(dsc, iaca));
        // the key landed in the issuer keystore with the chain, so the runtime can sign with it
        assertEquals(0, run("keys", "list", "-k", path("issuer.p12").toString(), "-p", PASSWORD));
        assertTrue(stdout().contains("mdl-dsc@2026-11\tES256"), stdout());
        reset();

        assertEquals(0, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "mdoc-dsc"));
        assertTrue(stdout().contains("ok mdoc-dsc"), stdout());

        requireOpenSsl();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--crl-number", "1", "--out", path("iaca.crl").toString()));
        reset();
        String verified = openssl("verify", "-x509_strict", "-crl_check",
                "-CAfile", path("iaca.pem").toString(), "-CRLfile", path("iaca.crl").toString(),
                dscFile());
        assertTrue(verified.contains(": OK"), verified);
    }

    /** The DSC alone, first block of the chain, for {@code openssl verify}. */
    String dscFile() throws Exception {
        Path file = path("dsc.pem");
        Files.writeString(file, Pem.writeCertificate(Pem.readCertificates(readString("dsc-chain.pem")).get(0)),
                StandardCharsets.US_ASCII);
        return file.toString();
    }

    @Test
    void aCsrMadeByOpenSslIsSignedIntoADocumentSigner() throws Exception {
        iaca();
        requireOpenSsl();
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path("ec.pem").toString());
        openssl("req", "-new", "-key", path("ec.pem").toString(), "-subj", "/C=IN/CN=Lorem Ipsum Demo DSC 2026",
                "-out", path("dsc.csr").toString());
        Csr request = Csr.parsePem(readString("dsc.csr"));

        int code = run("pki", "dsc", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--csr", path("dsc.csr").toString(), "--out", path("csr-chain.pem").toString());
        assertEquals(0, code, stderr());
        List<X509Certificate> chain = chain("csr-chain.pem");
        assertEquals(List.of(), AnnexBValidator.validateDs(chain.get(0), chain.get(1)));
        assertEquals(request.publicKey(), chain.get(0).getPublicKey(), "the CSR's key is the key certified");
        assertTrue(stdout().contains("subject=CN=Lorem Ipsum Demo DSC 2026,ST=Karnataka,C=IN"), stdout());
        assertEquals(0, run("pki", "check", "--chain", path("csr-chain.pem").toString(), "--profile", "mdoc-dsc"));
        assertTrue(stdout().contains("ok mdoc-dsc"), stdout());
    }

    @Test
    void aCsrWithoutACommonNameTakesTheConfiguredDefault() throws Exception {
        iaca();
        requireOpenSsl();
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path("ec.pem").toString());
        openssl("req", "-new", "-key", path("ec.pem").toString(), "-subj", "/C=IN/CN=From The Request",
                "-out", path("dsc.csr").toString());
        assertEquals(0, run("pki", "dsc", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--csr", path("dsc.csr").toString(), "--cn", "Lorem Ipsum Demo DSC",
                "--out", path("csr-chain.pem").toString()), stderr());
        X509Certificate dsc = chain("csr-chain.pem").get(0);
        assertTrue(dsc.getSubjectX500Principal().getName().contains("CN=Lorem Ipsum Demo DSC"),
                dsc.getSubjectX500Principal().getName());
    }

    // ------------------------------------------------------------------ rotation

    @Test
    void rotateAddsAVersionedAliasKeepsTheOldOneAndRefusesASecondRotationThisMonth() throws Exception {
        iaca();
        dsc("mdl-dsc@2025-01");
        int code = run("pki", "dsc", "rotate", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "-k", path("issuer.p12").toString(), "-P", PASSWORD, "--alias-prefix", "mdl-dsc",
                "--out", path("rotated-chain.pem").toString());
        assertEquals(0, code, stderr());
        String rotatedAlias = java.time.YearMonth.now(java.time.ZoneOffset.UTC) + "";
        assertTrue(stdout().contains("alias=mdl-dsc@" + rotatedAlias), stdout());
        assertEquals(List.of(), AnnexBValidator.validateDs(
                chain("rotated-chain.pem").get(0), chain("rotated-chain.pem").get(1)));

        reset();
        assertEquals(0, run("keys", "list", "-k", path("issuer.p12").toString(), "-p", PASSWORD));
        assertTrue(stdout().contains("mdl-dsc@2025-01") && stdout().contains("mdl-dsc@" + rotatedAlias),
                "both the old and the new Document Signer stay in the keystore: " + stdout());
        reset();
        assertEquals(2, run("pki", "dsc", "rotate", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "-k", path("issuer.p12").toString(), "-P", PASSWORD, "--alias-prefix", "mdl-dsc"),
                "the same month's alias is refused");
        assertTrue(stderr().contains("already exists"), stderr());
    }

    // ------------------------------------------------------------------ crl

    @Test
    void crlNumberMustIncreaseAndTheWatermarkSurvivesAForce() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        assertEquals(0, crl("1", null), stderr());
        assertTrue(stdout().contains("crlNumber=1"), stdout());
        assertEquals("1\n", readString("iaca.p12.crlnumber"));

        reset();
        assertEquals(2, crl("1", null), "a repeated number is refused");
        assertTrue(stderr().contains("does not increase"), stderr());

        reset();
        assertEquals(0, crl("2", null), stderr());
        assertEquals("2\n", readString("iaca.p12.crlnumber"));

        reset();
        assertEquals(0, crl("1", "--force"), "the operator can publish out of order on purpose");
        assertTrue(stderr().contains("warning:"), stderr());
        assertEquals("2\n", readString("iaca.p12.crlnumber"), "a forced lower number does not lower the watermark");

        reset();
        assertEquals(2, crl("2", null), "the watermark still guards the next publication");
    }

    int crl(String number, String extra) {
        List<String> args = new ArrayList<>(List.of("pki", "crl", "issue", "--iaca", path("iaca.p12").toString(),
                "-p", PASSWORD, "--crl-number", number, "--out", path("iaca.crl").toString()));
        if (extra != null) {
            args.add(extra);
        }
        return run(args.toArray(String[]::new));
    }

    @Test
    void aRevokedDocumentSignerFailsOpenSslAndTheDerCrlIsRead() throws Exception {
        iaca();
        X509Certificate dsc = dsc("mdl-dsc@2026-11");
        requireOpenSsl();
        String serial = "0x" + dsc.getSerialNumber().toString(16);
        int code = run("pki", "crl", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--revoke", serial, "--crl-number", "1", "--out", path("iaca.der").toString());
        assertEquals(0, code, stderr());
        assertTrue(stdout().contains("revoked=1"), stdout());
        assertEquals(0, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "mdoc-dsc",
                "--crl", path("iaca.der").toString()), stderr());

        Process process = new ProcessBuilder(List.of("openssl", "verify", "-x509_strict", "-crl_check",
                "-CRLfile", path("iaca.der").toString(), "-CAfile", path("iaca.pem").toString(), dscFile()))
                .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS));
        assertEquals(2, process.exitValue(), () -> "a revoked DSC must not verify: " + output);
        assertTrue(output.contains("certificate revoked"), output);
    }

    // ------------------------------------------------------------------ pki check

    @Test
    void checkExitsZeroCleanTwoOnViolationsAndOneOnUsageErrors() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        reset();
        assertEquals(0, run("pki", "check", "--chain", path("iaca.pem").toString(), "--profile", "iaca"));
        assertTrue(stdout().contains("ok iaca"), stdout());

        reset();
        assertEquals(2, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "iaca"));
        assertFalse(stdout().isBlank(), "the violations are printed");
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_")), stdout());

        reset();
        assertEquals(1, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "mdoc-dsc",
                "--iaca", path("iaca.pem").toString(), "--crl", path("iaca.pem").toString()),
                "a certificate is not a CRL: an unreadable input is a usage error");

        // a CRL from another IACA is a profile violation, named by rule
        reset();
        assertEquals(0, run("pki", "iaca", "create", "-k", path("other-iaca.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--cn", "Other Demo IACA", "--issuer-alt-uri", "https://other.example.test",
                "--crl-uri", "https://other.example.test/iaca.crl"));
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", path("other-iaca.p12").toString(), "-p", PASSWORD,
                "--crl-number", "1", "--out", path("other.crl").toString()), stderr());
        reset();
        assertEquals(2, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "mdoc-dsc",
                "--iaca", path("iaca.pem").toString(), "--crl", path("other.crl").toString()));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("CRL_")), stdout());

        reset();
        assertEquals(1, run("pki", "check", "--profile", "iaca"), "a missing --chain is a usage error");
        assertEquals(1, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "nonsense"));
        assertEquals(1, run("pki", "check", "--chain", path("missing.pem").toString(), "--profile", "iaca"));
    }

    @Test
    void aTwoCertificateChainSuppliesItsOwnIaca() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        assertEquals(0, run("pki", "check", "--chain", path("dsc-chain.pem").toString(), "--profile", "mdoc-dsc"));
        assertTrue(stdout().contains("ok mdoc-dsc"), stdout());
    }

    // ------------------------------------------------------------------ keys csr and import

    @Test
    void keysCsrCreatesAValidRequestForAnExistingKey() throws Exception {
        assertEquals(0, run("keys", "generate", "-k", path("keys.p12").toString(), "-p", PASSWORD,
                "--alias", "issuer-es256", "--alg", "ES256"), stderr());
        reset();
        assertEquals(0, run("keys", "csr", "-k", path("keys.p12").toString(), "-p", PASSWORD,
                "--alias", "issuer-es256", "--cn", "Lorem Ipsum Demo DSC", "--out", path("key.csr").toString()));
        Csr request = Csr.parsePem(readString("key.csr"));
        assertTrue(request.subject().getName().contains("CN=Lorem Ipsum Demo DSC"), request.subject().getName());
    }

    @Test
    void keysImportAddsAnOpenSslKeyAndChainAndRefusesADuplicateAlias() throws Exception {
        requireOpenSsl();
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", path("key.pem").toString(), "-out", path("cert.pem").toString(),
                "-days", "365", "-subj", "/C=IN/CN=Imported DSC");
        openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "200000",
                "-in", path("key.pem").toString(), "-passout", "pass:" + PASSWORD,
                "-out", path("key-enc.pem").toString());

        int code = run("keys", "import", "-k", path("imported.p12").toString(), "-p", PASSWORD,
                "--alias", "imported-plain", "--key", path("key.pem").toString(),
                "--chain", path("cert.pem").toString());
        assertEquals(0, code, stderr());
        assertTrue(stdout().contains("alias=imported-plain"), stdout());
        reset();

        assertEquals(0, run("keys", "import", "-k", path("imported.p12").toString(), "-p", PASSWORD,
                "--alias", "imported-encrypted", "--key", path("key-enc.pem").toString(),
                "--key-password", PASSWORD, "--chain", path("cert.pem").toString()), stderr());
        reset();

        assertEquals(0, run("keys", "list", "-k", path("imported.p12").toString(), "-p", PASSWORD));
        assertTrue(stdout().contains("imported-plain") && stdout().contains("imported-encrypted"), stdout());
        reset();

        assertEquals(2, run("keys", "import", "-k", path("imported.p12").toString(), "-p", PASSWORD,
                "--alias", "imported-plain", "--key", path("key.pem").toString(),
                "--chain", path("cert.pem").toString()), "an existing alias is not replaced");
        assertTrue(stderr().contains("alias already exists"), stderr());
        reset();

        // a key from another pair does not match the certificate
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", path("other-key.pem").toString(), "-out", path("other-cert.pem").toString(),
                "-days", "365", "-subj", "/CN=Other");
        assertEquals(2, run("keys", "import", "-k", path("mismatch.p12").toString(), "-p", PASSWORD,
                "--alias", "mismatch", "--key", path("other-key.pem").toString(),
                "--chain", path("cert.pem").toString()));
        assertTrue(stderr().contains("does not belong"), stderr());
    }

    // ------------------------------------------------------------------ pem IACA

    @Test
    void anIacaWrittenAsPemStandsInForTheKeystore() throws Exception {
        int code = run("pki", "iaca", "create", "-k", path("iaca-pem.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/iaca.crl",
                "--pem-out", path("iaca-key.pem").toString());
        assertEquals(0, code, stderr());
        assertFalse(Files.exists(path("iaca-pem.p12")), "--pem-out replaces the PKCS#12 file");
        String keyPem = readString("iaca-key.pem");
        assertTrue(keyPem.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), keyPem);
        assertTrue(keyPem.contains("-----BEGIN CERTIFICATE-----"), "the certificate travels with the key");
        Files.writeString(path("iaca.pem"), stdout(), StandardCharsets.US_ASCII);

        assertEquals(0, run("pki", "dsc", "issue", "--iaca", path("iaca-key.pem").toString(), "-p", PASSWORD,
                "--generate", "-k", path("issuer.pem.p12").toString(), "-P", PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", path("pem-chain.pem").toString()), stderr());
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", path("iaca-key.pem").toString(), "-p", PASSWORD,
                "--crl-number", "1", "--out", path("pem-iaca.crl").toString()), stderr());
        reset();
        assertEquals(0, run("pki", "check", "--chain", path("pem-chain.pem").toString(), "--profile", "mdoc-dsc",
                "--iaca", path("iaca.pem").toString(), "--crl", path("pem-iaca.crl").toString()), stderr());
        assertTrue(stdout().contains("ok mdoc-dsc crl"), stdout());
        assertEquals(List.of(), AnnexBValidator.validateIaca(Pem.readCertificate(readString("iaca.pem"))));
    }

    // ------------------------------------------------------------------ openssl

    /** Skip when OpenSSL is absent, unless this is CI, where an unverified build is not acceptable. */
    static void requireOpenSsl() {
        try {
            Process process = new ProcessBuilder("openssl", "version").redirectErrorStream(true).start();
            assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            if (process.exitValue() == 0) {
                return;
            }
        } catch (Exception e) {
            // fall through to the skip or the CI failure
        }
        if (System.getenv("CI") != null) {
            fail("openssl is not on the PATH and CI is set: the independent verifier must run");
        }
        org.junit.jupiter.api.Assumptions.abort("openssl is not on the PATH");
    }

    static String openssl(String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of("openssl"));
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "openssl did not finish: " + command);
        assertEquals(0, process.exitValue(), () -> String.join(" ", command) + ": " + output);
        return output;
    }

    @Test
    void durationsCrossCheckTheAnnexBLimits() throws Exception {
        // the CLI refuses values the profile cannot represent, before any key is generated
        assertEquals(2, run("pki", "iaca", "create", "-k", path("bad.p12").toString(), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl",
                "--validity-years", "21"));
        assertTrue(stderr().contains("1 to 20"), stderr());
        reset();
        iaca();
        assertEquals(2, run("pki", "dsc", "issue", "--iaca", path("iaca.p12").toString(), "-p", PASSWORD,
                "--generate", "-k", path("issuer.p12").toString(), "-P", PASSWORD, "--alias", "too-long",
                "--validity-days", "500",
                "--out", path("too-long.pem").toString()));
        assertTrue(stderr().contains("1 to 457"), stderr());
    }
}
