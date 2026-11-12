package io.mosip.certify.cli;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.Csr;
import io.mosip.certify.pki.Pem;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Drives the {@code pki}, {@code keys csr} and {@code keys import} commands end to end in a temporary directory. Every
 * object a command writes is judged by {@link AnnexBValidator} and, where OpenSSL is on the PATH, by
 * {@code openssl verify -x509_strict -crl_check}: an independent implementation of RFC 5280 path and CRL validation.
 * A missing OpenSSL skips locally and fails under {@code CI}, as the {@code certify-pki} interop tests do. Permissions
 * and password sources are checked in a child JVM started under {@code umask 022} with a controlled environment.
 */
class PkiCommandTest {

    private static final String PASSWORD = "s3cret";
    private static final String ISSUER_PASSWORD = "issuer-pw";

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
            return CertifyCli.commandLine().execute(args);
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

    String p(String name) {
        return path(name).toString();
    }

    /** An offline IACA in {@code iaca.p12}, with its certificate in {@code iaca.pem}, as the recipes create it. */
    Path iaca() throws Exception {
        return iaca("iaca.p12", "iaca.pem", "Lorem Ipsum Demo IACA");
    }

    Path iaca(String store, String pem, String commonName) throws Exception {
        int code = run("pki", "iaca", "create", "-k", p(store), "-p", PASSWORD,
                "--country", "IN", "--state", "Karnataka", "--org", "Lorem Ipsum Demo",
                "--cn", commonName, "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl",
                "--validity-years", "10");
        assertEquals(0, code, stderr());
        Files.writeString(path(pem), stdout(), StandardCharsets.US_ASCII);
        reset();
        return path(store);
    }

    /** `pki dsc issue --generate` into issuer.p12, chain [DSC, IACA] in {@code chainFile}. */
    X509Certificate dsc(String alias, String chainFile) {
        int code = run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--generate", "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", alias,
                "--cn", "Lorem Ipsum Demo DSC", "--out", p(chainFile));
        assertEquals(0, code, stderr());
        reset();
        return Pem.readCertificates(readString(chainFile)).get(0);
    }

    X509Certificate dsc(String alias) {
        return dsc(alias, "dsc-chain.pem");
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

    /** `pki crl issue` with the given extra arguments, to {@code out}. */
    int crl(String outFile, String... extra) {
        List<String> args = new ArrayList<>(List.of("pki", "crl", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--out", p(outFile)));
        args.addAll(List.of(extra));
        return run(args.toArray(String[]::new));
    }

    X509CRL readCrl(String name) throws Exception {
        return PkiCommand.readCrl(path(name));
    }

    /** The DSC alone, first block of a chain, for {@code openssl verify}. */
    String leafFile(String chainFile, String name) throws Exception {
        Files.writeString(path(name), Pem.writeCertificate(chain(chainFile).get(0)), StandardCharsets.US_ASCII);
        return p(name);
    }

    static byte[] sha256(Path file) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file));
    }

    static String hex(X509Certificate certificate) {
        return "0x" + certificate.getSerialNumber().toString(16);
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

        assertEquals(0, run("pki", "check", "--chain", p("iaca.pem"), "--profile", "iaca"), stderr());
        assertTrue(stdout().startsWith("ok iaca"), stdout());
        reset();

        assertEquals(2, run("pki", "iaca", "create", "-k", p("iaca.p12"), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA", "--issuer-alt-uri", "https://a.test",
                "--crl-uri", "https://a.test/iaca.crl"), "an existing alias is never replaced");
        assertTrue(stderr().contains("alias already exists"), stderr());
    }

    @Test
    void iacaCreatePrintsTheSha256FingerprintOnStderrOnly() {
        int code = run("pki", "iaca", "create", "-k", p("iaca.p12"), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/iaca.crl");
        assertEquals(0, code, stderr());
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
        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD));
        assertTrue(stdout().contains("mdl-dsc@2026-11\tES256"), stdout());
        reset();

        assertEquals(0, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().contains("ok mdoc-dsc"), stdout());
        reset();

        requireOpenSsl();
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        String verified = openssl("verify", "-x509_strict", "-crl_check", "-CAfile", p("iaca.pem"),
                "-CRLfile", p("iaca.crl"), leafFile("dsc-chain.pem", "dsc.pem"));
        assertTrue(verified.contains(": OK"), verified);
    }

    @Test
    void aCsrMadeByOpenSslIsSignedUnderTheOperatorsCn() throws Exception {
        iaca();
        requireOpenSsl();
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("ec.pem"));
        openssl("req", "-new", "-key", p("ec.pem"), "-subj", "/C=XX/O=Requested Org/CN=Requested By The CSR",
                "-out", p("dsc.csr"));
        Csr request = Csr.parsePem(readString("dsc.csr"));

        int code = run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--csr", p("dsc.csr"), "--cn", "Lorem Ipsum Demo DSC 2026", "--out", p("csr-chain.pem"));
        assertEquals(0, code, stderr());
        List<X509Certificate> chain = chain("csr-chain.pem");
        assertEquals(List.of(), AnnexBValidator.validateDs(chain.get(0), chain.get(1)));
        assertEquals(request.publicKey(), chain.get(0).getPublicKey(), "the CSR's key is the key certified");
        assertTrue(stdout().contains("subject=CN=Lorem Ipsum Demo DSC 2026,ST=Karnataka,C=IN"),
                "the subject is the operator's CN under the IACA's C and ST; nothing of the request's: " + stdout());
        assertFalse(chain.get(0).getSubjectX500Principal().getName().contains("Requested"));
        reset();
        assertEquals(0, run("pki", "check", "--chain", p("csr-chain.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().contains("ok mdoc-dsc"), stdout());
    }

    @Test
    void aCsrWithoutAnOperatorCnIsAUsageError() throws Exception {
        iaca();
        requireOpenSsl();
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("ec.pem"));
        openssl("req", "-new", "-key", p("ec.pem"), "-subj", "/C=IN/CN=From The Request", "-out", p("dsc.csr"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--csr", p("dsc.csr"), "--out", p("csr-chain.pem")));
        assertTrue(stderr().contains("--csr needs --cn"), stderr());
        assertFalse(Files.exists(path("csr-chain.pem")));
    }

    @Test
    void aDocumentSignerForTheIacasOwnKeyIsRefused() throws Exception {
        iaca();
        KeyStore store = PkiFiles.read(path("iaca.p12"), PASSWORD.toCharArray());
        PrivateKey iacaKey = PkiFiles.privateKey(store, "iaca", PASSWORD.toCharArray());
        X509Certificate iacaCertificate = PkiFiles.chain(store, "iaca").get(0);
        Files.writeString(path("same.csr"), PkiFiles.csrPem(iacaKey, iacaCertificate.getPublicKey(),
                PkiFiles.commonNameSubject("Same Key")), StandardCharsets.US_ASCII);
        assertEquals(2, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--csr", p("same.csr"), "--cn", "Same Key DSC", "--out", p("same-chain.pem")));
        assertTrue(stderr().contains("DS_KEY_IS_IACA_KEY"), stderr());
        assertFalse(Files.exists(path("same-chain.pem")));
    }

    // ------------------------------------------------------------------ paths and writes

    @Test
    void anOutputThatIsTheKeystoreIsRefusedAndTheKeystoreSurvives() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-10");
        byte[] before = sha256(path("issuer.p12"));

        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("issuer.p12")), "the reported case: --out equal to -k");
        assertTrue(stderr().contains("name the same file"), stderr());
        assertArrayEquals(before, sha256(path("issuer.p12")), "the keystore is untouched");
        reset();

        // the same file named another way, and through a symbolic link
        Files.createDirectories(path("sub"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "x",
                "--out", dir.resolve("sub/../issuer.p12").toString()));
        reset();
        Files.createSymbolicLink(path("link.p12"), path("issuer.p12"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "x", "--out", p("link.p12")));
        reset();
        // -k equal to --iaca would write the Document Signer key into the IACA keystore
        byte[] iacaBefore = sha256(path("iaca.p12"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("iaca.p12"), "-P", PASSWORD, "--alias", "x", "--out", p("x.pem")));
        reset();
        // a CRL written over the IACA keystore
        assertEquals(1, crl("iaca.p12", "--initial", "--overwrite"));
        assertArrayEquals(iacaBefore, sha256(path("iaca.p12")));
        assertArrayEquals(before, sha256(path("issuer.p12")));
        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD), stderr());
        assertTrue(stdout().contains("mdl-dsc@2026-10") && !stdout().contains("mdl-dsc@2026-11"), stdout());
    }

    @Test
    void anExistingOutputIsReplacedOnlyWithOverwrite() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-10");
        byte[] before = sha256(path("dsc-chain.pem"));
        assertEquals(2, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("dsc-chain.pem")));
        assertTrue(stderr().contains("--overwrite"), stderr());
        assertArrayEquals(before, sha256(path("dsc-chain.pem")));
        reset();
        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD));
        assertFalse(stdout().contains("mdl-dsc@2026-11"), "refused before the keystore was touched: " + stdout());
        reset();
        assertEquals(0, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("dsc-chain.pem"), "--overwrite"), stderr());
        assertFalse(java.util.Arrays.equals(before, sha256(path("dsc-chain.pem"))));

        reset();
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        reset();
        assertEquals(2, crl("iaca.crl"), "the previous CRL is not replaced silently");
        assertTrue(stderr().contains("--overwrite"), stderr());
        reset();
        assertEquals(0, crl("iaca.crl", "--overwrite"), stderr());
        assertTrue(stdout().contains("crlNumber=2"), stdout());

        reset();
        assertEquals(2, run("pki", "iaca", "create", "--pem-out", p("iaca.pem"), "-p", PASSWORD, "--country", "IN",
                "--cn", "Other", "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl"),
                "--pem-out never replaces a file");
    }

    @Test
    void writesAreAtomicAndLeaveNoTemporaryFiles() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        try (var files = Files.list(dir)) {
            List<String> names = files.map(f -> f.getFileName().toString()).sorted().toList();
            assertTrue(names.stream().noneMatch(n -> n.endsWith(".tmp")), names.toString());
            assertTrue(names.contains("issuer.p12.lock") && names.contains("iaca.p12.crlstate.json.lock"),
                    "stable lock files next to the files they guard: " + names);
        }
    }

    // ------------------------------------------------------------------ rotation

    @Test
    void rotateAddsVersionedAliasesWithASameMonthSuffixAndKeepsTheOldOnes() throws Exception {
        iaca();
        dsc("mdl-dsc@2025-01");
        String month = YearMonth.now(ZoneOffset.UTC).toString();
        assertEquals(0, rotate("rotated-1.pem"), stderr());
        assertTrue(stdout().contains("alias=mdl-dsc@" + month + "\n"), stdout());
        assertTrue(stdout().contains("current=mdl-dsc@" + month + "\n"), stdout());
        assertTrue(stderr().contains("x509-file:mdl-dsc resolves to mdl-dsc@" + month), stderr());
        assertEquals(List.of(), AnnexBValidator.validateDs(chain("rotated-1.pem").get(0), chain("rotated-1.pem").get(1)));
        reset();

        // an emergency rotation in the same month takes the next suffix ...
        assertEquals(0, rotate("rotated-2.pem"), stderr());
        assertTrue(stdout().contains("alias=mdl-dsc@" + month + ".2\n"), stdout());
        assertTrue(stdout().contains("current=mdl-dsc@" + month + ".2\n"), "the newest valid notBefore: " + stdout());
        reset();
        // ... or the one the operator names, which must be free
        assertEquals(0, rotate("rotated-5.pem", "--suffix", "5"), stderr());
        assertTrue(stdout().contains("alias=mdl-dsc@" + month + ".5\n"), stdout());
        reset();
        assertEquals(2, rotate("rotated-5b.pem", "--suffix", "5"));
        assertTrue(stderr().contains("already exists"), stderr());
        reset();
        assertEquals(0, rotate("rotated-6.pem"), stderr());
        assertTrue(stdout().contains("alias=mdl-dsc@" + month + ".6\n"), "after the highest suffix: " + stdout());
        reset();
        assertEquals(1, rotate("rotated-x.pem", "--suffix", "1"), "suffixes start at 2");
        assertEquals(1, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD, "-k", p("issuer.p12"),
                "-P", ISSUER_PASSWORD, "--alias-prefix", "bad@prefix"), "an @ would break the version split");
        reset();

        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD));
        for (String alias : List.of("mdl-dsc@2025-01", "mdl-dsc@" + month, "mdl-dsc@" + month + ".2",
                "mdl-dsc@" + month + ".5", "mdl-dsc@" + month + ".6")) {
            assertTrue(stdout().contains(alias + "\t"), alias + " stays in the keystore: " + stdout());
        }
    }

    @Test
    void theRotationRulePicksTheValidEntryWithTheNewestNotBefore() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-01");
        Thread.sleep(1100);
        dsc("mdl-dsc@2026-02", "second.pem");
        KeyStore store = PkiFiles.read(path("issuer.p12"), ISSUER_PASSWORD.toCharArray());
        Instant now = Instant.now();
        assertEquals("mdl-dsc@2026-02", PkiCommand.Rotation.current(store, "mdl-dsc", now).orElseThrow());
        Instant beforeSecond = chain("second.pem").get(0).getNotBefore().toInstant().minusSeconds(1);
        assertEquals("mdl-dsc@2026-01", PkiCommand.Rotation.current(store, "mdl-dsc", beforeSecond).orElseThrow(),
                "an entry not yet valid is never chosen");
        assertTrue(PkiCommand.Rotation.current(store, "mdl-dsc", now.plus(500, ChronoUnit.DAYS)).isEmpty(),
                "an expired entry is never chosen");
        assertTrue(PkiCommand.Rotation.current(store, "other", now).isEmpty());
    }

    int rotate(String outFile, String... extra) {
        List<String> args = new ArrayList<>(List.of("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias-prefix", "mdl-dsc", "--out", p(outFile)));
        args.addAll(List.of(extra));
        return run(args.toArray(String[]::new));
    }

    // ------------------------------------------------------------------ crl: numbers and the inventory

    @Test
    void aRevocationStaysInEveryLaterCrlWithItsOriginalDate() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10", "revoked-chain.pem");
        X509Certificate kept = dsc("mdl-dsc@2026-11", "kept-chain.pem");
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        assertTrue(stdout().contains("crlNumber=1\n") && stdout().contains("revoked=0\n"), stdout());
        reset();
        assertEquals(0, crl("crl-2.pem", "--revoke", hex(revoked)), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("newlyRevoked=1\n"), stdout());
        reset();
        Thread.sleep(1100);
        assertEquals(0, crl("crl-3.pem"), "no --revoke this time: " + stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("revoked=1\n"), stdout());

        X509CRLEntry first = readCrl("crl-2.pem").getRevokedCertificate(revoked);
        X509CRLEntry later = readCrl("crl-3.pem").getRevokedCertificate(revoked);
        assertNotNull(later, "CRL n+1 still revokes what CRL n revoked");
        assertEquals(first.getRevocationDate(), later.getRevocationDate(), "the original revocation date");
        assertTrue(readCrl("crl-3.pem").getThisUpdate().after(later.getRevocationDate()));
        assertNull(readCrl("crl-3.pem").getRevokedCertificate(kept));
        assertEquals(BigInteger.valueOf(3), CrlState.crlNumber(readCrl("crl-3.pem")));
        reset();
        // revoking it again keeps the first date
        assertEquals(0, crl("crl-4.pem", "--revoke", hex(revoked)), stderr());
        assertTrue(stderr().contains("already revoked since"), stderr());
        assertEquals(first.getRevocationDate(), readCrl("crl-4.pem").getRevokedCertificate(revoked).getRevocationDate());

        requireOpenSsl();
        String revokedPem = leafFile("revoked-chain.pem", "revoked.pem");
        OpenSsl result = opensslResult("verify", "-x509_strict", "-crl_check", "-CAfile", p("iaca.pem"),
                "-CRLfile", p("crl-3.pem"), revokedPem);
        assertEquals(2, result.code(), () -> "a DSC revoked in CRL 2 must fail under CRL 3: " + result.output());
        assertTrue(result.output().contains("error 23") && result.output().contains("certificate revoked"),
                result.output());
        String ok = openssl("verify", "-x509_strict", "-crl_check", "-CAfile", p("iaca.pem"), "-CRLfile",
                p("crl-3.pem"), leafFile("kept-chain.pem", "kept.pem"));
        assertTrue(ok.contains(": OK"), ok);
    }

    @Test
    void crlNumbersOnlyIncreaseAndForceNeverGoesBack() throws Exception {
        iaca();
        assertEquals(2, crl("iaca.crl"), "no inventory, no base CRL, no --initial: a CRL would drop revocations");
        assertTrue(stderr().contains("--base-crl") && stderr().contains("--initial"), stderr());
        assertFalse(Files.exists(path("iaca.crl")));
        reset();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        assertTrue(stdout().contains("crlNumber=1\n"), stdout());
        reset();
        assertEquals(2, crl("crl-1b.pem", "--initial"), "--initial is only for the first CRL");
        reset();
        assertEquals(2, crl("crl-x.pem", "--crl-number", "1"), "a repeated number is refused");
        assertTrue(stderr().contains("does not increase"), stderr());
        reset();
        assertEquals(2, crl("crl-x.pem", "--crl-number", "1", "--force"), "--force never reuses a recorded number");
        assertTrue(stderr().contains("--force is for an IACA without"), stderr());
        reset();
        assertEquals(0, crl("crl-7.pem", "--crl-number", "7"), stderr());
        reset();
        assertEquals(0, crl("crl-8.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=8\n"), "the default is the last + 1: " + stdout());
        reset();
        assertEquals(1, crl("crl-y.pem", "--crl-number", "seven"));
        assertEquals(1, crl("crl-y.pem", "--revoke", "not-hex"));
    }

    @Test
    void aLostInventoryIsRebuiltFromTheLastPublishedCrl() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("crl-1.pem", "--initial", "--revoke", hex(revoked)), stderr());
        assertEquals(0, crl("crl-2.pem"), stderr());
        Instant date = readCrl("crl-2.pem").getRevokedCertificate(revoked).getRevocationDate().toInstant();
        Files.delete(path("iaca.p12.crlstate.json"));
        reset();

        assertEquals(2, crl("crl-3.pem"), "the inventory is gone: refuse rather than drop the revocation");
        reset();
        assertEquals(0, crl("crl-3.pem", "--base-crl", p("crl-2.pem")), stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("revoked=1\n"), stdout());
        assertEquals(date, readCrl("crl-3.pem").getRevokedCertificate(revoked).getRevocationDate().toInstant());
        reset();
        assertEquals(0, crl("crl-4.pem"), "the inventory exists again: " + stderr());
        assertNotNull(readCrl("crl-4.pem").getRevokedCertificate(revoked));

        // a CRL of another IACA is not imported
        iaca("other.p12", "other.pem", "Other Demo IACA");
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("other.p12"), "-p", PASSWORD, "--initial",
                "--out", p("other.crl")), stderr());
        Files.delete(path("iaca.p12.crlstate.json"));
        reset();
        assertEquals(2, crl("crl-5.pem", "--base-crl", p("other.crl")));
        assertTrue(stderr().contains("not by this IACA"), stderr());
    }

    @Test
    void forceRecoversWithoutAnyCrlButNeedsAnExplicitNumber() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(1, crl("crl.pem", "--force"), "--force needs --crl-number");
        reset();
        assertEquals(0, crl("crl.pem", "--force", "--crl-number", "40", "--revoke", hex(revoked)), stderr());
        assertTrue(stderr().contains("warning: --force"), stderr());
        assertTrue(stdout().contains("crlNumber=40\n"), stdout());
        reset();
        assertEquals(0, crl("crl-41.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=41\n") && stdout().contains("revoked=1\n"), stdout());
    }

    @Test
    void anEmptyOrCorruptInventoryIsAHardError() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        Files.writeString(path("iaca.p12.crlstate.json"), "");
        reset();
        assertEquals(2, crl("crl-2.pem"));
        assertTrue(stderr().contains("is corrupt") && stderr().contains("empty"), stderr());
        Files.writeString(path("iaca.p12.crlstate.json"), "{\"format\":\"certify-cli/crl-state/1\",\"iacas\":{\"zz\":1}}");
        reset();
        assertEquals(2, crl("crl-2.pem", "--initial"), "--initial does not paper over a corrupt file");
        assertTrue(stderr().contains("is corrupt"), stderr());
        assertFalse(Files.exists(path("crl-2.pem")));
    }

    @Test
    void theNumberIsReservedBeforeTheCrlIsExposed() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "needs POSIX permissions to make a directory read-only");
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        Path readOnly = Files.createDirectory(path("published"));
        Files.setPosixFilePermissions(readOnly, PosixFilePermissions.fromString("r-x------"));
        try {
            assumeTrue(!Files.isWritable(readOnly), "running as a user who can write anywhere");
            reset();
            // the state is written, then the CRL cannot be: the simulated failure between the two writes
            assertEquals(2, crl("published/crl-2.pem", "--revoke", hex(revoked)));
            assertTrue(stderr().contains("cannot write the CRL"), stderr());
        } finally {
            Files.setPosixFilePermissions(readOnly, PosixFilePermissions.fromString("rwx------"));
        }
        assertFalse(Files.exists(path("published/crl-2.pem")), "no CRL was exposed");
        CrlState state = CrlState.read(path("iaca.p12.crlstate.json"));
        CrlState.Inventory inventory = state.inventory(CrlState.keyId(Pem.readCertificate(readString("iaca.pem"))));
        assertEquals(BigInteger.TWO, inventory.lastCrlNumber(), "number 2 was reserved before the write");
        assertTrue(inventory.isRevoked(revoked.getSerialNumber()), "the revocation was recorded before the write");
        reset();
        assertEquals(0, crl("crl-3.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=3\n"), "a gap, never a reused number: " + stdout());
        assertNotNull(readCrl("crl-3.pem").getRevokedCertificate(revoked));
    }

    @Test
    void concurrentCrlIssuanceYieldsDistinctIncreasingNumbers() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        PrintStream sink = new PrintStream(OutputStream.nullOutputStream());
        System.setOut(sink);
        System.setErr(sink);
        List<Future<Integer>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String file = p("concurrent-" + i + ".pem");
                Callable<Integer> task = () -> {
                    start.await();
                    return CertifyCli.commandLine().execute("pki", "crl", "issue", "--iaca", p("iaca.p12"),
                            "-p", PASSWORD, "--out", file);
                };
                results.add(pool.submit(task));
            }
            start.countDown();
            for (Future<Integer> result : results) {
                assertEquals(0, result.get(120, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
        Set<BigInteger> numbers = new TreeSet<>();
        for (int i = 0; i < threads; i++) {
            numbers.add(CrlState.crlNumber(readCrl("concurrent-" + i + ".pem")));
        }
        Set<BigInteger> expected = new TreeSet<>();
        for (int n = 2; n <= threads + 1; n++) {
            expected.add(BigInteger.valueOf(n));
        }
        assertEquals(expected, numbers, "every CRL got its own number, none repeated or skipped");
        assertEquals(BigInteger.valueOf(threads + 1), CrlState.read(path("iaca.p12.crlstate.json"))
                .inventory(CrlState.keyId(Pem.readCertificate(readString("iaca.pem")))).lastCrlNumber());
    }

    @Test
    void thePkcs12AndPemFormsOfOneIacaShareOneInventory() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("crl-1.pem", "--initial", "--revoke", hex(revoked)), stderr());
        // the same IACA as an encrypted PEM, as --pem-out would have written it
        KeyStore store = PkiFiles.read(path("iaca.p12"), PASSWORD.toCharArray());
        Files.writeString(path("iaca-key.pem"), Pem.writeEncryptedPrivateKey(
                PkiFiles.privateKey(store, "iaca", PASSWORD.toCharArray()), PASSWORD.toCharArray())
                + Pem.writeCertificate(PkiFiles.chain(store, "iaca").get(0)), StandardCharsets.US_ASCII);
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("iaca-key.pem"), "-p", PASSWORD,
                "--out", p("crl-2.pem")), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("state=" + p("iaca.p12.crlstate.json")),
                stdout());
        assertNotNull(readCrl("crl-2.pem").getRevokedCertificate(revoked));
        assertFalse(Files.exists(path("iaca-key.pem.crlstate.json")));
    }

    @Test
    void aRevokedDocumentSignerIsReportedByCheckAndOpenSslAndTheDerCrlIsRead() throws Exception {
        iaca();
        X509Certificate dsc = dsc("mdl-dsc@2026-11");
        requireOpenSsl();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--initial",
                "--revoke", hex(dsc), "--out", p("iaca.der")), stderr());
        assertTrue(stdout().contains("revoked=1"), stdout());
        reset();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--crl", p("iaca.der")), stderr());
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_REVOKED\t")), stdout());

        OpenSsl result = opensslResult("verify", "-x509_strict", "-crl_check", "-CRLfile", p("iaca.der"),
                "-CAfile", p("iaca.pem"), leafFile("dsc-chain.pem", "dsc.pem"));
        assertEquals(2, result.code(), () -> "a revoked DSC must not verify: " + result.output());
        assertTrue(result.output().contains("certificate revoked"), result.output());
    }

    // ------------------------------------------------------------------ pki check

    @Test
    void checkExitsZeroCleanTwoOnFindingsAndOneOnUsageErrors() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        assertEquals(0, run("pki", "check", "--chain", p("iaca.pem"), "--profile", "iaca"));
        assertTrue(stdout().contains("ok iaca"), stdout());

        reset();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "iaca"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_")), stdout());

        reset();
        assertEquals(1, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--iaca", p("iaca.pem"), "--crl", p("iaca.pem")),
                "a certificate is not a CRL: an unreadable input is a usage error");

        // a CRL from another IACA is a profile violation, named by rule
        iaca("other-iaca.p12", "other-iaca.pem", "Other Demo IACA");
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("other-iaca.p12"), "-p", PASSWORD, "--initial",
                "--out", p("other.crl")), stderr());
        reset();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--iaca", p("iaca.pem"), "--crl", p("other.crl")));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("CRL_")), stdout());

        reset();
        assertEquals(1, run("pki", "check", "--profile", "iaca"), "a missing --chain is a usage error");
        assertEquals(1, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "nonsense"));
        assertEquals(1, run("pki", "check", "--chain", p("missing.pem"), "--profile", "iaca"));
        assertEquals(1, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--at", "yesterday"));
    }

    @Test
    void checkJudgesTheIacaTheChainAndTheValidityAtAnInstant() throws Exception {
        iaca();
        X509Certificate dsc = dsc("mdl-dsc@2026-11");
        iaca("other-iaca.p12", "other-iaca.pem", "Other Demo IACA");

        // --iaca must be the chain's second certificate
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--iaca", p("other-iaca.pem")));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("CHAIN_IACA_MISMATCH\t")), stdout());
        reset();

        // the IACA itself is judged under mdoc-dsc: a DSC in the IACA's place is not an IACA
        Files.writeString(path("double.pem"), Pem.writeCertificates(List.of(dsc, dsc)), StandardCharsets.US_ASCII);
        assertEquals(2, run("pki", "check", "--chain", p("double.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_")), stdout());
        reset();

        String later = dsc.getNotAfter().toInstant().plus(1, ChronoUnit.DAYS).toString();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc", "--at", later));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_EXPIRED\t")), stdout());
        assertFalse(stdout().lines().anyMatch(line -> line.startsWith("IACA_EXPIRED\t")), stdout());
        reset();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--at", "2000-01-01T00:00:00Z"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_NOT_YET_VALID\t")), stdout());
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_NOT_YET_VALID\t")), stdout());
        reset();
        String iacaLater = Pem.readCertificate(readString("iaca.pem")).getNotAfter().toInstant().plusSeconds(1)
                .toString();
        assertEquals(2, run("pki", "check", "--chain", p("iaca.pem"), "--profile", "iaca", "--at", iacaLater));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_EXPIRED\t")), stdout());
        reset();
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        reset();
        String afterNextUpdate = readCrl("iaca.crl").getNextUpdate().toInstant().plusSeconds(1).toString();
        assertEquals(2, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--crl", p("iaca.crl"), "--at", afterNextUpdate));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("CRL_EXPIRED\t")), stdout());
        reset();
        assertEquals(0, run("pki", "check", "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc",
                "--crl", p("iaca.crl")), stdout());
        assertTrue(stdout().contains("ok mdoc-dsc crl"), stdout());
    }

    // ------------------------------------------------------------------ keys csr and import

    @Test
    void keysCsrKeepsTheSubjectOrderAndTakesTheCnVerbatim() throws Exception {
        assertEquals(0, run("keys", "generate", "-k", p("keys.p12"), "-p", PASSWORD,
                "--alias", "issuer-es256", "--alg", "ES256", "--subject", "C=IN,O=Lorem Ipsum Demo,CN=Demo Issuer"),
                stderr());
        reset();
        assertEquals(0, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "issuer-es256",
                "--out", p("default.csr")), stderr());
        X509Certificate certificate = PkiFiles.chain(PkiFiles.read(path("keys.p12"), PASSWORD.toCharArray()),
                "issuer-es256").get(0);
        Csr request = Csr.parsePem(readString("default.csr"));
        assertArrayEquals(certificate.getSubjectX500Principal().getEncoded(), request.subject().getEncoded(),
                "the certificate subject, attribute order and string types kept");

        reset();
        assertEquals(0, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "issuer-es256",
                "--cn", "Demo DSC,O=Injected", "--out", p("cn.csr")), stderr());
        X500Name subject = X500Name.getInstance(Csr.parsePem(readString("cn.csr")).subject().getEncoded());
        RDN[] rdns = subject.getRDNs();
        assertEquals(1, rdns.length, "one attribute, nothing injected: " + subject);
        assertEquals(BCStyle.CN, rdns[0].getFirst().getType());
        assertEquals("Demo DSC,O=Injected", rdns[0].getFirst().getValue().toString());
        reset();
        assertEquals(2, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "issuer-es256",
                "--out", p("cn.csr")), "an existing request is not replaced");
        reset();
        assertEquals(1, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "issuer-es256",
                "--out", p("keys.p12")), "the request would overwrite the keystore");
    }

    @Test
    void keysImportAddsAnOpenSslKeyAndChainAndRefusesADuplicateAlias() throws Exception {
        requireOpenSsl();
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("key.pem"), "-out", p("cert.pem"), "-days", "365", "-subj", "/C=IN/CN=Imported DSC");
        openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "200000",
                "-in", p("key.pem"), "-passout", "pass:" + PASSWORD, "-out", p("key-enc.pem"));

        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD,
                "--alias", "imported-plain", "--key", p("key.pem"), "--chain", p("cert.pem")), stderr());
        assertTrue(stdout().contains("alias=imported-plain"), stdout());
        reset();
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD,
                "--alias", "imported-encrypted", "--key", p("key-enc.pem"),
                "--key-password", PASSWORD, "--chain", p("cert.pem")), stderr());
        reset();
        assertEquals(0, run("keys", "list", "-k", p("imported.p12"), "-p", PASSWORD));
        assertTrue(stdout().contains("imported-plain") && stdout().contains("imported-encrypted"), stdout());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD,
                "--alias", "imported-plain", "--key", p("key.pem"), "--chain", p("cert.pem")),
                "an existing alias is not replaced");
        assertTrue(stderr().contains("alias already exists"), stderr());
        reset();

        // a key from another pair does not match the certificate
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("other-key.pem"), "-out", p("other-cert.pem"), "-days", "365", "-subj", "/CN=Other");
        assertEquals(2, run("keys", "import", "-k", p("mismatch.p12"), "-p", PASSWORD,
                "--alias", "mismatch", "--key", p("other-key.pem"), "--chain", p("cert.pem")));
        assertTrue(stderr().contains("does not belong"), stderr());
        reset();

        // an RSA key is named, not misreported as a mismatch
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("rsa-key.pem"),
                "-out", p("rsa-cert.pem"), "-days", "365", "-subj", "/CN=RSA");
        assertEquals(2, run("keys", "import", "-k", p("rsa.p12"), "-p", PASSWORD,
                "--alias", "rsa", "--key", p("rsa-key.pem"), "--chain", p("rsa-cert.pem")));
        assertTrue(stderr().contains("only EC P-256/384/521 is supported"), stderr());
        assertFalse(Files.exists(path("rsa.p12")));
    }

    @Test
    void keysImportVerifiesTheChainAndTheDocumentSignerProfile() throws Exception {
        requireOpenSsl();
        iaca();
        dsc("mdl-dsc@2026-11");
        KeyStore issuer = PkiFiles.read(path("issuer.p12"), ISSUER_PASSWORD.toCharArray());
        Files.writeString(path("dsc-key.pem"), Pem.writePrivateKey(
                PkiFiles.privateKey(issuer, "mdl-dsc@2026-11", ISSUER_PASSWORD.toCharArray())));
        leafFile("dsc-chain.pem", "dsc.pem");

        // a leaf whose issuer is not given cannot be checked
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "a",
                "--key", p("dsc-key.pem"), "--chain", p("dsc.pem")));
        assertTrue(stderr().contains("not self-signed"), stderr());
        reset();
        // a chain whose second certificate did not sign the first
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("unrelated-key.pem"), "-out", p("unrelated.pem"), "-days", "365", "-subj", "/CN=Unrelated");
        Files.writeString(path("broken-chain.pem"), readString("dsc.pem") + readString("unrelated.pem"));
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "b",
                "--key", p("dsc-key.pem"), "--chain", p("broken-chain.pem")));
        assertTrue(stderr().contains("is not signed by certificate 2"), stderr());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "c",
                "--key", p("dsc-key.pem"), "--chain", p("dsc.pem"), "--anchor", p("unrelated.pem")));
        assertTrue(stderr().contains("not signed by the --anchor"), stderr());
        reset();

        // the leaf under its IACA, as an anchor: the mdoc-dsc entry stores [DSC, IACA]
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--key", p("dsc-key.pem"), "--chain", p("dsc.pem"), "--anchor", p("iaca.pem"),
                "--profile", "mdoc-dsc"), stderr());
        assertTrue(stdout().contains("chain=2\n"), stdout());
        assertEquals(2, PkiFiles.chain(PkiFiles.read(path("imported.p12"), PASSWORD.toCharArray()),
                "mdl-dsc@2026-11").size());
        reset();
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "full",
                "--key", p("dsc-key.pem"), "--chain", p("dsc-chain.pem"), "--profile", "mdoc-dsc"), stderr());
        reset();
        // a lone self-signed certificate has no IACA to be judged against
        assertEquals(1, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "plain",
                "--key", p("unrelated-key.pem"), "--chain", p("unrelated.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stderr().contains("needs the IACA"), stderr());
        reset();
        // a plain CA and leaf link, but are not an Annex B IACA and Document Signer
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("ca-key.pem"), "-out", p("ca.pem"), "-days", "365", "-subj", "/C=IN/CN=Plain CA");
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("leaf-key.pem"), "-out", p("leaf.csr"), "-subj", "/C=IN/CN=Plain Leaf");
        openssl("x509", "-req", "-in", p("leaf.csr"), "-CA", p("ca.pem"), "-CAkey", p("ca-key.pem"),
                "-CAcreateserial", "-days", "30", "-out", p("leaf.pem"));
        Files.writeString(path("plain-chain.pem"), readString("leaf.pem") + readString("ca.pem"));
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "plain",
                "--key", p("leaf-key.pem"), "--chain", p("plain-chain.pem")), "without a profile: " + stderr());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "plain-dsc",
                "--key", p("leaf-key.pem"), "--chain", p("plain-chain.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_")), stdout());
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("IACA_")), stdout());
    }

    // ------------------------------------------------------------------ pem IACA

    @Test
    void anIacaWrittenAsPemStandsInForTheKeystore() throws Exception {
        int code = run("pki", "iaca", "create", "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://credentials.example.test",
                "--crl-uri", "https://credentials.example.test/iaca.crl",
                "--pem-out", p("iaca-key.pem"));
        assertEquals(0, code, "--pem-out needs no -k: " + stderr());
        String keyPem = readString("iaca-key.pem");
        assertTrue(keyPem.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), keyPem);
        assertTrue(keyPem.contains("-----BEGIN CERTIFICATE-----"), "the certificate travels with the key");
        Files.writeString(path("iaca.pem"), stdout(), StandardCharsets.US_ASCII);
        reset();
        assertEquals(1, run("pki", "iaca", "create", "-k", p("x.p12"), "--pem-out", p("x.pem"), "-p", PASSWORD,
                "--country", "IN", "--cn", "X", "--issuer-alt-uri", "https://a.test", "--crl-uri",
                "https://a.test/x.crl"), "-k and --pem-out are exclusive");
        reset();

        assertEquals(0, run("pki", "dsc", "issue", "--iaca", p("iaca-key.pem"), "-p", PASSWORD,
                "--generate", "-k", p("issuer.pem.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("pem-chain.pem")), stderr());
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("iaca-key.pem"), "-p", PASSWORD, "--initial",
                "--out", p("pem-iaca.crl")), stderr());
        assertTrue(Files.exists(path("iaca-key.pem.crlstate.json")));
        reset();
        assertEquals(0, run("pki", "check", "--chain", p("pem-chain.pem"), "--profile", "mdoc-dsc",
                "--iaca", p("iaca.pem"), "--crl", p("pem-iaca.crl")), stderr());
        assertTrue(stdout().contains("ok mdoc-dsc crl"), stdout());
        assertEquals(List.of(), AnnexBValidator.validateIaca(Pem.readCertificate(readString("iaca.pem"))));
    }

    // ------------------------------------------------------------------ PKCS#12 encryption

    @Test
    void everyKeystoreIsWrittenUnderPbkdf2With200000Iterations() throws Exception {
        iaca();
        dsc("mdl-dsc@2026-11");
        assertEquals(0, run("keys", "generate", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "k",
                "--alg", "ES256"), stderr());
        for (String file : List.of("iaca.p12", "issuer.p12", "keys.p12")) {
            assertPkcs12Strength(path(file));
        }
        if (openSslAvailable()) {
            String info = openssl("pkcs12", "-info", "-nokeys", "-noout", "-in", p("issuer.p12"),
                    "-passin", "pass:" + ISSUER_PASSWORD);
            assertTrue(info.contains("MAC: sha256, Iteration 200000"), info);
            assertTrue(info.contains("PBES2, PBKDF2, AES-256-CBC, Iteration 200000, PRF hmacWithSHA256"), info);
        }
    }

    /** MAC, certificate bag and key bags of a PKCS#12 file, read with BouncyCastle's ASN.1 classes. */
    static void assertPkcs12Strength(Path file) throws Exception {
        Pfx pfx = Pfx.getInstance(Files.readAllBytes(file));
        MacData mac = pfx.getMacData();
        assertEquals(PkiFiles.PKCS12_ITERATIONS, mac.getIterationCount().intValue(), file + " MAC iterations");
        assertEquals(NISTObjectIdentifiers.id_sha256, mac.getMac().getAlgorithmId().getAlgorithm(), file + " MAC");
        AuthenticatedSafe safe = AuthenticatedSafe.getInstance(
                ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets());
        int certificateBags = 0;
        int keyBags = 0;
        for (ContentInfo info : safe.getContentInfo()) {
            if (PKCSObjectIdentifiers.encryptedData.equals(info.getContentType())) {
                assertPbes2(EncryptedData.getInstance(info.getContent()).getEncryptionAlgorithm(), file + " certs");
                certificateBags++;
            } else if (PKCSObjectIdentifiers.data.equals(info.getContentType())) {
                ASN1Sequence bags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(info.getContent()).getOctets());
                for (ASN1Encodable encodable : bags) {
                    SafeBag bag = SafeBag.getInstance(encodable);
                    if (PKCSObjectIdentifiers.pkcs8ShroudedKeyBag.equals(bag.getBagId())) {
                        assertPbes2(EncryptedPrivateKeyInfo.getInstance(bag.getBagValue()).getEncryptionAlgorithm(),
                                file + " key");
                        keyBags++;
                    }
                }
            }
        }
        assertTrue(certificateBags > 0 && keyBags > 0, file + ": " + certificateBags + " cert, " + keyBags + " key");
    }

    static void assertPbes2(AlgorithmIdentifier algorithm, String what) {
        assertEquals(PKCSObjectIdentifiers.id_PBES2, algorithm.getAlgorithm(), what);
        PBES2Parameters parameters = PBES2Parameters.getInstance(algorithm.getParameters());
        PBKDF2Params kdf = PBKDF2Params.getInstance(parameters.getKeyDerivationFunc().getParameters());
        assertEquals(PkiFiles.PKCS12_ITERATIONS, kdf.getIterationCount().intValue(), what + " iterations");
        assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, kdf.getPrf().getAlgorithm(), what + " PRF");
        assertEquals(NISTObjectIdentifiers.id_aes256_CBC, parameters.getEncryptionScheme().getAlgorithm(), what);
    }

    // ------------------------------------------------------------------ usage errors

    @Test
    void usageErrorsExitOneOnEveryCommand() throws Exception {
        assertEquals(1, run("pki", "dsc", "issue", "--generate"), "missing required options");
        assertEquals(1, run("pki", "crl", "issue", "--bogus"));
        assertEquals(1, run("pki", "iaca", "create", "--country", "IN"));
        assertEquals(1, run("keys", "generate", "-k", p("k.p12"), "-p", PASSWORD), "missing --alias");
        assertEquals(1, run("keys", "import", "-k", p("k.p12")));
        assertEquals(1, run("pki", "iaca", "create", "-k", p("bad.p12"), "-p", PASSWORD,
                "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl",
                "--validity-years", "21"));
        assertTrue(stderr().contains("1 to 20"), stderr());
        reset();
        iaca();
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "--generate", "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "too-long",
                "--validity-days", "500", "--out", p("too-long.pem")));
        assertTrue(stderr().contains("1 to 457"), stderr());
        assertFalse(Files.exists(path("issuer.p12")), "refused before any key is generated");
    }

    // ------------------------------------------------------------------ child JVM: umask and environment

    @Test
    void keysAndStateAreOwnerOnlyUnderUmask022AndPublicFilesAreNot() throws Exception {
        assumeTrue(SecureFiles.posix(dir) && Files.isExecutable(Path.of("/bin/sh")), "POSIX only");
        Map<String, String> env = Map.of(PkiFiles.IACA_PASSWORD_ENV, PASSWORD,
                PkiFiles.KEYSTORE_PASSWORD_ENV, ISSUER_PASSWORD);
        child(env, 0, "pki", "iaca", "create", "-k", "iaca.p12", "--country", "IN", "--cn", "Lorem Ipsum Demo IACA",
                "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl");
        child(env, 0, "pki", "iaca", "create", "--pem-out", "iaca-key.pem", "--country", "IN", "--cn", "PEM IACA",
                "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl");
        child(env, 0, "pki", "dsc", "issue", "--iaca", "iaca.p12", "--generate", "-k", "issuer.p12",
                "--alias", "mdl-dsc@2026-11", "--out", "dsc-chain.pem");
        child(env, 0, "pki", "crl", "issue", "--iaca", "iaca.p12", "--initial", "--out", "iaca.crl");
        for (String secret : List.of("iaca.p12", "iaca-key.pem", "issuer.p12", "iaca.p12.crlstate.json",
                "issuer.p12.lock")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(path(secret))),
                    secret);
        }
        for (String published : List.of("dsc-chain.pem", "iaca.crl")) {
            assertEquals("rw-r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(path(published))),
                    published);
        }
    }

    @Test
    void theIacaPasswordNeverFallsBackToTheKeystorePassword() throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "POSIX only");
        iaca();
        // only the keystore password is set, and it is the IACA's: still refused, the variables never stand in
        Child refused = child(Map.of(PkiFiles.KEYSTORE_PASSWORD_ENV, PASSWORD), 1,
                "pki", "crl", "issue", "--iaca", "iaca.p12", "--initial", "--out", "iaca.crl");
        assertTrue(refused.stderr().contains("no IACA keystore password") && refused.stderr()
                .contains(PkiFiles.IACA_PASSWORD_ENV), refused.stderr());
        assertFalse(Files.exists(path("iaca.crl")));
        child(Map.of(PkiFiles.IACA_PASSWORD_ENV, PASSWORD), 0,
                "pki", "crl", "issue", "--iaca", "iaca.p12", "--initial", "--out", "iaca.crl");
        // and the issuer keystore does not take the IACA's variable
        Child issuer = child(Map.of(PkiFiles.IACA_PASSWORD_ENV, PASSWORD), 1, "pki", "dsc", "issue",
                "--iaca", "iaca.p12", "--generate", "-k", "issuer.p12", "--alias", "a", "--out", "a.pem");
        assertTrue(issuer.stderr().contains("no issuer keystore password"), issuer.stderr());
        assertFalse(Files.exists(path("issuer.p12")));
    }

    record Child(int code, String stdout, String stderr) {}

    /** The CLI in a child JVM under {@code umask 022}, in {@link #dir}, with only the given password variables. */
    Child child(Map<String, String> env, int expected, String... args) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> command = new ArrayList<>(List.of("/bin/sh", "-c", "umask 022 && exec \"$@\"", "sh", java,
                "-Djdk.console=java.base", "-cp", System.getProperty("java.class.path"), CertifyCli.class.getName()));
        command.addAll(List.of(args));
        ProcessBuilder builder = new ProcessBuilder(command).directory(dir.toFile());
        Map<String, String> environment = builder.environment();
        environment.remove(PkiFiles.IACA_PASSWORD_ENV);
        environment.remove(PkiFiles.KEYSTORE_PASSWORD_ENV);
        environment.remove(PkiFiles.KEY_PASSWORD_ENV);
        environment.putAll(new HashMap<>(env));
        File stdoutFile = Files.createTempFile("child", ".out").toFile();
        File stderrFile = Files.createTempFile("child", ".err").toFile();
        builder.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        builder.redirectOutput(stdoutFile).redirectError(stderrFile);
        Process process = builder.start();
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "the child JVM did not finish: " + command);
        String stdout;
        String stderr;
        try (InputStream o = new FileInputStream(stdoutFile); InputStream e = new FileInputStream(stderrFile)) {
            stdout = new String(o.readAllBytes(), StandardCharsets.UTF_8);
            stderr = new String(e.readAllBytes(), StandardCharsets.UTF_8);
        } finally {
            stdoutFile.delete();
            stderrFile.delete();
        }
        Child child = new Child(process.exitValue(), stdout, stderr);
        assertEquals(expected, child.code(), () -> String.join(" ", args) + "\nstdout: " + stdout + "\nstderr: "
                + stderr);
        return child;
    }

    // ------------------------------------------------------------------ openssl

    record OpenSsl(int code, String output) {}

    static boolean openSslAvailable() {
        try {
            Process process = new ProcessBuilder("openssl", "version").redirectErrorStream(true).start();
            return process.waitFor(30, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /** Skip when OpenSSL is absent, unless this is CI, where an unverified build is not acceptable. */
    static void requireOpenSsl() {
        if (openSslAvailable()) {
            return;
        }
        if (System.getenv("CI") != null) {
            fail("openssl is not on the PATH and CI is set: the independent verifier must run");
        }
        org.junit.jupiter.api.Assumptions.abort("openssl is not on the PATH");
    }

    static OpenSsl opensslResult(String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of("openssl"));
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "openssl did not finish: " + command);
        return new OpenSsl(process.exitValue(), output);
    }

    static String openssl(String... arguments) throws Exception {
        OpenSsl result = opensslResult(arguments);
        assertEquals(0, result.code(), () -> String.join(" ", arguments) + ": " + result.output());
        return result.output();
    }
}
