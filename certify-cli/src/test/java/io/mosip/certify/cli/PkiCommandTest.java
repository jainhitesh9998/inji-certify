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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    /** The temporary directory with every symbolic link resolved (on macOS /var is /private/var). */
    Path real(String name) {
        try {
            return dir.toRealPath().resolve(name);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The canonical inventory file of the IACA whose certificate is in {@code pemFile}. */
    Path statePath(String pemFile) {
        return real(CrlState.canonicalName(CrlState.keyId(Pem.readCertificate(readString(pemFile)))));
    }

    Path statePath() {
        return statePath("iaca.pem");
    }

    /** Every {@code *.crlstate.json} in the directory, by real path. */
    List<Path> stateFiles() throws Exception {
        try (var files = Files.list(real("."))) {
            return files.filter(f -> f.getFileName().toString().endsWith(CrlState.SUFFIX)).map(f -> real(
                    f.getFileName().toString())).sorted().toList();
        }
    }

    /** Runs {@code threads} commands at once (released together) in this JVM; their exit codes in order. */
    List<Integer> concurrently(int threads, java.util.function.IntFunction<List<String>> command) throws Exception {
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
                String[] args = command.apply(i).toArray(String[]::new);
                Callable<Integer> task = () -> {
                    start.await();
                    return CertifyCli.commandLine().execute(args);
                };
                results.add(pool.submit(task));
            }
            start.countDown();
            List<Integer> codes = new ArrayList<>();
            for (Future<Integer> result : results) {
                codes.add(result.get(120, TimeUnit.SECONDS));
            }
            return codes;
        } finally {
            pool.shutdownNow();
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    static KeyPair ecKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** A certificate built field by field with BouncyCastle, for path shapes the CLI itself never writes. */
    static X509Certificate certificate(String subject, KeyPair subjectKey, String issuer, KeyPair issuerKey,
                                       Instant from, Instant to, Extension... extensions) throws Exception {
        return certificate(subject, subjectKey, new X500Name(issuer), issuerKey, from, to, extensions);
    }

    static X509Certificate certificate(String subject, KeyPair subjectKey, X500Name issuer, KeyPair issuerKey,
                                       Instant from, Instant to, Extension... extensions) throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
                new BigInteger(72, new java.security.SecureRandom()).setBit(71), Date.from(from), Date.from(to),
                new X500Name(subject), subjectKey.getPublic());
        for (Extension extension : extensions) {
            builder.addExtension(extension);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    static Extension basicConstraints(boolean ca, int pathLen) throws Exception {
        return Extension.create(Extension.basicConstraints, true,
                ca ? (pathLen >= 0 ? new BasicConstraints(pathLen) : new BasicConstraints(true))
                        : new BasicConstraints(false));
    }

    static Extension keyUsage(int usage) throws Exception {
        return Extension.create(Extension.keyUsage, true, new KeyUsage(usage));
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

    /** A keystore named through a symbolic link is updated where the link points, under the real file's lock. */
    @Test
    void aSymbolicLinkToTheKeystoreIsUpdatedWhereItPoints() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "symbolic links");
        iaca();
        Files.createDirectories(path("deployed"));
        assertEquals(0, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("deployed/issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-10",
                "--out", p("c0.pem")), stderr());
        Files.createSymbolicLink(path("issuer-link.p12"), Path.of("deployed/issuer.p12"));
        reset();
        assertEquals(0, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer-link.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("c1.pem")), stderr());
        reset();
        assertEquals(0, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                "-k", p("issuer-link.p12"), "-P", ISSUER_PASSWORD, "--out", p("c2.pem")), stderr());
        reset();
        assertEquals(0, run("keys", "generate", "-k", p("issuer-link.p12"), "-p", ISSUER_PASSWORD,
                "--alias", "plain", "--alg", "ES256"), stderr());
        assertTrue(Files.isSymbolicLink(path("issuer-link.p12")), "the link stays a link");
        List<String> aliases = PkiFiles.aliases(PkiFiles.read(path("deployed/issuer.p12"),
                ISSUER_PASSWORD.toCharArray()));
        assertTrue(aliases.containsAll(List.of("mdl-dsc@2026-10", "mdl-dsc@2026-11", "plain")) && aliases.size() == 4,
                "every new key is in the deployed keystore: " + aliases);
        assertTrue(Files.exists(path("deployed/issuer.p12.lock")) && !Files.exists(path("issuer-link.p12.lock")),
                "one lock, beside the real file");
    }

    @Test
    void aHardLinkedKeystoreOrADanglingLinkIsRefused() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "links");
        iaca();
        dsc("mdl-dsc@2026-10");
        byte[] before = sha256(path("issuer.p12"));
        Files.createLink(path("hard.p12"), path("issuer.p12"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("hard.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11", "--out", p("c.pem")));
        assertTrue(stderr().contains("has 2 hard links"), stderr());
        assertArrayEquals(before, sha256(path("issuer.p12")));
        Files.delete(path("hard.p12"));
        reset();
        Files.createSymbolicLink(path("ghost.p12"), Path.of("missing/issuer.p12"));
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("ghost.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11", "--out", p("c.pem")));
        assertTrue(stderr().contains("is a symbolic link to missing/issuer.p12, which does not exist"), stderr());
        assertTrue(Files.isSymbolicLink(path("ghost.p12")) && !Files.exists(path("missing")));
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
            String state = statePath().getFileName().toString();
            String identity = "." + CrlState.keyId(Pem.readCertificate(readString("iaca.pem"))) + ".crl.lock";
            assertTrue(names.contains("issuer.p12.lock") && names.contains(state + ".lock")
                    && names.contains(identity), "stable lock files next to the files they guard: " + names);
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

    /** M-05's order: equal notBefore, so the label decides, numerically ({@code .10} after {@code .9}). */
    @Test
    void theRotationTieBreakComparesVersionLabelsNumerically() throws Exception {
        Instant from = Instant.now().minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);
        Instant to = from.plus(30, ChronoUnit.DAYS);
        KeyStore store = PkiFiles.empty();
        for (String alias : List.of("mdl-dsc@2026-11", "mdl-dsc@2026-11.9", "mdl-dsc@2026-11.10",
                "mdl-dsc@2026-11.2")) {
            KeyPair key = ecKey();
            store.setKeyEntry(alias, key.getPrivate(), PASSWORD.toCharArray(), new java.security.cert.Certificate[] {
                    certificate("CN=" + alias, key, "CN=" + alias, key, from, to)});
        }
        assertEquals("mdl-dsc@2026-11.10", PkiCommand.Rotation.current(store, "mdl-dsc", Instant.now()).orElseThrow());
        assertTrue(io.mosip.certify.keyprovider.jca.VersionLabels.compare("2026-11.10", "2026-11.9") > 0);
        assertTrue(io.mosip.certify.keyprovider.jca.VersionLabels.compare("2026-11", "2026-11.2") < 0);
        assertTrue(io.mosip.certify.keyprovider.jca.VersionLabels.compare("2026-12", "2026-11.10") > 0);
        assertTrue(io.mosip.certify.keyprovider.jca.VersionLabels.compare("2026-11.02", "2026-11.2") != 0, "a total order");
    }

    @Test
    void rotateWithoutOutKeepsTheChainLastOnStdout() throws Exception {
        iaca();
        dsc("mdl-dsc@2025-01");
        assertEquals(0, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD, "-k", p("issuer.p12"),
                "-P", ISSUER_PASSWORD), stderr());
        assertTrue(stdout().stripTrailing().endsWith("-----END CERTIFICATE-----"), "the PEM ends stdout: " + stdout());
        assertEquals(2, Pem.readCertificates(stdout()).size());
        assertFalse(stdout().contains("current="), stdout());
        assertTrue(stderr().contains("current=mdl-dsc@"), stderr());
    }

    /** PKCS#12 lower-cases aliases on reload, so an upper-case alias would be stored under another name (as M-05). */
    @Test
    void upperCaseAliasesAreRefusedEverywhereAKeyIsStored() throws Exception {
        iaca();
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "Mdl-DSC@2026-11", "--out", p("c.pem")));
        assertTrue(stderr().contains("--alias Mdl-DSC@2026-11 has upper-case letters")
                && stderr().contains("pass mdl-dsc@2026-11"), stderr());
        assertFalse(Files.exists(path("issuer.p12")));
        reset();
        assertEquals(1, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD, "-k", p("issuer.p12"),
                "-P", ISSUER_PASSWORD, "--alias-prefix", "MDL-dsc"));
        assertTrue(stderr().contains("--alias-prefix MDL-dsc has upper-case letters"), stderr());
        reset();
        assertEquals(1, run("pki", "iaca", "create", "-k", p("iaca2.p12"), "-p", PASSWORD, "--alias", "IACA",
                "--country", "IN", "--cn", "X", "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/x.crl"));
        assertEquals(1, run("keys", "generate", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "Issuer",
                "--alg", "ES256"));
        assertFalse(Files.exists(path("iaca2.p12")) || Files.exists(path("keys.p12")));
        reset();
        Files.writeString(path("dsc-key.pem"), "unused");
        assertEquals(1, run("keys", "import", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "Imported",
                "--key", p("dsc-key.pem"), "--chain", p("iaca.pem")));
        assertTrue(stderr().contains("has upper-case letters"), stderr());
        reset();
        // what is stored is what is printed
        dsc("mdl-dsc@2026-11");
        assertEquals(List.of("mdl-dsc@2026-11"), PkiFiles.aliases(PkiFiles.read(path("issuer.p12"),
                ISSUER_PASSWORD.toCharArray())));
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
        Files.delete(statePath());
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
        Files.delete(statePath());
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
        Files.writeString(statePath(), "");
        reset();
        assertEquals(2, crl("crl-2.pem"));
        assertTrue(stderr().contains("is corrupt") && stderr().contains("empty"), stderr());
        Files.writeString(statePath(), "{\"format\":\"certify-cli/crl-state/1\",\"iacas\":{\"zz\":1}}");
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
            assertTrue(stderr().contains("CRL number 2 and its revocations are already recorded in " + statePath())
                    && stderr().contains("to publish CRL 3"), "what happened and what a rerun does: " + stderr());
        } finally {
            Files.setPosixFilePermissions(readOnly, PosixFilePermissions.fromString("rwx------"));
        }
        assertFalse(Files.exists(path("published/crl-2.pem")), "no CRL was exposed");
        CrlState state = CrlState.read(statePath());
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
        assertEquals(BigInteger.valueOf(threads + 1), CrlState.read(statePath())
                .inventory(CrlState.keyId(Pem.readCertificate(readString("iaca.pem")))).lastCrlNumber());
    }

    /** Two copies of one IACA in one directory (the reported race): one first CRL, one inventory, one sequence. */
    @Test
    void concurrentFirstIssuanceFromTwoCopiesOfOneIacaStartsOneInventory() throws Exception {
        iaca();
        Files.copy(path("iaca.p12"), path("a.p12"));
        Files.copy(path("iaca.p12"), path("b.p12"));
        Files.delete(path("iaca.p12"));
        int threads = 8;
        List<Integer> initial = concurrently(threads, i -> List.of("pki", "crl", "issue", "--iaca",
                p(i % 2 == 0 ? "a.p12" : "b.p12"), "-p", PASSWORD, "--initial", "--out", p("first-" + i + ".crl")));
        assertEquals(1, initial.stream().filter(code -> code == 0).count(), "exactly one first CRL: " + initial);
        assertEquals(threads - 1, initial.stream().filter(code -> code == 2).count(), "the others refused: " + initial);
        assertEquals(List.of(statePath()), stateFiles(), "one inventory, named by the IACA's key identifier");

        List<Integer> later = concurrently(threads, i -> List.of("pki", "crl", "issue", "--iaca",
                p(i % 2 == 0 ? "a.p12" : "b.p12"), "-p", PASSWORD, "--out", p("later-" + i + ".crl")));
        assertEquals(List.of(0, 0, 0, 0, 0, 0, 0, 0), later);
        Set<BigInteger> numbers = new TreeSet<>();
        for (int i = 0; i < threads; i++) {
            numbers.add(CrlState.crlNumber(readCrl("later-" + i + ".crl")));
        }
        assertEquals(threads, numbers.size(), "no number issued twice across the copies: " + numbers);
        assertEquals(BigInteger.valueOf(threads + 1), CrlState.read(statePath())
                .inventory(CrlState.keyId(Pem.readCertificate(readString("iaca.pem")))).lastCrlNumber());
    }

    /** The same race across processes: the identity lock is a file lock, not only a lock inside one JVM. */
    @Test
    void concurrentFirstIssuanceAcrossProcessesStartsOneInventory() throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "POSIX only");
        iaca();
        Files.copy(path("iaca.p12"), path("a.p12"));
        Files.copy(path("iaca.p12"), path("b.p12"));
        Map<String, String> env = Map.of(PkiFiles.IACA_PASSWORD_ENV, PASSWORD);
        List<Process> processes = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            processes.add(startChild(env, "pki", "crl", "issue", "--iaca", i % 2 == 0 ? "a.p12" : "b.p12",
                    "--initial", "--out", "process-" + i + ".crl"));
        }
        List<Integer> codes = new ArrayList<>();
        for (Process process : processes) {
            assertTrue(process.waitFor(120, TimeUnit.SECONDS), "a child JVM did not finish");
            codes.add(process.exitValue());
        }
        assertEquals(1, codes.stream().filter(code -> code == 0).count(), "exactly one first CRL: " + codes);
        assertEquals(List.of(statePath()), stateFiles());
    }

    @Test
    void aSymbolicLinkToTheIacaFindsItsInventoryAndRefusesInitial() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "symbolic links");
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        reset();
        Files.createDirectories(path("linked"));
        Files.createSymbolicLink(path("linked/iaca.p12"), Path.of("../iaca.p12"));
        assertEquals(2, run("pki", "crl", "issue", "--iaca", p("linked/iaca.p12"), "-p", PASSWORD, "--initial",
                "--out", p("link-1.pem")), "the inventory of the real IACA exists: " + stdout());
        assertTrue(stderr().contains("--initial is for an IACA without a revocation inventory"), stderr());
        assertFalse(Files.exists(path("link-1.pem")));
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("linked/iaca.p12"), "-p", PASSWORD,
                "--out", p("link-2.pem")), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("state=" + statePath() + "\n"), stdout());
        try (var files = Files.list(path("linked"))) {
            assertEquals(List.of("iaca.p12"), files.map(f -> f.getFileName().toString()).toList(),
                    "nothing created beside the link");
        }
    }

    @Test
    void aSymbolicLinkToTheStateIsUpdatedWhereItPoints() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "symbolic links");
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        Files.createDirectories(path("vault"));
        Files.move(statePath(), path("vault/state.json"));
        Files.createSymbolicLink(path("state-link.json"), Path.of("vault/state.json"));
        reset();
        assertEquals(0, crl("crl-2.pem", "--state", p("state-link.json")), stderr());
        assertTrue(stdout().contains("crlNumber=2\n")
                && stdout().contains("state=" + real("vault").resolve("state.json") + "\n"), stdout());
        assertTrue(Files.isSymbolicLink(path("state-link.json")), "the link stays a link");
        String keyId = CrlState.keyId(Pem.readCertificate(readString("iaca.pem")));
        assertEquals(BigInteger.TWO, CrlState.read(path("vault/state.json")).inventory(keyId).lastCrlNumber());
        assertTrue(stderr().contains("recorded " + real("vault").resolve("state.json") + " as the CRL state of this"
                + " IACA in " + statePath()), stderr());
        reset();
        // the slot beside the IACA now points at the vault file: a run without --state finds it, never forks
        assertEquals(0, crl("crl-3.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=3\n")
                && stdout().contains("state=" + real("vault").resolve("state.json") + "\n"), stdout());
        reset();
        assertEquals(0, crl("crl-4.pem", "--state", p("vault/state.json")), stderr());
        assertTrue(stdout().contains("crlNumber=4\n"), stdout());
        reset();
        assertEquals(0, crl("crl-5.pem", "--state", p("state-link.json")), "the link names the same file: " + stderr());
        assertTrue(stdout().contains("crlNumber=5\n"), stdout());
    }

    @Test
    void aStateFileThatDoesNotRecordTheIacaIsRefusedWhileAnotherDoes() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        reset();
        assertEquals(1, crl("crl-x.pem", "--state", p("fresh.json"), "--initial"),
                "a second inventory for the same IACA would restart its numbers");
        assertTrue(stderr().contains("--state " + real("fresh.json") + " is not the CRL state of this IACA: "
                + statePath() + " is") && stderr().contains("--base-crl"), stderr());
        assertFalse(Files.exists(path("fresh.json")));
        reset();
        // no slot and two files recording one IACA: refused, both named by their absolute real path
        Files.move(statePath(), path("a.crlstate.json"));
        Files.copy(path("a.crlstate.json"), path("b.crlstate.json"));
        assertEquals(1, crl("crl-2.pem"));
        assertTrue(stderr().contains("more than one file [" + real("a.crlstate.json") + ", " + real("b.crlstate.json")
                + "]"), stderr());
        reset();
        // --state says which (at or ahead of the other); the slot then points at it
        assertEquals(0, crl("crl-2.pem", "--state", p("a.crlstate.json")), stderr());
        assertTrue(stderr().contains("warning: " + real("b.crlstate.json") + " also records this IACA"), stderr());
        assertTrue(CrlState.readEntry(statePath()) instanceof CrlState.Pointer pointer
                && pointer.stateAt().equals(real("a.crlstate.json")), "a pointer in the slot");
        reset();
        assertEquals(0, crl("crl-3.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("state=" + real("a.crlstate.json")),
                stdout());
        reset();
        // a stale copy cannot be chosen: it disagrees with the pointer
        assertEquals(1, crl("crl-x.pem", "--state", p("b.crlstate.json")));
        assertTrue(stderr().contains("is not the CRL state of this IACA: " + real("a.crlstate.json")), stderr());
        reset();
        // without a slot, a --state that records nothing while another file does would start a second inventory
        Files.delete(statePath());
        Files.delete(path("b.crlstate.json"));
        assertEquals(1, crl("crl-x.pem", "--state", p("fresh.json"), "--initial"));
        assertTrue(stderr().contains("does not record this IACA, but [" + real("a.crlstate.json") + "]"), stderr());
        assertFalse(Files.exists(path("fresh.json")) || Files.exists(statePath()), "no state and no pointer written");
        reset();
        assertEquals(1, crl("x.crlstate.json"), "--out must not look like a state file");
    }

    /** Reviewer finding: two runs naming different --state files both issued CRL 1. */
    @Test
    void alternateStateNamesNeverForkTheInventory() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial", "--state", p("state-a.json"), "--revoke", "0xabc"), stderr());
        assertTrue(CrlState.readEntry(statePath()) instanceof CrlState.Pointer pointer
                && pointer.stateAt().equals(real("state-a.json")), "the slot points at state-a.json");
        reset();
        assertEquals(1, crl("crl-b.pem", "--initial", "--state", p("state-b.json")), "a second CRL 1");
        assertTrue(stderr().contains("--state " + real("state-b.json") + " is not the CRL state of this IACA: "
                + real("state-a.json") + " is (the pointer " + statePath() + ")"), stderr());
        assertTrue(stderr().contains("--base-crl"), stderr());
        assertFalse(Files.exists(path("state-b.json")) || Files.exists(path("crl-b.pem")));
        reset();
        assertEquals(1, crl("crl-b.pem", "--state", p("state-b.json")));
        reset();
        // a copy of the IACA in the same directory, without --state, follows the pointer
        Files.copy(path("iaca.p12"), path("b.p12"));
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("b.p12"), "-p", PASSWORD, "--out", p("crl-2.pem")),
                stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("revoked=1\n")
                && stdout().contains("state=" + real("state-a.json") + "\n"), stdout());
        reset();
        assertEquals(2, crl("crl-x.pem", "--initial"));
        assertTrue(stderr().contains("--initial is for an IACA without a revocation inventory"), stderr());
        // the pointer itself is no state
        reset();
        assertEquals(1, crl("crl-x.pem", "--state", statePath().toString()));
        assertTrue(stderr().contains("is a CRL state pointer to " + real("state-a.json")), stderr());
    }

    /** Reviewer finding: a --state in another directory was invisible to later runs, and --initial restarted at 1. */
    @Test
    void anExternalStateIsFoundWithoutStateAndAMissingOneStopsTheRun() throws Exception {
        iaca();
        Files.createDirectories(path("elsewhere"));
        assertEquals(0, crl("crl-1.pem", "--initial", "--state", p("elsewhere/s.json"), "--revoke", "0x1234"),
                stderr());
        reset();
        assertEquals(2, crl("crl-x.pem", "--initial"), "CRL 1 again");
        assertTrue(stderr().contains("--initial is for an IACA without a revocation inventory, but "
                + real("elsewhere/s.json") + " records CRL number 1"), stderr());
        reset();
        assertEquals(0, crl("crl-2.pem"), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("revoked=1\n")
                && stdout().contains("state=" + real("elsewhere/s.json") + "\n"), stdout());
        reset();
        // the medium is not mounted (the file is gone): the run stops, it never starts again at CRL 1
        Files.move(path("elsewhere/s.json"), path("elsewhere/moved.json"));
        for (String[] extra : List.of(new String[0], new String[] {"--initial"},
                new String[] {"--state", p("elsewhere/moved.json")})) {
            reset();
            assertEquals(2, crl("crl-x.pem", extra), String.join(" ", extra));
            assertTrue(stderr().contains("names " + real("elsewhere").resolve("s.json") + ", which does not exist"),
                    stderr());
        }
        assertFalse(Files.exists(path("crl-x.pem")) || Files.exists(path("elsewhere/s.json")));
        reset();
        // a missing --state directory is refused, not created
        assertEquals(1, crl("crl-x.pem", "--state", p("unmounted/s.json")));
        assertTrue(stderr().contains("does not exist") && !Files.exists(path("unmounted")), stderr());
        reset();
        // the remedy the message names: move the pointer aside and name the file
        Files.move(statePath(), path("pointer.bak"));
        assertEquals(0, crl("crl-3.pem", "--state", p("elsewhere/moved.json")), stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("revoked=1\n"), stdout());
    }

    /** Several holders: the inventory in use must be at or ahead of every other file that records the IACA. */
    @Test
    void anInventoryBehindAnotherHolderIsRefused() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        byte[] atOne = Files.readAllBytes(statePath());
        reset();
        assertEquals(0, crl("crl-2.pem", "--revoke", "0xbeef"), stderr());
        // the canonical state goes back to CRL 1 while a copy at CRL 2 (the round-2 name) remains
        Files.copy(statePath(), path("iaca.p12" + CrlState.SUFFIX));
        Files.write(statePath(), atOne);
        reset();
        assertEquals(2, crl("crl-x.pem"), "behind the copy");
        assertTrue(stderr().contains("the CRL state " + statePath() + " (CRL number 1) is behind "
                + real("iaca.p12" + CrlState.SUFFIX) + " (CRL number 2)") && stderr().contains("--base-crl"), stderr());
        reset();
        assertEquals(2, crl("crl-x.pem", "--state", statePath().toString()), "named explicitly: still behind");
        reset();
        assertEquals(1, crl("crl-x.pem", "--state", p("iaca.p12" + CrlState.SUFFIX)),
                "the copy is not the IACA's state");
        reset();
        // same number, but the copy lists a serial the canonical state lacks
        String two = Files.readString(path("iaca.p12" + CrlState.SUFFIX));
        Files.writeString(statePath(), two.replaceAll("\\{\\s*\"serial\" : \"beef\"[^}]*\\}", ""));
        assertEquals(2, crl("crl-x.pem"));
        assertTrue(stderr().contains("does not list 0xbeef"), stderr());
        assertFalse(Files.exists(path("crl-x.pem")));
        reset();
        // the remedy: catch up from the last published CRL
        assertEquals(0, crl("crl-3.pem", "--base-crl", p("crl-2.pem")), stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("revoked=1\n"), stdout());
        assertTrue(stderr().contains("warning: " + real("iaca.p12" + CrlState.SUFFIX) + " also records this IACA"),
                stderr());
    }

    /** D3: an IACA on read-only offline media keeps its lock and state where --state says. */
    @Test
    void aReadOnlyIacaDirectoryNeedsAWritableState() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "POSIX permissions");
        assumeTrue(!"root".equals(System.getProperty("user.name")), "root writes into a read-only directory");
        Files.createDirectories(path("media"));
        Files.createDirectories(path("rw"));
        Files.createDirectories(path("ro-state"));
        iaca("media/iaca.p12", "iaca.pem", "Lorem Ipsum Demo IACA");
        List<String> before;
        try (var files = Files.list(path("media"))) {
            before = files.map(f -> f.getFileName().toString()).sorted().toList();
        }
        Files.setPosixFilePermissions(path("media"), PosixFilePermissions.fromString("r-xr-xr-x"));
        Files.setPosixFilePermissions(path("ro-state"), PosixFilePermissions.fromString("r-xr-xr-x"));
        try {
            String keyId = CrlState.keyId(Pem.readCertificate(readString("iaca.pem")));
            assertEquals(1, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD, "--initial",
                    "--out", p("rw/crl-1.pem")));
            assertTrue(stderr().contains("the IACA directory " + real("media") + " is read-only; pass --state <file>"
                    + " in a writable directory and use the same --state on every run"), stderr());
            reset();
            assertEquals(0, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD, "--initial",
                    "--revoke", "0x1234", "--state", p("rw/s.json"), "--out", p("rw/crl-1.pem")), stderr());
            assertTrue(stdout().contains("crlNumber=1\n") && stdout().contains("state=" + real("rw/s.json")), stdout());
            try (var files = Files.list(path("rw"))) {
                List<String> names = files.map(f -> f.getFileName().toString()).toList();
                assertTrue(names.contains("." + keyId + ".crl.lock") && names.contains("s.json.lock")
                        && names.contains(CrlState.canonicalName(keyId)), "lock and pointer beside the state: "
                        + names);
            }
            reset();
            assertEquals(0, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD,
                    "--state", p("rw/s.json"), "--out", p("rw/crl-2.pem")), stderr());
            assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("revoked=1\n"), stdout());
            reset();
            assertEquals(1, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD, "--initial",
                    "--state", p("rw/t.json"), "--out", p("rw/crl-x.pem")), "another name in the same directory");
            assertTrue(stderr().contains("is not the CRL state of this IACA: " + real("rw/s.json")), stderr());
            reset();
            assertEquals(1, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD,
                    "--out", p("rw/crl-x.pem")), "every run names the state");
            reset();
            // a --state directory that is not writable: the lock failure names the directory and the cause
            assertEquals(2, run("pki", "crl", "issue", "--iaca", p("media/iaca.p12"), "-p", PASSWORD, "--initial",
                    "--state", p("ro-state/s.json"), "--out", p("rw/crl-x.pem")));
            assertTrue(stderr().contains("cannot take the lock ." + keyId + ".crl.lock in the directory "
                    + real("ro-state") + ": permission denied"), stderr());
            assertFalse(Files.exists(path("rw/crl-x.pem")));
            try (var files = Files.list(path("media"))) {
                assertEquals(before, files.map(f -> f.getFileName().toString()).sorted().toList(),
                        "nothing written beside the IACA");
            }
            assertNotNull(readCrl("rw/crl-2.pem").getRevokedCertificate(new BigInteger("1234", 16)));
        } finally {
            Files.setPosixFilePermissions(path("media"), PosixFilePermissions.fromString("rwx------"));
            Files.setPosixFilePermissions(path("ro-state"), PosixFilePermissions.fromString("rwx------"));
        }
    }

    @Test
    void theRound2StateFileNameIsReadAndRenamedUnderTheLock() throws Exception {
        iaca();
        assertEquals(0, crl("crl-1.pem", "--initial"), stderr());
        // a round-2 CLI kept the inventory under <iaca-store>.crlstate.json
        Files.move(statePath(), path("iaca.p12.crlstate.json"));
        reset();
        assertEquals(0, crl("crl-2.pem"), stderr());
        assertTrue(stderr().contains("renamed the CRL state " + real("iaca.p12.crlstate.json") + " to "
                + statePath()), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("state=" + statePath() + "\n"), stdout());
        assertFalse(Files.exists(path("iaca.p12.crlstate.json")));
    }

    @Test
    void anInventoryWithoutALastCrlNumberIsCorrupt() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("crl-1.pem", "--initial", "--revoke", hex(revoked)), stderr());
        String json = Files.readString(statePath());
        Files.writeString(statePath(), json.replace("\"lastCrlNumber\" : \"1\"", "\"lastCrlNumber\" : null"));
        reset();
        assertEquals(2, crl("crl-2.pem"), "a missing number would restart the sequence at 1");
        assertTrue(stderr().contains("is corrupt") && stderr().contains("lastCrlNumber") && stderr().contains("missing"),
                stderr());
        Files.writeString(statePath(), json.replaceAll(",\\s*\"lastCrlNumber\" : \"1\"", ""));
        reset();
        assertEquals(2, crl("crl-2.pem", "--initial"));
        assertTrue(stderr().contains("missing"), stderr());
        assertFalse(Files.exists(path("crl-2.pem")));
    }

    /** A backup restored without the latest state: the last published CRL in --out exposes it. */
    @Test
    void aStaleInventoryIsRefusedAgainstTheCrlItWouldReplace() throws Exception {
        iaca();
        X509Certificate revoked = dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        byte[] backup = Files.readAllBytes(statePath());
        reset();
        assertEquals(0, crl("iaca.crl", "--revoke", hex(revoked), "--overwrite"), stderr());
        Instant revokedAt = readCrl("iaca.crl").getRevokedCertificate(revoked).getRevocationDate().toInstant();
        byte[] published = sha256(path("iaca.crl"));
        Files.write(statePath(), backup);
        reset();

        assertEquals(2, crl("iaca.crl", "--overwrite"), "the restored inventory is at 1, the published CRL at 2");
        assertTrue(stderr().contains("holds CRL number 2 of this IACA, at or above the number 2")
                && stderr().contains("--base-crl " + p("iaca.crl")), stderr());
        reset();
        assertEquals(2, crl("iaca.crl", "--overwrite", "--crl-number", "9"), "a higher number still drops the serial");
        assertTrue(stderr().contains("revokes " + hex(revoked)) && stderr().contains("does not list"), stderr());
        assertArrayEquals(published, sha256(path("iaca.crl")), "the published CRL is untouched");
        reset();

        // the remedy: merge the published CRL, which may be --out itself
        assertEquals(0, crl("iaca.crl", "--overwrite", "--base-crl", p("iaca.crl")), stderr());
        assertTrue(stdout().contains("crlNumber=3\n") && stdout().contains("revoked=1\n"), stdout());
        assertEquals(revokedAt, readCrl("iaca.crl").getRevokedCertificate(revoked).getRevocationDate().toInstant());
        reset();
        // an --out from another IACA is no evidence about this one and is replaced, with a warning
        iaca("other.p12", "other.pem", "Other Demo IACA");
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("other.p12"), "-p", PASSWORD, "--initial",
                "--out", p("foreign.crl")), stderr());
        reset();
        assertEquals(0, crl("foreign.crl", "--overwrite"), stderr());
        assertTrue(stderr().contains("holds a CRL this IACA did not sign"), stderr());
    }

    /** A PEM IACA moved to another directory has no inventory there; --initial must not restart at CRL 1. */
    @Test
    void initialIsRefusedWhenOutHoldsACrlOfTheIaca() throws Exception {
        Files.createDirectories(path("old"));
        Files.createDirectories(path("new"));
        assertEquals(0, run("pki", "iaca", "create", "-p", PASSWORD, "--country", "IN", "--cn", "PEM IACA",
                "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/iaca.crl",
                "--pem-out", p("old/iaca-key.pem")), stderr());
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("old/iaca-key.pem"), "-p", PASSWORD, "--initial",
                "--revoke", "0x1234567890abcdef", "--out", p("iaca.crl")), stderr());
        Files.move(path("old/iaca-key.pem"), path("new/iaca-key.pem"));
        reset();
        assertEquals(2, run("pki", "crl", "issue", "--iaca", p("new/iaca-key.pem"), "-p", PASSWORD, "--initial",
                "--out", p("iaca.crl"), "--overwrite"));
        assertTrue(stderr().contains("holds CRL number 1 of this IACA")
                && stderr().contains("--initial is only for an IACA that never published a CRL"), stderr());
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("new/iaca-key.pem"), "-p", PASSWORD,
                "--base-crl", p("iaca.crl"), "--out", p("iaca.crl"), "--overwrite"), stderr());
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("revoked=1\n"), stdout());
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
        assertTrue(stdout().contains("crlNumber=2\n") && stdout().contains("state=" + statePath() + "\n"),
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
        reset();
        assertEquals(1, run("pki", "check", "--chain", p("iaca.pem"), "--profile", "iaca", "--iaca", p("iaca.pem")),
                "--iaca is not used by --profile iaca");
        assertTrue(stderr().contains("--iaca belongs to --profile mdoc-dsc"), stderr());
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
        // req -x509 makes a CA certificate by default; a signing key needs an end-entity one
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("ca-key.pem"), "-out", p("ca-cert.pem"), "-days", "365", "-subj", "/C=IN/CN=Imported CA");
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD,
                "--alias", "imported-ca", "--key", p("ca-key.pem"), "--chain", p("ca-cert.pem")));
        assertTrue(stderr().contains("KEY_IS_CA") && stderr().contains("basicConstraints CA:true"), stderr());
        assertFalse(Files.exists(path("imported.p12")));
        reset();
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", p("key.pem"), "-out", p("cert.pem"), "-days", "365", "-subj", "/C=IN/CN=Imported DSC",
                "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature");
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
                "-keyout", p("other-key.pem"), "-out", p("other-cert.pem"), "-days", "365", "-subj", "/CN=Other",
                "-addext", "basicConstraints=critical,CA:FALSE");
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
        // PKCS#12 stores no purpose; the listing derives mdoc-dsc from the mDL extended key usage of the DSC
        assertEquals(0, run("keys", "list", "-k", p("imported.p12"), "-p", PASSWORD), stderr());
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("mdl-dsc@2026-11\t")
                && line.contains("\tmdoc-dsc\t")), stdout());
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

    /**
     * RFC 5280 path validation, not only signatures: the reported chain (an issuer with CA:FALSE and only
     * digitalSignature, which OpenSSL rejects with errors 79 and 32) and the other constraints a CA must meet.
     */
    @Test
    void keysImportRefusesAChainThatIsNotAValidCertificationPath() throws Exception {
        Instant now = Instant.now();
        Instant from = now.minus(1, ChronoUnit.HOURS);
        Instant to = now.plus(30, ChronoUnit.DAYS);
        KeyPair rootKey = ecKey();
        KeyPair leafKey = ecKey();
        Files.writeString(path("leaf-key.pem"), Pem.writePrivateKey(leafKey.getPrivate()));

        X509Certificate notACa = certificate("CN=Not A CA", rootKey, "CN=Not A CA", rootKey, from, to,
                basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature));
        assertImportRefused("not-a-ca", certificate("CN=Leaf", leafKey, "CN=Not A CA", rootKey, from, to), notACa,
                "not a valid certification path at CN=Not A CA");
        if (openSslAvailable()) {
            Files.writeString(path("root.pem"), Pem.writeCertificate(notACa));
            OpenSsl result = opensslResult("verify", "-x509_strict", "-CAfile", p("root.pem"), p("not-a-ca.pem"));
            assertTrue(result.code() != 0 && result.output().contains("error 79")
                    && result.output().contains("error 32"), "OpenSSL agrees: " + result.output());
        }

        X509Certificate caFalseNoUsage = certificate("CN=Flag Only", rootKey, "CN=Flag Only", rootKey, from, to,
                basicConstraints(false, -1));
        assertImportRefused("flag-only", certificate("CN=Leaf", leafKey, "CN=Flag Only", rootKey, from, to),
                caFalseNoUsage, "not a CA certificate");

        X509Certificate noCertSign = certificate("CN=No CertSign", rootKey, "CN=No CertSign", rootKey, from, to,
                basicConstraints(true, 0), keyUsage(KeyUsage.digitalSignature));
        assertImportRefused("no-cert-sign", certificate("CN=Leaf", leafKey, "CN=No CertSign", rootKey, from, to),
                noCertSign, "keyCertSign");

        X509Certificate root = certificate("CN=Root", rootKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, 0), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        KeyPair middleKey = ecKey();
        X509Certificate middle = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign));
        X509Certificate belowMiddle = certificate("CN=Leaf", leafKey, "CN=Middle", middleKey, from, to);
        Files.writeString(path("path-len.pem"), Pem.writeCertificates(List.of(belowMiddle, middle, root)));
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "path-len",
                "--key", p("leaf-key.pem"), "--chain", p("path-len.pem")), "pathLen 0 allows no intermediate CA");
        assertTrue(stderr().contains("not a valid certification path"), stderr());
        reset();

        assertImportRefused("expired", certificate("CN=Leaf", leafKey, "CN=Root", rootKey,
                now.minus(30, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS)), root, "not a valid certification path");
        assertImportRefused("unknown-critical", certificate("CN=Leaf", leafKey, "CN=Root", rootKey, from, to,
                Extension.create(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), true, DERNull.INSTANCE)), root,
                "not a valid certification path");

        // what does pass: a leaf under a proper CA, alone with --anchor too, and a standalone self-signed key
        X509Certificate leaf = certificate("CN=Leaf", leafKey, "CN=Root", rootKey, from, to);
        Files.writeString(path("good.pem"), Pem.writeCertificates(List.of(leaf, root)));
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "good",
                "--key", p("leaf-key.pem"), "--chain", p("good.pem")), stderr());
        Files.writeString(path("leaf-only.pem"), Pem.writeCertificate(leaf));
        Files.writeString(path("root.pem"), Pem.writeCertificate(root));
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "anchored",
                "--key", p("leaf-key.pem"), "--chain", p("leaf-only.pem"), "--anchor", p("root.pem")), stderr());
        KeyPair standaloneKey = ecKey();
        Files.writeString(path("standalone-key.pem"), Pem.writePrivateKey(standaloneKey.getPrivate()));
        Files.writeString(path("standalone.pem"), Pem.writeCertificate(certificate("CN=Standalone", standaloneKey,
                "CN=Standalone", standaloneKey, from, to, basicConstraints(false, -1),
                keyUsage(KeyUsage.digitalSignature))));
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "standalone",
                "--key", p("standalone-key.pem"), "--chain", p("standalone.pem")), "a chain of one: " + stderr());
        reset();
        // an --anchor issued by another CA is judged as a CA itself
        Files.writeString(path("middle.pem"), Pem.writeCertificate(certificate("CN=Middle", middleKey, "CN=Root",
                rootKey, from, to, basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature))));
        Files.writeString(path("below.pem"), Pem.writeCertificate(belowMiddle));
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "below",
                "--key", p("leaf-key.pem"), "--chain", p("below.pem"), "--anchor", p("middle.pem")));
        assertTrue(stderr().contains("is not a CA certificate"), stderr());
    }

    void assertImportRefused(String name, X509Certificate leaf, X509Certificate issuer, String reason)
            throws Exception {
        Files.writeString(path(name + ".pem"), Pem.writeCertificate(leaf));
        Files.writeString(path(name + "-chain.pem"), Pem.writeCertificates(List.of(leaf, issuer)));
        reset();
        assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", name,
                "--key", p("leaf-key.pem"), "--chain", p(name + "-chain.pem")), name + ": " + stdout());
        assertTrue(stderr().contains(reason), name + ": " + stderr());
        reset();
    }

    /** The IACA private key never enters an issuer keystore (D3), whichever way it is presented. */
    @Test
    void theIacaKeyIsNeverImportedNorCertifiedAsADocumentSigner() throws Exception {
        iaca();
        KeyStore store = PkiFiles.read(path("iaca.p12"), PASSWORD.toCharArray());
        PrivateKey iacaKey = PkiFiles.privateKey(store, "iaca", PASSWORD.toCharArray());
        X509Certificate iacaCertificate = PkiFiles.chain(store, "iaca").get(0);
        Files.writeString(path("iaca-key.pem"), Pem.writePrivateKey(iacaKey));
        // a Document Signer certificate that certifies the IACA's own key, otherwise Annex B clean
        Instant now = Instant.now();
        KeyPair iacaPair = new KeyPair(iacaCertificate.getPublicKey(), iacaKey);
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        X509Certificate sameKey = certificate("C=IN,ST=Karnataka,CN=Same Key DSC", iacaPair,
                PkiFiles.subject(iacaCertificate), iacaPair, iacaCertificate.getNotBefore().toInstant(),
                now.plus(300, ChronoUnit.DAYS),
                keyUsage(KeyUsage.digitalSignature),
                Extension.create(Extension.extendedKeyUsage, true,
                        new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.0.18013.5.1.2")))),
                Extension.create(Extension.authorityKeyIdentifier, false,
                        utils.createAuthorityKeyIdentifier(iacaCertificate)),
                Extension.create(Extension.subjectKeyIdentifier, false,
                        utils.createSubjectKeyIdentifier(iacaCertificate.getPublicKey())),
                Extension.create(Extension.issuerAlternativeName, false, new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, "https://credentials.example.test"))),
                Extension.create(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                        new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(
                                GeneralName.uniformResourceIdentifier,
                                "https://credentials.example.test/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl"))),
                                null, null)})));
        assertEquals(List.of(), AnnexBValidator.validateDs(sameKey, iacaCertificate),
                "only the key gives it away, which validateDs does not look at");
        Files.writeString(path("same-key-chain.pem"), Pem.writeCertificates(List.of(sameKey, iacaCertificate)));

        assertEquals(2, run("pki", "check", "--chain", p("same-key-chain.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_KEY_IS_IACA_KEY\t")), stdout());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("online.p12"), "-p", PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--key", p("iaca-key.pem"), "--chain", p("same-key-chain.pem"), "--profile", "mdoc-dsc"));
        assertTrue(stdout().lines().anyMatch(line -> line.startsWith("DS_KEY_IS_IACA_KEY\t")), stdout());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("online.p12"), "-p", PASSWORD, "--alias", "same-key",
                "--key", p("iaca-key.pem"), "--chain", p("same-key-chain.pem")), "no profile: still the IACA key");
        assertTrue(stderr().contains("KEY_IS_ISSUER_KEY"), stderr());
        reset();
        assertEquals(2, run("keys", "import", "-k", p("online.p12"), "-p", PASSWORD, "--alias", "iaca",
                "--key", p("iaca-key.pem"), "--chain", p("iaca.pem")), "the IACA itself, as a chain of one");
        assertTrue(stderr().contains("KEY_IS_IACA") && stderr().contains("--iaca"), stderr());
        assertFalse(Files.exists(path("online.p12")), "nothing was written");
    }

    /** Reviewer finding: Root -> Middle (critical 1.2.3.4) -> Leaf imported with --anchor mid.pem. */
    @Test
    void anAnchorIsJudgedItselfIncludingItsCriticalExtensions() throws Exception {
        Instant now = Instant.now();
        Instant from = now.minus(1, ChronoUnit.HOURS);
        Instant to = now.plus(30, ChronoUnit.DAYS);
        KeyPair rootKey = ecKey();
        KeyPair middleKey = ecKey();
        KeyPair leafKey = ecKey();
        Files.writeString(path("leaf-key.pem"), Pem.writePrivateKey(leafKey.getPrivate()));
        X509Certificate root = certificate("CN=Root", rootKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate middle = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign),
                Extension.create(new ASN1ObjectIdentifier("1.2.3.4"), true, DERNull.INSTANCE));
        X509Certificate leaf = certificate("CN=Leaf", leafKey, "CN=Middle", middleKey, from, to,
                basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature));
        Files.writeString(path("root.pem"), Pem.writeCertificate(root));
        Files.writeString(path("mid.pem"), Pem.writeCertificate(middle));
        Files.writeString(path("leaf.pem"), Pem.writeCertificate(leaf));
        Files.writeString(path("leaf-mid.pem"), Pem.writeCertificates(List.of(leaf, middle)));
        for (String[] shape : List.of(new String[] {"leaf.pem", "mid.pem"}, new String[] {"leaf-mid.pem", "mid.pem"},
                new String[] {"leaf-mid.pem", "root.pem"})) {
            reset();
            assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                    "--key", p("leaf-key.pem"), "--chain", p(shape[0]), "--anchor", p(shape[1])),
                    String.join(" ", shape));
            assertTrue(stderr().contains("1.2.3.4") || stderr().contains("critical"), stderr());
        }
        assertFalse(Files.exists(path("imported.p12")), "nothing imported");
        if (openSslAvailable()) {
            OpenSsl result = opensslResult("verify", "-x509_strict", "-CAfile", p("root.pem"), "-untrusted",
                    p("mid.pem"), p("leaf.pem"));
            assertTrue(result.code() != 0 && result.output().contains("error 34"), "OpenSSL agrees: "
                    + result.output());
        }
        // the anchor's other duties: a CA, with keyCertSign, valid now
        X509Certificate expired = certificate("CN=Middle", middleKey, "CN=Root", rootKey,
                now.minus(30, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS), basicConstraints(true, -1),
                keyUsage(KeyUsage.keyCertSign));
        X509Certificate noCertSign = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.digitalSignature));
        for (Map.Entry<X509Certificate, String> anchor : Map.of(expired, "is not valid at", noCertSign,
                "keyCertSign").entrySet()) {
            Files.writeString(path("anchor.pem"), Pem.writeCertificate(anchor.getKey()));
            reset();
            assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                    "--key", p("leaf-key.pem"), "--chain", p("leaf.pem"), "--anchor", p("anchor.pem")));
            assertTrue(stderr().contains(anchor.getValue()), stderr());
        }
        // without the unknown extension, the same shape imports
        X509Certificate plainMiddle = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        Files.writeString(path("mid.pem"), Pem.writeCertificate(plainMiddle));
        reset();
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                "--key", p("leaf-key.pem"), "--chain", p("leaf.pem"), "--anchor", p("mid.pem")), stderr());
    }

    /**
     * Reviewer finding: an --anchor issued by another CA binds the path below it with its own name and policy
     * constraints. Name constraints as OpenSSL applies them to a partial chain ({@code verify -x509_strict
     * -partial_chain -CAfile mid.pem}, error 47). Policy constraints as OpenSSL applies them with the same CA inside the
     * path ({@code -policy_check}, error 43): OpenSSL does not process a partial-chain anchor's policy constraints, but
     * RFC 5937 does, and an intermediate passed as --anchor must not lift a constraint that binds the path when the
     * chain is anchored at its root instead.
     */
    @Test
    void anAnchorsNameAndPolicyConstraintsBindThePathBelowIt() throws Exception {
        requireOpenSsl();
        Instant now = Instant.now();
        Instant from = now.minus(1, ChronoUnit.HOURS);
        Instant to = now.plus(30, ChronoUnit.DAYS);
        KeyPair rootKey = ecKey();
        KeyPair middleKey = ecKey();
        KeyPair leafKey = ecKey();
        Files.writeString(path("leaf-key.pem"), Pem.writePrivateKey(leafKey.getPrivate()));
        // -x509_strict wants key identifiers on every certificate, so OpenSSL fails only for the reason under test
        JcaX509ExtensionUtils ids = new JcaX509ExtensionUtils();
        Extension rootId = Extension.create(Extension.subjectKeyIdentifier, false,
                ids.createSubjectKeyIdentifier(rootKey.getPublic()));
        Extension middleId = Extension.create(Extension.subjectKeyIdentifier, false,
                ids.createSubjectKeyIdentifier(middleKey.getPublic()));
        Extension leafId = Extension.create(Extension.subjectKeyIdentifier, false,
                ids.createSubjectKeyIdentifier(leafKey.getPublic()));
        Extension byRoot = Extension.create(Extension.authorityKeyIdentifier, false,
                ids.createAuthorityKeyIdentifier(rootKey.getPublic()));
        Extension byMiddle = Extension.create(Extension.authorityKeyIdentifier, false,
                ids.createAuthorityKeyIdentifier(middleKey.getPublic()));
        Extension permittedAllowed = Extension.create(Extension.nameConstraints, true, new NameConstraints(
                new GeneralSubtree[] {new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".allowed.example"))},
                null));
        Extension requireExplicitPolicy = Extension.create(Extension.policyConstraints, true,
                new DERSequence(new DERTaggedObject(false, 0, new ASN1Integer(0))));
        Map<String, Extension> constraints = new java.util.LinkedHashMap<>();
        constraints.put("nameConstraints", permittedAllowed);
        constraints.put("policyConstraints", requireExplicitPolicy);
        Map<String, String> openSslError = Map.of("nameConstraints", "error 47", "policyConstraints", "error 43");
        for (Map.Entry<String, Extension> constraint : constraints.entrySet()) {
            String name = constraint.getKey();
            X509Certificate middle = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                    basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign), middleId, byRoot,
                    constraint.getValue());
            X509Certificate bad = certificate("CN=Leaf", leafKey, "CN=Middle", middleKey, from, to,
                    basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature), leafId, byMiddle,
                    Extension.create(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, "bad.example"))));
            X509Certificate root = certificate("CN=Root", rootKey, "CN=Root", rootKey, from, to,
                    basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign), rootId);
            Files.writeString(path("root.pem"), Pem.writeCertificate(root));
            Files.writeString(path("mid.pem"), Pem.writeCertificate(middle));
            Files.writeString(path("bad.pem"), Pem.writeCertificate(bad));
            Files.writeString(path("bad-mid.pem"), Pem.writeCertificates(List.of(bad, middle)));
            OpenSsl refused = "nameConstraints".equals(name)
                    ? opensslResult("verify", "-x509_strict", "-partial_chain", "-CAfile", p("mid.pem"), p("bad.pem"))
                    : opensslResult("verify", "-x509_strict", "-policy_check", "-CAfile", p("root.pem"), "-untrusted",
                            p("mid.pem"), p("bad.pem"));
            assertTrue(refused.code() != 0 && refused.output().contains(openSslError.get(name))
                    && refused.output().split("\\berror \\d+ at").length == 2,
                    name + ": OpenSSL refuses the leaf for that reason alone: " + refused.output());
            for (String chain : List.of("bad.pem", "bad-mid.pem")) {
                reset();
                assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                        "--key", p("leaf-key.pem"), "--chain", p(chain), "--anchor", p("mid.pem")),
                        name + " " + chain + ": " + stdout());
                assertTrue(stderr().contains("not a valid certification path"), name + ": " + stderr());
            }
            reset();
            assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                    "--key", p("leaf-key.pem"), "--chain", p("bad-mid.pem"), "--anchor", p("root.pem")),
                    name + ": anchored at the root, as before");
            assertFalse(Files.exists(path("imported.p12")), name + ": nothing imported");
        }

        // a leaf inside the permitted subtree imports, and OpenSSL agrees
        X509Certificate middle = certificate("CN=Middle", middleKey, "CN=Root", rootKey, from, to,
                basicConstraints(true, -1), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign), middleId, byRoot,
                permittedAllowed);
        X509Certificate good = certificate("CN=Leaf", leafKey, "CN=Middle", middleKey, from, to,
                basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature), leafId, byMiddle,
                Extension.create(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "issuer.allowed.example"))));
        Files.writeString(path("mid.pem"), Pem.writeCertificate(middle));
        Files.writeString(path("good.pem"), Pem.writeCertificate(good));
        openssl("verify", "-x509_strict", "-partial_chain", "-CAfile", p("mid.pem"), p("good.pem"));
        reset();
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "leaf",
                "--key", p("leaf-key.pem"), "--chain", p("good.pem"), "--anchor", p("mid.pem")), stderr());
        assertEquals(List.of(good), PkiFiles.chain(PkiFiles.read(path("imported.p12"), PASSWORD.toCharArray()),
                "leaf"), "the entry stores the chain as given; the anchor's stand-in never leaves the validation");
    }

    /** D3: a CA key never enters an issuer keystore, Annex B IACA or not. */
    @Test
    void aCaKeyIsNeverImported() throws Exception {
        Instant from = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant to = Instant.now().plus(30, ChronoUnit.DAYS);
        KeyPair key = ecKey();
        Files.writeString(path("key.pem"), Pem.writePrivateKey(key.getPrivate()));
        Map<String, Extension[]> shapes = new java.util.LinkedHashMap<>();
        shapes.put("basicConstraints CA:true", new Extension[] {basicConstraints(true, -1)});
        shapes.put("keyUsage keyCertSign", new Extension[] {basicConstraints(false, -1),
                keyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign)});
        shapes.put("keyUsage cRLSign", new Extension[] {keyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign)});
        for (Map.Entry<String, Extension[]> shape : shapes.entrySet()) {
            Files.writeString(path("ca.pem"), Pem.writeCertificate(certificate("CN=Some CA", key, "CN=Some CA", key,
                    from, to, shape.getValue())));
            reset();
            assertEquals(2, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "ca",
                    "--key", p("key.pem"), "--chain", p("ca.pem")), shape.getKey());
            assertTrue(stderr().contains("KEY_IS_CA") && stderr().contains(shape.getKey()), stderr());
        }
        assertFalse(Files.exists(path("imported.p12")));
        Files.writeString(path("ee.pem"), Pem.writeCertificate(certificate("CN=Signer", key, "CN=Signer", key,
                from, to, basicConstraints(false, -1), keyUsage(KeyUsage.digitalSignature))));
        reset();
        assertEquals(0, run("keys", "import", "-k", p("imported.p12"), "-p", PASSWORD, "--alias", "ee",
                "--key", p("key.pem"), "--chain", p("ee.pem")), stderr());
    }

    /** Reviewer finding: --overwrite replaced another IACA's keystore or a CRL state with only a warning. */
    @Test
    void overwriteReplacesOnlyAPreviousOutputOfTheSameKind() throws Exception {
        iaca();
        iaca("other.p12", "other.pem", "Other Demo IACA");
        dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        reset();
        assertEquals(0, run("pki", "crl", "issue", "--iaca", p("other.p12"), "-p", PASSWORD, "--initial",
                "--state", p("other-state.json"), "--out", p("other.crl")), stderr());
        assertEquals(0, run("pki", "iaca", "create", "--pem-out", p("pem-iaca.pem"), "-p", PASSWORD, "--country",
                "IN", "--cn", "PEM IACA", "--issuer-alt-uri", "https://a.test", "--crl-uri", "https://a.test/i.crl"),
                stderr());
        assertEquals(0, run("keys", "generate", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "plain", "--alg",
                "ES256"), stderr());
        // certificate PEMs that are no Document Signer chain: the IACA alone, and a chain that starts with a CA
        Files.writeString(path("iaca-first.pem"), readString("iaca.pem") + readString("other.pem"));
        Map<String, byte[]> victims = new HashMap<>();
        for (String name : List.of("other.p12", "other-state.json", "pem-iaca.pem", "keys.p12", "iaca.crl",
                "dsc-chain.pem", "iaca.pem", "iaca-first.pem")) {
            victims.put(name, sha256(path(name)));
        }

        // crl issue: another IACA's keystore, a CRL state, a key PEM or a chain is no CRL
        for (String victim : List.of("other.p12", "other-state.json", "pem-iaca.pem", "dsc-chain.pem")) {
            reset();
            assertEquals(2, crl(victim, "--overwrite"), victim);
            assertTrue(stderr().contains("--out " + p(victim) + " exists and is not a CRL"), stderr());
        }
        // dsc issue and rotate: a keystore, a CRL, an IACA PEM (key and certificate, or the certificate alone) or a
        // chain that starts with a CA is no Document Signer chain
        for (String victim : List.of("other.p12", "iaca.crl", "pem-iaca.pem", "other-state.json", "iaca.pem",
                "iaca-first.pem")) {
            reset();
            assertEquals(2, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                    "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                    "--out", p(victim), "--overwrite"), victim);
            assertTrue(stderr().contains("exists and is not a PEM chain whose first certificate is an end entity"),
                    stderr());
            reset();
            assertEquals(2, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD,
                    "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--out", p(victim), "--overwrite"), victim);
            assertTrue(stderr().contains("exists and is not a PEM chain whose first certificate is an end entity"),
                    stderr());
        }
        // whatever its basicConstraints, a file that starts with the --iaca certificate is never replaced
        X509Certificate iacaCertificate = Pem.readCertificate(readString("iaca.pem"));
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> PkiCommand.Dsc.refuseIacaOut(path("iaca-first.pem"), iacaCertificate));
        assertTrue(refused.getMessage().contains("holds the --iaca certificate"), refused.getMessage());
        PkiCommand.Dsc.refuseIacaOut(path("dsc-chain.pem"), iacaCertificate); // a previous chain: [DSC, IACA]
        reset();
        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD));
        assertEquals(1, stdout().lines().count(), "no key was added: " + stdout());
        // keys csr: a keystore or a chain is no request; a request is replaced
        for (String victim : List.of("other.p12", "dsc-chain.pem")) {
            reset();
            assertEquals(2, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "plain",
                    "--out", p(victim), "--overwrite"), victim);
            assertTrue(stderr().contains("exists and is not a PKCS#10 request"), stderr());
        }
        for (Map.Entry<String, byte[]> victim : victims.entrySet()) {
            assertArrayEquals(victim.getValue(), sha256(path(victim.getKey())), victim.getKey() + " untouched");
        }
        reset();
        assertEquals(0, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "plain",
                "--out", p("req.pem")), stderr());
        assertEquals(0, run("keys", "csr", "-k", p("keys.p12"), "-p", PASSWORD, "--alias", "plain",
                "--out", p("req.pem"), "--overwrite"), stderr());
        // no CRL number was spent on the refusals; a CRL still replaces a CRL
        reset();
        assertEquals(0, crl("iaca.crl", "--overwrite"), stderr());
        assertTrue(stdout().contains("crlNumber=2\n"), stdout());
    }

    /** Reviewer finding: a hard-linked --out consumed a CRL number on every refused run. */
    @Test
    void hardLinkedOutputsAndKeystoresAreRefusedBeforeANumberOrAKeyIsSpent() throws Exception {
        assumeTrue(SecureFiles.posix(dir), "links");
        iaca();
        dsc("mdl-dsc@2026-10");
        assertEquals(0, crl("iaca.crl", "--initial"), stderr());
        Files.createLink(path("published.crl"), path("iaca.crl"));
        for (int i = 0; i < 2; i++) {
            reset();
            assertEquals(1, crl("iaca.crl", "--overwrite"));
            assertTrue(stderr().contains("has 2 hard links") && stderr().contains("cp -p '" + real("iaca.crl")
                    + "' '" + real("iaca.crl") + ".new' && mv"), stderr());
        }
        String keyId = CrlState.keyId(Pem.readCertificate(readString("iaca.pem")));
        assertEquals(BigInteger.ONE, CrlState.read(statePath()).inventory(keyId).lastCrlNumber(), "no number spent");
        Files.delete(path("published.crl"));
        reset();
        assertEquals(0, crl("iaca.crl", "--overwrite"), stderr());
        assertTrue(stdout().contains("crlNumber=2\n"), stdout());

        Files.createLink(path("issuer-copy.p12"), path("issuer.p12"));
        byte[] issuer = sha256(path("issuer.p12"));
        reset();
        assertEquals(1, run("pki", "dsc", "rotate", "--iaca", p("iaca.p12"), "-p", PASSWORD, "-k", p("issuer.p12"),
                "-P", ISSUER_PASSWORD, "--out", p("new-chain.pem")));
        assertTrue(stderr().contains("has 2 hard links"), stderr());
        reset();
        assertEquals(1, run("keys", "generate", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD, "--alias", "x",
                "--alg", "ES256"));
        assertArrayEquals(issuer, sha256(path("issuer.p12")));
        assertFalse(Files.exists(path("new-chain.pem")));
        Files.createLink(path("chain-copy.pem"), path("dsc-chain.pem"));
        Files.delete(path("issuer-copy.p12"));
        reset();
        assertEquals(1, run("pki", "dsc", "issue", "--iaca", p("iaca.p12"), "-p", PASSWORD, "--generate",
                "-k", p("issuer.p12"), "-P", ISSUER_PASSWORD, "--alias", "mdl-dsc@2026-11",
                "--out", p("dsc-chain.pem"), "--overwrite"));
        reset();
        assertEquals(0, run("keys", "list", "-k", p("issuer.p12"), "-p", ISSUER_PASSWORD));
        assertFalse(stdout().contains("mdl-dsc@2026-11"), "refused before the keystore was touched: " + stdout());
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
        assertTrue(Files.exists(statePath("iaca.pem")), "the inventory beside the PEM IACA, named by its key");
        assertFalse(Files.exists(path("iaca-key.pem.crlstate.json")));
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
        String keyId = CrlState.keyId(PkiFiles.chain(PkiFiles.read(path("iaca.p12"), PASSWORD.toCharArray()), "iaca")
                .get(0));
        String state = CrlState.canonicalName(keyId);
        for (String secret : List.of("iaca.p12", "iaca-key.pem", "issuer.p12", state, state + ".lock",
                "." + keyId + ".crl.lock", "issuer.p12.lock")) {
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

    /** The CLI in a child JVM in {@link #dir}, started and not waited for; output discarded. */
    Process startChild(Map<String, String> env, String... args) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> command = new ArrayList<>(List.of(java, "-cp", System.getProperty("java.class.path"),
                CertifyCli.class.getName()));
        command.addAll(List.of(args));
        ProcessBuilder builder = new ProcessBuilder(command).directory(dir.toFile());
        builder.environment().remove(PkiFiles.IACA_PASSWORD_ENV);
        builder.environment().remove(PkiFiles.KEYSTORE_PASSWORD_ENV);
        builder.environment().putAll(env);
        builder.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
        return builder.start();
    }

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
