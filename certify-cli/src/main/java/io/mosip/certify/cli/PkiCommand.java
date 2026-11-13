package io.mosip.certify.cli;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.Csr;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code certify pki}: the offline half of the ISO/IEC 18013-5 Annex B PKI (M-07).
 *
 * <pre>
 *   export CERTIFY_IACA_PASSWORD=…   CERTIFY_KEYSTORE_PASSWORD=…    # or omit them and answer the prompts
 *   certify pki iaca create -k iaca.p12 --country IN --cn "Lorem Ipsum Demo IACA" \
 *       --issuer-alt-uri https://credentials.example.test --crl-uri https://credentials.example.test/mdoc/iaca/lorem.crl
 *   certify pki dsc issue --iaca iaca.p12 --generate -k issuer.p12 --alias mdl-dsc@2026-11 --out dsc-chain.pem
 *   certify pki dsc issue --iaca iaca.p12 --csr dsc.csr --cn "Lorem Ipsum Demo DSC" --out dsc-chain.pem
 *   certify pki dsc rotate --iaca iaca.p12 -k issuer.p12 --alias-prefix mdl-dsc --out dsc-chain.pem
 *   certify pki crl issue --iaca iaca.p12 --initial --out iaca.crl
 *   certify pki crl issue --iaca iaca.p12 --revoke 0x40a1… --out iaca.crl --overwrite
 *   certify pki check --chain dsc-chain.pem --profile mdoc-dsc --crl iaca.crl
 * </pre>
 *
 * <p>Everything here is offline: the IACA private key is created outside the deployment (D3) and only the Document
 * Signer key, the {@code [DSC, IACA]} chain and the IACA-signed CRL travel into it. Every object is judged by
 * {@link AnnexBValidator} before it is written, so the CLI cannot produce a certificate the runtime would refuse. Every
 * file is written atomically and secrets {@code rw-------} ({@link SecureFiles}); input and output paths that name the
 * same file are refused before anything is written. Output is line-oriented {@code key=value} text on stdout.
 *
 * <p>Exit codes: {@code 0} done; {@code 1} usage (picocli parameter errors, missing or conflicting options, a missing
 * password, overlapping paths, and for {@code pki check} an input it cannot read); {@code 2} a refusal of a well-formed
 * request (Annex B violations, an existing alias or file, a CRL number that does not increase, a wrong password) and
 * {@code pki check} findings.
 */
@Command(name = "pki", description = "ISO/IEC 18013-5 Annex B PKI: IACA, Document Signer and CRL objects.",
        mixinStandardHelpOptions = true,
        subcommands = {PkiCommand.Iaca.class, PkiCommand.Dsc.class, PkiCommand.Crl.class, PkiCommand.Check.class})
class PkiCommand {

    static final String IACA_PROFILE = "iaca";
    static final String DS_PROFILE = "mdoc-dsc";
    static final String DEFAULT_DS_CN = "Lorem Ipsum Demo DSC";
    static final String DS_KEY_IS_IACA_KEY = "DS_KEY_IS_IACA_KEY";
    static final String IACA_PASSWORD = "IACA keystore password";
    static final String KEYSTORE_PASSWORD = "issuer keystore password";

    /**
     * An alias prefix: the part before {@code @}, a KeyRef-safe name in lower case (a PKCS#12 keystore lower-cases
     * every alias, so an upper-case prefix would never match the entries it wrote).
     */
    static final Pattern ALIAS_PREFIX = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");

    private PkiCommand() {}

    // ------------------------------------------------------------------ shared

    /** Runs a command body and maps its failure to the exit code and one line on stderr. */
    static int execute(Callable<Integer> body, String failing) {
        try {
            return body.call();
        } catch (UsageException e) {
            return error(1, e.getMessage());
        } catch (FileAlreadyExistsException e) {
            return error(2, e.getFile() + " already exists; refusing to overwrite it");
        } catch (IOException e) {
            return error(2, failing + ": " + e.getMessage());
        } catch (Exception e) {
            return error(2, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    static int error(int code, String message) {
        System.err.println(message);
        return code;
    }

    static void print(String rule, String message) {
        System.out.println(rule + "\t" + message);
    }

    static int violations(List<AnnexBValidator.Violation> violations, String what) {
        for (AnnexBValidator.Violation violation : violations) {
            print(violation.ruleId(), violation.message());
        }
        System.err.println(what + ": " + violations.size() + " violation(s)");
        return 2;
    }

    static String nullIfEmpty(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /** A certificate or CRL {@code --out} that exists is refused unless {@code --overwrite}. */
    static void refuseExisting(Path out, boolean overwrite) {
        if (out != null && !overwrite && Files.exists(out)) {
            throw new IllegalArgumentException(out + " already exists; pass --overwrite to replace it");
        }
    }

    static String pem(Path path) throws IOException {
        return Files.readString(path, StandardCharsets.US_ASCII);
    }

    static byte[] encoded(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (java.security.cert.CRLException e) {
            throw new IllegalStateException("cannot encode the CRL", e);
        }
    }

    /** A CRL in PEM or DER, told apart by content, not by file name. */
    static X509CRL readCrl(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (text.contains("-----BEGIN X509 CRL-----")) {
            return Pem.readCrl(text);
        }
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(bytes));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("cannot read the CRL " + path + " as PEM or DER: " + e.getMessage(), e);
        }
    }

    /** An IACA certificate and the private key that signs DSCs and CRLs with it. */
    record IacaKey(X509Certificate certificate, PrivateKey privateKey) {

        KeyPair keyPair() {
            return new KeyPair(certificate.getPublicKey(), privateKey);
        }

        /**
         * The IACA from a PKCS#12 keystore entry, or from a PEM file holding an encrypted PKCS#8 private key and the
         * certificate (the form {@code --pem-out} writes, combined), told apart by content.
         */
        static IacaKey load(Path path, char[] password, String alias) throws IOException {
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("no such IACA keystore or PEM file: " + path);
            }
            byte[] bytes = Files.readAllBytes(path);
            String text = new String(bytes, StandardCharsets.US_ASCII);
            if (text.startsWith("-----BEGIN ") || text.contains("\n-----BEGIN ")) {
                return new IacaKey(certificate(text), Pem.readPrivateKey(text, password));
            }
            KeyStore store = PkiFiles.read(path, password);
            List<X509Certificate> chain = PkiFiles.chain(store, alias);
            return new IacaKey(chain.get(0), PkiFiles.privateKey(store, alias, password));
        }

        /** The first CERTIFICATE block, so a file that also holds the private key can be read. */
        private static X509Certificate certificate(String text) {
            String begin = "-----BEGIN CERTIFICATE-----";
            String end = "-----END CERTIFICATE-----";
            int start = text.indexOf(begin);
            int stop = start < 0 ? -1 : text.indexOf(end, start);
            if (stop < 0) {
                throw new IllegalArgumentException("the IACA PEM file has no CERTIFICATE block");
            }
            return Pem.readCertificate(text.substring(start, stop + end.length()));
        }
    }

    // ------------------------------------------------------------------ pki iaca

    @Command(name = "iaca", description = "IACA certificate operations.", mixinStandardHelpOptions = true,
            subcommands = Iaca.Create.class)
    static class Iaca {

        @Command(name = "create", mixinStandardHelpOptions = true,
                description = "Create an offline IACA key and self-signed Annex B IACA certificate.")
        static class Create implements Callable<Integer> {

            @Option(names = {"-k", "--keystore"},
                    description = "new or existing PKCS#12 file for the IACA key (or --pem-out)")
            Path keystore;
            @Option(names = {"-p", "--iaca-password"}, arity = "0..1", interactive = true,
                    description = "IACA password; " + PkiFiles.IACA_PASSWORD_ENV + " when absent, prompted when neither")
            char[] password;
            @Option(names = "--alias", defaultValue = "iaca", description = "key alias in the keystore")
            String alias;
            @Option(names = "--country", required = true, description = "subject C, ISO 3166-1 alpha-2 (demo: IN)")
            String country;
            @Option(names = "--state", description = "subject ST, optional") String state;
            @Option(names = "--org", description = "subject O, optional") String organization;
            @Option(names = "--cn", required = true,
                    description = "subject CN (demo: \"Lorem Ipsum Demo IACA\")") String commonName;
            @Option(names = "--issuer-alt-uri", description = "issuerAltName URI (at least one of the two alt names)")
            String issuerAltUri;
            @Option(names = "--issuer-alt-email", description = "issuerAltName mailbox (at least one alt name)")
            String issuerAltEmail;
            @Option(names = "--crl-uri", required = true, description = "CRL distribution point URI, absolute http(s)")
            String crlUri;
            @Option(names = "--validity-years", defaultValue = "10", description = "lifetime in years, 1..20")
            int validityYears;
            @Option(names = "--alg", defaultValue = "ES256", description = "ES256, ES384 or ES512")
            String algorithm;
            @Option(names = "--pem-out",
                    description = "write the key as an encrypted PKCS#8 PEM (plus the certificate) instead of -k")
            Path pemOut;

            @Override
            public Integer call() {
                return execute(this::create, "cannot write the IACA");
            }

            private Integer create() throws IOException {
                if ((keystore == null) == (pemOut == null)) {
                    throw new UsageException("pass exactly one of -k <iaca.p12> or --pem-out <iaca.pem>");
                }
                if (validityYears < 1 || validityYears > 20) {
                    throw new UsageException("--validity-years is " + validityYears
                            + "; Annex B allows 1 to 20 calendar years");
                }
                PkiFiles.curve(algorithm);
                PkiFiles.requireLowerCaseAlias(alias, "--alias");
                Path store = keystore == null ? null : SecureFiles.canonical(keystore);
                char[] secret = PkiFiles.password(password, PkiFiles.IACA_PASSWORD_ENV, IACA_PASSWORD, "-p");
                try {
                    X509Certificate iaca;
                    if (pemOut != null) {
                        KeyPair keyPair = PkiFiles.keyPair(algorithm);
                        iaca = build(keyPair);
                        if (iaca == null) {
                            return 2;
                        }
                        // the key first (so `openssl pkey -in iaca.pem` reads it), then the certificate, so the same
                        // file can stand in for the keystore wherever this CLI takes --iaca; CREATE_NEW refuses an
                        // existing file
                        SecureFiles.write(pemOut, (Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), secret)
                                        + Pem.writeCertificate(iaca)).getBytes(StandardCharsets.US_ASCII),
                                SecureFiles.Visibility.SECRET, false);
                    } else {
                        try (SecureFiles.Lock lock = SecureFiles.lock(store)) {
                            boolean exists = Files.exists(store);
                            KeyStore keys = PkiFiles.readOrCreate(store, secret);
                            if (PkiFiles.contains(keys, alias)) {
                                throw new IllegalArgumentException("alias already exists in " + keystore + ": "
                                        + alias);
                            }
                            KeyPair keyPair = PkiFiles.keyPair(algorithm);
                            iaca = build(keyPair);
                            if (iaca == null) {
                                return 2;
                            }
                            PkiFiles.add(keys, alias, keyPair.getPrivate(), secret, List.of(iaca));
                            PkiFiles.write(keys, store, secret, exists);
                        }
                    }
                    // the certificate is the only thing on stdout, so `> iaca.pem` yields a publishable file
                    System.out.print(Pem.writeCertificate(iaca));
                    System.err.println("IACA created: alias=" + alias + " store=" + (pemOut != null ? pemOut : keystore));
                    System.err.println("sha256=" + PkiFiles.sha256(iaca));
                    return 0;
                } finally {
                    PkiFiles.clear(secret, password);
                }
            }

            /** The IACA certificate, or {@code null} after printing its violations. */
            private X509Certificate build(KeyPair keyPair) {
                Instant start = Instant.now().truncatedTo(ChronoUnit.SECONDS);
                Duration validity = Duration.between(start,
                        start.atZone(ZoneOffset.UTC).plusYears(validityYears).toInstant());
                X509Certificate iaca = IsoMdocProfiles.iaca(keyPair)
                        .country(country)
                        .state(nullIfEmpty(state))
                        .organization(nullIfEmpty(organization))
                        .commonName(commonName)
                        .issuerAltUri(nullIfEmpty(issuerAltUri))
                        .issuerAltEmail(nullIfEmpty(issuerAltEmail))
                        .crlDistributionPoint(crlUri)
                        .notBefore(start)
                        .validity(validity)
                        .build();
                List<AnnexBValidator.Violation> violations = AnnexBValidator.validateIaca(iaca);
                if (!violations.isEmpty()) {
                    PkiCommand.violations(violations, "IACA");
                    return null;
                }
                return iaca;
            }
        }
    }

    // ------------------------------------------------------------------ pki dsc

    @Command(name = "dsc", description = "Document Signer certificate operations.", mixinStandardHelpOptions = true,
            subcommands = {Dsc.Issue.class, Dsc.Rotate.class})
    static class Dsc {

        @Command(name = "issue", mixinStandardHelpOptions = true,
                description = "Sign a PKCS#10 request or a new key with the IACA and write the [DSC, IACA] chain.")
        static class Issue implements Callable<Integer> {

            @Option(names = "--iaca", required = true, description = "IACA PKCS#12 keystore, or a PEM key+certificate")
            Path iaca;
            @Option(names = {"-p", "--iaca-password"}, arity = "0..1", interactive = true,
                    description = "IACA password; " + PkiFiles.IACA_PASSWORD_ENV + " when absent, prompted when neither")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = "--csr", description = "PKCS#10 request to certify (DER or PEM), e.g. from a keymanager")
            Path csr;
            @Option(names = "--generate", description = "generate a new Document Signer key in -k instead of a CSR")
            boolean generate;
            @Option(names = {"-k", "--keystore"}, description = "issuer PKCS#12 keystore for --generate") Path keystore;
            @Option(names = {"-P", "--issuer-password"}, arity = "0..1", interactive = true,
                    description = "issuer keystore password; " + PkiFiles.KEYSTORE_PASSWORD_ENV
                            + " when absent, prompted when neither")
            char[] issuerPassword;
            @Option(names = "--alias", description = "alias of the generated key, e.g. mdl-dsc@2026-11")
            String alias;
            @Option(names = "--cn", description = "Document Signer CN; required with --csr (the CN a request asks for"
                    + " is never copied), default \"" + DEFAULT_DS_CN + "\" with --generate")
            String commonName;
            @Option(names = "--validity-days", defaultValue = "365", description = "lifetime in days, 1..457")
            int validityDays;
            @Option(names = "--alg", defaultValue = "ES256", description = "key algorithm for --generate")
            String algorithm;
            @Option(names = "--out", required = true, description = "output chain PEM, [DSC, IACA] leaf first")
            Path out;
            @Option(names = {"--overwrite", "--force"}, description = "replace an existing --out file")
            boolean overwrite;

            @Override
            public Integer call() {
                return execute(this::issue, "cannot write the Document Signer");
            }

            private Integer issue() throws IOException {
                if ((csr == null) == !generate) {
                    throw new UsageException("pass exactly one of --csr <file> or --generate");
                }
                checkValidity(validityDays);
                if (csr != null) {
                    if (commonName == null || commonName.isBlank()) {
                        throw new UsageException("--csr needs --cn <name>: the Document Signer's CN is the operator's"
                                + " choice and is never copied from the request");
                    }
                    if (keystore != null || alias != null) {
                        throw new UsageException("-k and --alias belong to --generate; with --csr the key stays where"
                                + " the request was made");
                    }
                    SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iaca, "--csr", csr),
                            SecureFiles.paths("--out", out));
                    refuseExisting(out, overwrite);
                    char[] secret = PkiFiles.password(password, PkiFiles.IACA_PASSWORD_ENV, IACA_PASSWORD, "-p");
                    try {
                        IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                        Csr request = Csr.parse(Files.readAllBytes(csr));
                        return Dsc.issue(authority, request.publicKey(), null, commonName, validityDays, out, overwrite,
                                null, null, false, null, null);
                    } finally {
                        PkiFiles.clear(secret, password);
                    }
                }
                if (keystore == null) {
                    throw new UsageException("--generate needs -k <issuer.p12>");
                }
                if (alias == null || alias.isBlank()) {
                    throw new UsageException("--generate needs --alias <name>");
                }
                PkiFiles.requireLowerCaseAlias(alias, "--alias");
                PkiFiles.curve(algorithm);
                Path store = SecureFiles.canonical(keystore);
                SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iaca),
                        SecureFiles.paths("-k", store, "--out", out, "the lock of -k", SecureFiles.lockFile(store)));
                refuseExisting(out, overwrite);
                char[] secret = PkiFiles.password(password, PkiFiles.IACA_PASSWORD_ENV, IACA_PASSWORD, "-p");
                char[] issuerSecret = null;
                try {
                    issuerSecret = PkiFiles.password(issuerPassword, PkiFiles.KEYSTORE_PASSWORD_ENV,
                            KEYSTORE_PASSWORD, "-P");
                    IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                    try (SecureFiles.Lock lock = SecureFiles.lock(store)) {
                        boolean exists = Files.exists(store);
                        KeyStore keys = PkiFiles.readOrCreate(store, issuerSecret);
                        if (PkiFiles.contains(keys, alias)) {
                            throw new IllegalArgumentException("alias already exists in " + keystore + ": " + alias);
                        }
                        KeyPair keyPair = PkiFiles.keyPair(algorithm);
                        return Dsc.issue(authority, keyPair.getPublic(), keyPair.getPrivate(),
                                commonName != null ? commonName : DEFAULT_DS_CN, validityDays, out, overwrite,
                                keys, store, exists, issuerSecret, alias);
                    }
                } finally {
                    PkiFiles.clear(secret, issuerSecret, password, issuerPassword);
                }
            }
        }

        @Command(name = "rotate", mixinStandardHelpOptions = true,
                description = "Issue a new versioned Document Signer (<prefix>@yyyy-MM[.N]) and keep the old ones.")
        static class Rotate implements Callable<Integer> {

            @Option(names = "--iaca", required = true, description = "IACA PKCS#12 keystore, or a PEM key+certificate")
            Path iaca;
            @Option(names = {"-p", "--iaca-password"}, arity = "0..1", interactive = true,
                    description = "IACA password; " + PkiFiles.IACA_PASSWORD_ENV + " when absent, prompted when neither")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = {"-k", "--keystore"}, required = true, description = "existing issuer PKCS#12 keystore")
            Path keystore;
            @Option(names = {"-P", "--issuer-password"}, arity = "0..1", interactive = true,
                    description = "issuer keystore password; " + PkiFiles.KEYSTORE_PASSWORD_ENV
                            + " when absent, prompted when neither")
            char[] issuerPassword;
            @Option(names = "--alias-prefix", defaultValue = "mdl-dsc",
                    description = "alias prefix; the new alias is <prefix>@<yyyy-MM>, or <prefix>@<yyyy-MM>.<N> when"
                            + " this month's already exists")
            String aliasPrefix;
            @Option(names = "--suffix", description = "force the same-month suffix N (2 or more), e.g. 2 for"
                    + " mdl-dsc@2026-11.2; default: the next free one when this month's alias exists")
            Integer suffix;
            @Option(names = "--cn", description = "Document Signer CN (default: a demo name with the month)")
            String commonName;
            @Option(names = "--validity-days", defaultValue = "365", description = "lifetime in days, 1..457")
            int validityDays;
            @Option(names = "--alg", defaultValue = "ES256", description = "key algorithm for the new key")
            String algorithm;
            @Option(names = "--out", description = "output chain PEM; stdout when omitted") Path out;
            @Option(names = {"--overwrite", "--force"}, description = "replace an existing --out file")
            boolean overwrite;

            @Override
            public Integer call() {
                return execute(this::rotate, "cannot write the Document Signer");
            }

            private Integer rotate() throws IOException {
                PkiFiles.requireLowerCaseAlias(aliasPrefix, "--alias-prefix");
                if (!ALIAS_PREFIX.matcher(aliasPrefix).matches()) {
                    throw new UsageException("--alias-prefix must be lower-case letters, digits, '.', '_' or '-' (no"
                            + " '@' or ':'), at most 64 characters: " + aliasPrefix);
                }
                if (suffix != null && suffix < 2) {
                    throw new UsageException("--suffix starts at 2: the month's first Document Signer has none");
                }
                checkValidity(validityDays);
                PkiFiles.curve(algorithm);
                Path store = SecureFiles.canonical(keystore);
                SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iaca),
                        SecureFiles.paths("-k", store, "--out", out, "the lock of -k", SecureFiles.lockFile(store)));
                refuseExisting(out, overwrite);
                char[] secret = PkiFiles.password(password, PkiFiles.IACA_PASSWORD_ENV, IACA_PASSWORD, "-p");
                char[] issuerSecret = null;
                try {
                    issuerSecret = PkiFiles.password(issuerPassword, PkiFiles.KEYSTORE_PASSWORD_ENV,
                            KEYSTORE_PASSWORD, "-P");
                    IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                    try (SecureFiles.Lock lock = SecureFiles.lock(store)) {
                        KeyStore keys = PkiFiles.read(store, issuerSecret);
                        String month = YearMonth.now(ZoneOffset.UTC).toString();
                        String alias = Rotation.nextAlias(PkiFiles.aliases(keys), aliasPrefix + "@" + month, suffix);
                        KeyPair keyPair = PkiFiles.keyPair(algorithm);
                        String name = commonName != null ? commonName : DEFAULT_DS_CN + " " + month;
                        int code = Dsc.issue(authority, keyPair.getPublic(), keyPair.getPrivate(), name, validityDays,
                                out, overwrite, keys, store, true, issuerSecret, alias);
                        if (code == 0) {
                            Optional<String> current = Rotation.current(keys, aliasPrefix, Instant.now());
                            // without --out the chain PEM ends stdout, so nothing may follow it there
                            (out != null ? System.out : System.err).println("current=" + current.orElse(""));
                            System.err.println("kept the older Document Signers of " + aliasPrefix + " in " + keystore
                                    + "; x509-file:" + aliasPrefix + " resolves to " + current.orElse("(none valid)")
                                    + " (M-05 rotation rule: the entry valid now with the newest notBefore; needs the"
                                    + " x509-file provider with versioned aliases, certify 1.0.0-beta.1 rebuild);"
                                    + " pin this one with x509-file:" + alias);
                        }
                        return code;
                    }
                } finally {
                    PkiFiles.clear(secret, issuerSecret, password, issuerPassword);
                }
            }
        }

        static void checkValidity(int validityDays) {
            if (validityDays < 1 || validityDays > IsoMdocProfiles.DS_MAX_VALIDITY.toDays()) {
                throw new UsageException("--validity-days is " + validityDays + "; Annex B allows 1 to "
                        + IsoMdocProfiles.DS_MAX_VALIDITY.toDays());
            }
        }

        /**
         * Signs one Document Signer, validates it, stores a generated key with its chain (keystore first: the chain
         * is in the keystore entry too, so a failed {@code --out} loses nothing), then writes the chain. The caller
         * holds the keystore lock and has refused an existing alias.
         */
        static int issue(IacaKey authority, PublicKey subjectKey, PrivateKey subjectPrivate, String commonName,
                         int validityDays, Path out, boolean overwrite, KeyStore store, Path storePath,
                         boolean storeExists, char[] storePassword, String alias) throws IOException {
            if (PkiFiles.sameKey(subjectKey, authority.certificate().getPublicKey())) {
                throw new IllegalArgumentException("DS_KEY_IS_IACA_KEY: the Document Signer key is the IACA's own key;"
                        + " a Document Signer needs a key of its own");
            }
            X509Certificate dsc = IsoMdocProfiles.ds(subjectKey, authority.certificate(), authority.keyPair())
                    .commonName(commonName)
                    .validity(Duration.ofDays(validityDays))
                    .build();
            List<AnnexBValidator.Violation> violations = AnnexBValidator.validateDs(dsc, authority.certificate());
            if (!violations.isEmpty()) {
                return PkiCommand.violations(violations, "Document Signer");
            }
            List<X509Certificate> chain = List.of(dsc, authority.certificate());
            if (store != null) {
                PkiFiles.add(store, alias, subjectPrivate, storePassword, chain);
                PkiFiles.write(store, storePath, storePassword, storeExists);
            }
            if (out != null) {
                SecureFiles.write(out, Pem.writeCertificates(chain).getBytes(StandardCharsets.US_ASCII),
                        SecureFiles.Visibility.PUBLIC, overwrite);
            }
            System.out.println("serial=0x" + dsc.getSerialNumber().toString(16));
            System.out.println("subject=" + dsc.getSubjectX500Principal().getName());
            System.out.println("notBefore=" + dsc.getNotBefore().toInstant());
            System.out.println("notAfter=" + dsc.getNotAfter().toInstant());
            if (alias != null) {
                System.out.println("alias=" + alias);
            }
            if (out != null) {
                System.out.println("chain=" + out);
            } else {
                System.out.println();
                System.out.print(Pem.writeCertificates(chain));
            }
            return 0;
        }
    }

    /**
     * Versioned Document Signer aliases, consistent with the {@code x509-file} provider (M-05): one key entry per
     * version, {@code <prefix>@<yyyy-MM>} and, for a second rotation in the same month, {@code <prefix>@<yyyy-MM>.<N>}
     * with N from 2. {@code x509-file:<prefix>} resolves to the entry valid now with the newest {@code notBefore}, ties
     * broken by the version label compared numerically (runs of digits as numbers, so {@code 2026-11.10} comes after
     * {@code 2026-11.9}, as M-05's {@code VersionLabels} orders them); a versioned reference resolves to that entry.
     */
    static final class Rotation {

        private Rotation() {}

        /** The alias for this rotation: the month's base alias, or the forced or next free {@code .N} after it. */
        static String nextAlias(List<String> aliases, String base, Integer suffix) {
            Set<String> existing = new LinkedHashSet<>(aliases);
            if (suffix != null) {
                String alias = base + "." + suffix;
                if (existing.contains(alias)) {
                    throw new IllegalArgumentException("the Document Signer " + alias + " already exists; pass another"
                            + " --suffix, or none for the next free one");
                }
                return alias;
            }
            if (!existing.contains(base)) {
                return base;
            }
            Pattern numbered = Pattern.compile(Pattern.quote(base) + "\\.(\\d{1,6})");
            int next = 2;
            for (String alias : existing) {
                Matcher matcher = numbered.matcher(alias);
                if (matcher.matches()) {
                    next = Math.max(next, Integer.parseInt(matcher.group(1)) + 1);
                }
            }
            return base + "." + next;
        }

        /** The entry {@code x509-file:<prefix>} resolves to at {@code at}: valid then, newest notBefore, then label. */
        static Optional<String> current(KeyStore store, String prefix, Instant at) {
            Map<String, X509Certificate> candidates = new LinkedHashMap<>();
            for (String alias : PkiFiles.aliases(store)) {
                if (alias.equals(prefix) || alias.startsWith(prefix + "@")) {
                    try {
                        if (store.getCertificate(alias) instanceof X509Certificate leaf
                                && !at.isBefore(leaf.getNotBefore().toInstant())
                                && at.isBefore(leaf.getNotAfter().toInstant())) {
                            candidates.put(alias, leaf);
                        }
                    } catch (GeneralSecurityException e) {
                        // an unreadable entry is not a candidate
                    }
                }
            }
            return candidates.entrySet().stream()
                    .max(Comparator.<Map.Entry<String, X509Certificate>, Instant>comparing(
                                    e -> e.getValue().getNotBefore().toInstant())
                            .thenComparing(e -> e.getKey(), Rotation::compareLabels))
                    .map(Map.Entry::getKey);
        }

        /**
         * Version labels in numeric-aware order: digit runs compare as numbers ({@code .10} after {@code .9}, leading
         * zeros ignored), other runs as text, a label that is a prefix of another first; equal by that order, the
         * plain string order decides.
         */
        static int compareLabels(String a, String b) {
            List<String> left = runs(a);
            List<String> right = runs(b);
            for (int i = 0; i < Math.min(left.size(), right.size()); i++) {
                String x = left.get(i);
                String y = right.get(i);
                int order;
                if (Character.isDigit(x.charAt(0)) && Character.isDigit(y.charAt(0))) {
                    order = new BigInteger(x).compareTo(new BigInteger(y));
                } else {
                    order = x.compareTo(y);
                }
                if (order != 0) {
                    return order;
                }
            }
            int bySize = Integer.compare(left.size(), right.size());
            return bySize != 0 ? bySize : a.compareTo(b);
        }

        private static final Pattern RUNS = Pattern.compile("[0-9]+|[^0-9]+");

        private static List<String> runs(String label) {
            List<String> runs = new ArrayList<>();
            Matcher matcher = RUNS.matcher(label);
            while (matcher.find()) {
                runs.add(matcher.group());
            }
            return runs;
        }
    }

    // ------------------------------------------------------------------ pki crl

    @Command(name = "crl", description = "CRL operations.", mixinStandardHelpOptions = true,
            subcommands = Crl.Issue.class)
    static class Crl {

        @Command(name = "issue", mixinStandardHelpOptions = true,
                description = "Sign a complete X.509 v2 CRL with the IACA: every serial ever revoked (from the"
                        + " revocation inventory next to the IACA) plus --revoke, under the next CRL number.")
        static class Issue implements Callable<Integer> {

            @Option(names = "--iaca", required = true, description = "IACA PKCS#12 keystore, or a PEM key+certificate")
            Path iaca;
            @Option(names = {"-p", "--iaca-password"}, arity = "0..1", interactive = true,
                    description = "IACA password; " + PkiFiles.IACA_PASSWORD_ENV + " when absent, prompted when neither")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = "--revoke", description = "serial to revoke, hexadecimal (0x prefixed or not); repeatable")
            List<String> revoke = new ArrayList<>();
            @Option(names = "--crl-number",
                    description = "cRLNumber; default the last recorded + 1, and never at or below the last recorded")
            String crlNumber;
            @Option(names = "--next-update-days", defaultValue = "30", description = "days until the next CRL is due")
            int nextUpdateDays;
            @Option(names = "--state", description = "revocation inventory file (default: the file in the IACA's"
                    + " directory that records this IACA, else iaca-<ski>" + CrlState.SUFFIX + " there)")
            Path state;
            @Option(names = "--base-crl", description = "import the entries and number of a CRL this IACA published"
                    + " (verified under the IACA), e.g. when the inventory was never kept or is older than that CRL;"
                    + " may be the --out file itself")
            Path baseCrl;
            @Option(names = "--initial", description = "the IACA's first CRL: no inventory exists and none is needed")
            boolean initial;
            @Option(names = "--force", description = "recover a lost inventory without --base-crl: needs an explicit"
                    + " --crl-number above every number ever published; earlier revocations are listed only if passed"
                    + " again with --revoke. Refused when an inventory exists")
            boolean force;
            @Option(names = "--out", required = true, description = "output CRL; DER for a .der name, PEM otherwise."
                    + " Pass the last published CRL here (with --overwrite) or as --base-crl: a stale inventory is"
                    + " then detected")
            Path out;
            @Option(names = "--overwrite", description = "replace an existing --out file (the previous CRL)")
            boolean overwrite;

            @Override
            public Integer call() {
                return execute(this::issue, "cannot write the CRL");
            }

            private Integer issue() throws IOException {
                if (nextUpdateDays < 1) {
                    throw new UsageException("--next-update-days must be at least 1");
                }
                BigInteger requested = crlNumber == null ? null : parseNumber(crlNumber);
                Set<BigInteger> serials = new LinkedHashSet<>();
                for (String serial : revoke) {
                    serials.add(parseSerial(serial));
                }
                if (initial && (force || baseCrl != null)) {
                    throw new UsageException("--initial is the IACA's first CRL; it does not combine with --force or"
                            + " --base-crl");
                }
                if (force && baseCrl != null) {
                    throw new UsageException("--base-crl rebuilds the inventory; --force is for when no CRL is left");
                }
                if (force && requested == null) {
                    throw new UsageException("--force needs --crl-number, greater than every CRL number this IACA has"
                            + " published: without the inventory the CLI cannot know the last one");
                }
                String outName = out.getFileName() == null ? "" : out.getFileName().toString();
                if (outName.endsWith(CrlState.SUFFIX) || outName.endsWith(".lock")) {
                    throw new UsageException("--out " + out + " is named like a CRL state or lock file; name the CRL"
                            + " .crl, .pem or .der");
                }
                SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iaca), SecureFiles.paths("--out", out,
                        "--state", state));
                refuseExisting(out, overwrite);
                char[] secret = PkiFiles.password(password, PkiFiles.IACA_PASSWORD_ENV, IACA_PASSWORD, "-p");
                try {
                    // one real path for the IACA: discovery looks in its real directory, never the link's
                    Path iacaPath = SecureFiles.canonical(iaca);
                    IacaKey authority = IacaKey.load(iacaPath, secret, iacaAlias);
                    String keyId = CrlState.keyId(authority.certificate());
                    Path explicit = state == null ? null : SecureFiles.canonical(state);
                    Map<String, Path> identityLocks = new LinkedHashMap<>();
                    identityLocks.put("the CRL lock of this IACA",
                            CrlState.identityLock(iacaPath.getParent(), keyId));
                    if (explicit != null && !explicit.getParent().equals(iacaPath.getParent())) {
                        identityLocks.put("the CRL lock of this IACA beside --state",
                                CrlState.identityLock(explicit.getParent(), keyId));
                    }
                    X509CRL base = baseCrl == null ? null : verifiedBase(baseCrl, authority.certificate());
                    // the identity lock comes before discovery: two copies of one IACA (a.p12, b.p12) can neither
                    // both find no inventory nor both create one
                    try (SecureFiles.Lock identity = SecureFiles.lockAll(identityLocks.values())) {
                        CrlState.Location location = CrlState.discover(iacaPath, keyId, explicit);
                        Path statePath = location.path();
                        Map<String, Path> written = new LinkedHashMap<>();
                        written.put("the CRL state", statePath);
                        written.put("the lock of the CRL state", SecureFiles.lockFile(statePath));
                        written.putAll(identityLocks);
                        // --base-crl may be the --out file: it is read whole before anything is written
                        SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iacaPath, "--base-crl", baseCrl),
                                written);
                        Map<String, Path> outputs = new LinkedHashMap<>(SecureFiles.paths("--out", out));
                        outputs.putAll(written);
                        SecureFiles.requireDistinct(SecureFiles.paths("--iaca", iacaPath), outputs);
                        if (location.migratedFrom() != null) {
                            System.err.println("renamed the CRL state " + location.migratedFrom() + " to " + statePath
                                    + " (one inventory per IACA, named by its subject key identifier)");
                        }
                        try (SecureFiles.Lock file = SecureFiles.lock(statePath)) {
                            return issue(authority, keyId, statePath, base, requested, serials);
                        }
                    }
                } finally {
                    PkiFiles.clear(secret, password);
                }
            }

            private Integer issue(IacaKey authority, String keyId, Path statePath, X509CRL base, BigInteger requested,
                                  Set<BigInteger> serials) throws IOException {
                CrlState current = CrlState.read(statePath);
                CrlState.Inventory inventory = current == null ? null : current.inventory(keyId);
                if (inventory == null) {
                    if (base == null && !initial && !force) {
                        throw new IllegalArgumentException("no revocation inventory for this IACA in " + statePath
                                + ": a CRL issued now would drop every earlier revocation. Pass --base-crl <the last"
                                + " CRL this IACA published> to rebuild it, or --initial for the IACA's first CRL");
                    }
                    inventory = new CrlState.Inventory(authority.certificate().getSubjectX500Principal().getName(),
                            null);
                    if (force) {
                        System.err.println("warning: --force: no revocation inventory and no base CRL; this CRL lists"
                                + " only the serials passed with --revoke, and the inventory starts again from it");
                    }
                } else if (initial || force) {
                    throw new IllegalArgumentException((initial ? "--initial" : "--force") + " is for an IACA without"
                            + " a revocation inventory, but " + statePath + " records CRL number "
                            + inventory.lastCrlNumber() + " for this IACA; drop the option");
                }
                if (base != null) {
                    inventory.importCrl(base, CrlState.crlNumber(base));
                }
                BigInteger last = inventory.lastCrlNumber();
                BigInteger number = requested != null ? requested
                        : last == null ? BigInteger.ONE : last.add(BigInteger.ONE);
                if (last != null && number.compareTo(last) <= 0) {
                    throw new IllegalArgumentException("the CRL number " + number + " does not increase on the last"
                            + " recorded one " + last + " (" + statePath + "); omit --crl-number for " + last.add(
                            BigInteger.ONE) + " or pass a larger one");
                }
                refuseStale(previousCrl(authority.certificate()), inventory, number, statePath);
                Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
                int added = 0;
                for (BigInteger serial : serials) {
                    if (inventory.isRevoked(serial)) {
                        System.err.println("0x" + serial.toString(16) + " is already revoked since "
                                + inventory.revoked().get(serial) + "; the original date is kept");
                    } else {
                        inventory.revoke(serial, now);
                        added++;
                    }
                }
                Instant next = now.plus(Duration.ofDays(nextUpdateDays));
                Instant iacaNotAfter = authority.certificate().getNotAfter().toInstant().truncatedTo(ChronoUnit.SECONDS);
                if (next.isAfter(iacaNotAfter)) {
                    next = iacaNotAfter;
                }
                CrlBuilder builder = CrlBuilder.forIaca(authority.certificate(), authority.keyPair())
                        .crlNumber(number).thisUpdate(now).nextUpdate(next);
                inventory.revoked().forEach(builder::revoke);
                X509CRL crl = builder.build();
                List<AnnexBValidator.Violation> violations =
                        AnnexBValidator.validateCrl(crl, authority.certificate(), now);
                if (!violations.isEmpty()) {
                    return PkiCommand.violations(violations, "CRL");
                }
                // reserve the number and record the revocations before the CRL is exposed: a failure after this
                // leaves a gap in the numbers, never a reused number or a lost revocation
                inventory.lastCrlNumber(number);
                CrlState updated = current == null ? CrlState.empty() : current;
                updated.put(keyId, inventory);
                updated.write(statePath);
                boolean der = out.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".der");
                try {
                    SecureFiles.write(out, der ? encoded(crl) : Pem.writeCrl(crl).getBytes(StandardCharsets.US_ASCII),
                            SecureFiles.Visibility.PUBLIC, overwrite);
                } catch (IOException | RuntimeException e) {
                    String cause = e instanceof FileSystemException failure ? failure.getFile()
                            + (failure.getReason() != null ? ": " + failure.getReason()
                            : " (" + e.getClass().getSimpleName() + ")") : e.getMessage();
                    throw new IOException(cause + ". CRL number " + number + " and its revocations are already"
                            + " recorded in " + statePath + ", so CRL " + number + " is never published: rerun the"
                            + " command (with a writable --out) to publish CRL " + number.add(BigInteger.ONE)
                            + " listing them", e);
                }
                System.out.println("crlNumber=" + number);
                System.out.println("revoked=" + inventory.revoked().size());
                System.out.println("newlyRevoked=" + added);
                System.out.println("thisUpdate=" + crl.getThisUpdate().toInstant());
                System.out.println("nextUpdate=" + crl.getNextUpdate().toInstant());
                System.out.println("sha256=" + PkiFiles.sha256(encoded(crl)));
                System.out.println("state=" + statePath);
                System.out.println("out=" + out);
                return 0;
            }

            /**
             * The CRL {@code --out} already holds when this IACA signed it (the CRL about to be replaced); {@code null}
             * when there is no file, or it is not a CRL of this IACA (it is replaced, with a warning).
             */
            private X509CRL previousCrl(X509Certificate iaca) {
                if (!Files.exists(out)) {
                    return null;
                }
                X509CRL previous;
                try {
                    previous = readCrl(out);
                } catch (IOException | RuntimeException e) {
                    System.err.println("warning: --out " + out + " is not a CRL; replacing it");
                    return null;
                }
                try {
                    if (!previous.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) {
                        throw new GeneralSecurityException("another issuer");
                    }
                    previous.verify(iaca.getPublicKey());
                } catch (GeneralSecurityException | RuntimeException e) {
                    System.err.println("warning: --out " + out + " holds a CRL this IACA did not sign; replacing it");
                    return null;
                }
                return previous;
            }

            /**
             * Refuses to replace a CRL of this IACA that the inventory has not caught up with: one whose number is at
             * or above the number about to be issued, or that lists a serial the inventory lacks. Either means the
             * inventory is older than what was published (a backup restored without the latest state, or the state
             * of a copy of the IACA kept elsewhere); issuing would reuse a number or drop a revocation. The CRL is
             * merged only when the operator passes it as {@code --base-crl}, never implicitly.
             */
            private void refuseStale(X509CRL previous, CrlState.Inventory inventory, BigInteger number,
                                     Path statePath) {
                if (previous == null) {
                    return;
                }
                BigInteger published;
                try {
                    published = CrlState.crlNumber(previous);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("--out " + out + " is a CRL of this IACA but "
                            + e.getMessage() + "; move it aside or name another --out");
                }
                String remedy = (initial ? " --initial is only for an IACA that never published a CRL: drop it and"
                        + " merge" : force ? " --force is only for when no CRL is left: drop it and merge" : " Merge")
                        + " that CRL into the inventory with --base-crl " + out + " (its number and every entry are"
                        + " imported), then rerun";
                if (published.compareTo(number) >= 0) {
                    throw new IllegalArgumentException("--out " + out + " holds CRL number " + published + " of this"
                            + " IACA, at or above the number " + number + " this run would issue: the revocation"
                            + " inventory " + statePath + " is behind the last published CRL (a backup restored"
                            + " without the latest state, or the state of a copy of the IACA kept elsewhere)."
                            + remedy);
                }
                List<String> missing = new ArrayList<>();
                if (previous.getRevokedCertificates() != null) {
                    for (X509CRLEntry entry : previous.getRevokedCertificates()) {
                        if (!inventory.isRevoked(entry.getSerialNumber())) {
                            missing.add("0x" + entry.getSerialNumber().toString(16));
                        }
                    }
                }
                if (!missing.isEmpty()) {
                    throw new IllegalArgumentException("--out " + out + " (CRL number " + published + " of this"
                            + " IACA) revokes " + String.join(", ", missing) + ", which the revocation inventory "
                            + statePath + " does not list: the inventory is behind the last published CRL, and this"
                            + " CRL would drop the revocation." + remedy);
                }
            }

            /** A CRL to import: signed by the IACA's key and naming the IACA as issuer, else refused. */
            private static X509CRL verifiedBase(Path path, X509Certificate iaca) throws IOException {
                X509CRL crl = readCrl(path);
                if (!crl.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) {
                    throw new IllegalArgumentException("--base-crl " + path + " was issued by "
                            + crl.getIssuerX500Principal().getName() + ", not by this IACA");
                }
                try {
                    crl.verify(iaca.getPublicKey());
                } catch (GeneralSecurityException e) {
                    throw new IllegalArgumentException("--base-crl " + path + " is not signed by this IACA's key: "
                            + e.getMessage(), e);
                }
                return crl;
            }

            private static BigInteger parseNumber(String value) {
                try {
                    BigInteger number = new BigInteger(value.trim());
                    if (number.signum() < 0) {
                        throw new UsageException("--crl-number must not be negative");
                    }
                    return number;
                } catch (NumberFormatException e) {
                    throw new UsageException("--crl-number is not a decimal integer: " + value);
                }
            }

            private static BigInteger parseSerial(String value) {
                String hex = value.trim();
                if (hex.startsWith("0x") || hex.startsWith("0X")) {
                    hex = hex.substring(2);
                }
                try {
                    BigInteger serial = new BigInteger(hex, 16);
                    if (serial.signum() <= 0) {
                        throw new UsageException("--revoke " + value + " is not a positive serial number");
                    }
                    return serial;
                } catch (NumberFormatException e) {
                    throw new UsageException("--revoke " + value + " is not hexadecimal");
                }
            }
        }
    }

    // ------------------------------------------------------------------ pki check

    @Command(name = "check", mixinStandardHelpOptions = true,
            description = "Validate a chain (and a CRL) against the Annex B profile at an instant; exit 0 clean,"
                    + " 2 findings, 1 usage or unreadable input.")
    static class Check implements Callable<Integer> {

        @Option(names = "--chain", required = true, description = "certificate chain PEM; [DSC, IACA] or one object")
        Path chain;
        @Option(names = "--profile", required = true, description = "iaca or mdoc-dsc") String profile;
        @Option(names = "--iaca", description = "IACA PEM; must equal the chain's second certificate when both exist")
        Path iaca;
        @Option(names = "--crl", description = "CRL PEM or DER to validate against the IACA; a DSC it revokes is"
                + " DS_REVOKED") Path crl;
        @Option(names = "--at", description = "the instant to judge validity at, ISO-8601 (default now)") String at;

        @Override
        public Integer call() {
            try {
                return check();
            } catch (IOException e) {
                return error(1, "cannot read the input: " + e.getMessage());
            } catch (RuntimeException e) {
                return error(1, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
        }

        private Integer check() throws IOException {
            Instant instant;
            try {
                instant = at == null ? Instant.now() : Instant.parse(at);
            } catch (DateTimeParseException e) {
                throw new UsageException("--at is not an ISO-8601 instant such as 2026-11-13T00:00:00Z: " + at);
            }
            if (!IACA_PROFILE.equals(profile) && !DS_PROFILE.equals(profile)) {
                throw new UsageException("--profile is " + profile + "; use " + IACA_PROFILE + " or " + DS_PROFILE);
            }
            List<X509Certificate> certificates = Pem.readCertificates(pem(chain));
            if (certificates.isEmpty()) {
                throw new UsageException(chain + " holds no certificate");
            }
            X509Certificate given = iaca == null ? null : Pem.readCertificate(pem(iaca));
            X509CRL list = crl == null ? null : readCrl(crl);
            List<AnnexBValidator.Violation> violations = new ArrayList<>();
            X509Certificate authority;
            X509Certificate ds = null;
            if (IACA_PROFILE.equals(profile)) {
                if (iaca != null) {
                    throw new UsageException("--iaca belongs to --profile " + DS_PROFILE + "; with --profile "
                            + IACA_PROFILE + " the IACA is the --chain certificate");
                }
                authority = certificates.get(0);
            } else {
                ds = certificates.get(0);
                X509Certificate fromChain = certificates.size() > 1 ? certificates.get(1) : null;
                if (given == null && fromChain == null) {
                    throw new UsageException("no IACA: pass --iaca or a two-certificate --chain");
                }
                if (given != null && fromChain != null && !PkiFiles.sameCertificate(given, fromChain)) {
                    violations.add(new AnnexBValidator.Violation("CHAIN_IACA_MISMATCH", "the chain's second"
                            + " certificate (sha256 " + PkiFiles.sha256(fromChain) + ") is not the --iaca certificate"
                            + " (sha256 " + PkiFiles.sha256(given) + ")"));
                }
                authority = given != null ? given : fromChain;
            }
            violations.addAll(AnnexBValidator.validateIaca(authority));
            validity(authority, "IACA", instant, violations);
            if (ds != null) {
                violations.addAll(AnnexBValidator.validateDs(ds, authority));
                validity(ds, "DS", instant, violations);
                sameKey(ds, authority).ifPresent(violations::add);
            }
            if (list != null) {
                violations.addAll(AnnexBValidator.validateCrl(list, authority, instant));
                if (list.getNextUpdate() != null && list.getNextUpdate().toInstant().isBefore(instant)) {
                    violations.add(new AnnexBValidator.Violation("CRL_EXPIRED", "the CRL's nextUpdate "
                            + list.getNextUpdate().toInstant() + " is before " + instant + "; publish a new CRL"));
                }
                X509CRLEntry entry = ds == null ? null : list.getRevokedCertificate(ds);
                if (entry != null) {
                    violations.add(new AnnexBValidator.Violation("DS_REVOKED", "the CRL revokes the Document Signer"
                            + " 0x" + ds.getSerialNumber().toString(16) + " since "
                            + entry.getRevocationDate().toInstant()));
                }
            }
            if (!violations.isEmpty()) {
                // validateDs repeats an IACA finding validateIaca already made (an unreadable IACA, say)
                return PkiCommand.violations(new ArrayList<>(new LinkedHashSet<>(violations)),
                        profile + (crl != null ? " + crl" : ""));
            }
            System.out.println("ok " + profile + (crl != null ? " crl" : "") + " at " + instant);
            return 0;
        }

        /**
         * {@code DS_KEY_IS_IACA_KEY} when the Document Signer certifies the IACA's own public key: that DSC's private
         * key is the IACA key, which must never sign documents or enter an online keystore (D3).
         */
        static Optional<AnnexBValidator.Violation> sameKey(X509Certificate ds, X509Certificate iaca) {
            if (!PkiFiles.sameKey(ds.getPublicKey(), iaca.getPublicKey())) {
                return Optional.empty();
            }
            return Optional.of(new AnnexBValidator.Violation(DS_KEY_IS_IACA_KEY, "the Document Signer certifies the"
                    + " IACA's own public key; its private key is the IACA key, which stays offline and never signs"
                    + " documents (D3)"));
        }

        private static void validity(X509Certificate certificate, String prefix, Instant at,
                                     List<AnnexBValidator.Violation> violations) {
            if (at.isBefore(certificate.getNotBefore().toInstant())) {
                violations.add(new AnnexBValidator.Violation(prefix + "_NOT_YET_VALID", "valid from "
                        + certificate.getNotBefore().toInstant() + ", after " + at));
            } else if (at.isAfter(certificate.getNotAfter().toInstant())) {
                violations.add(new AnnexBValidator.Violation(prefix + "_EXPIRED", "expired at "
                        + certificate.getNotAfter().toInstant() + ", before " + at));
            }
        }
    }
}
