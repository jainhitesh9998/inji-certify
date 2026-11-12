package io.mosip.certify.cli;

import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.Csr;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code certify pki}: the offline half of the ISO/IEC 18013-5 Annex B PKI (M-07).
 *
 * <pre>
 *   certify pki iaca create -k iaca.p12 -p s3cret --country IN --cn "Lorem Ipsum Demo IACA" \
 *       --issuer-alt-uri https://credentials.example.test --crl-uri https://credentials.example.test/mdoc/iaca/lorem.crl
 *   certify pki dsc issue --iaca iaca.p12 -p s3cret --generate -k issuer.p12 -P s3cret --alias mdl-dsc@2026-11 \
 *       --out dsc-chain.pem
 *   certify pki dsc issue --iaca iaca.p12 -p s3cret --csr dsc.csr --cn "Lorem Ipsum Demo DSC" --out dsc-chain.pem
 *   certify pki dsc rotate --iaca iaca.p12 -p s3cret -k issuer.p12 -P s3cret --alias-prefix mdl-dsc
 *   certify pki crl issue --iaca iaca.p12 -p s3cret --revoke 0x40a1... --crl-number 1 --out iaca.crl
 *   certify pki check --chain dsc-chain.pem --profile mdoc-dsc --crl iaca.crl
 * </pre>
 *
 * <p>Everything here is offline: the IACA private key is created outside the deployment (D3) and only the Document
 * Signer key, the {@code [DSC, IACA]} chain and the IACA-signed CRL travel into it. Every object is judged by
 * {@link AnnexBValidator} before it is written, so the CLI cannot produce a certificate the runtime would refuse.
 * Passwords come from the option or an environment variable and are never printed. Output is line-oriented
 * {@code key=value} text on stdout, so a script can read it.
 */
@Command(name = "pki", description = "ISO/IEC 18013-5 Annex B PKI: IACA, Document Signer and CRL objects.",
        mixinStandardHelpOptions = true,
        subcommands = {PkiCommand.Iaca.class, PkiCommand.Dsc.class, PkiCommand.Crl.class, PkiCommand.Check.class})
class PkiCommand {

    static final String IACA_PROFILE = "iaca";
    static final String DS_PROFILE = "mdoc-dsc";
    static final String DEFAULT_DS_CN = "Lorem Ipsum Demo DSC";

    private PkiCommand() {}

    static int error(int code, RuntimeException e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
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
        System.err.println(what + ": " + violations.size() + " Annex B violation(s)");
        return 2;
    }

    static String nullIfEmpty(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    static void write(Path out, byte[] bytes) throws IOException {
        Path parent = out.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(out, bytes);
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

    /** An IACA certificate and the private key that signs DSCs and CRLs with it. */
    record IacaKey(X509Certificate certificate, PrivateKey privateKey) {

        KeyPair keyPair() {
            return new KeyPair(certificate.getPublicKey(), privateKey);
        }

        /**
         * The IACA from a PKCS#12 keystore entry, or from a PEM file holding an encrypted PKCS#8 private key and the
         * certificate (the form {@code --pem-out} writes, combined), which keeps the key off any shared filesystem.
         */
        static IacaKey load(Path path, char[] password, String alias) {
            if (isPem(path)) {
                String text = read(path);
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

        private static boolean isPem(Path path) {
            return path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".pem");
        }

        private static String read(Path path) {
            try {
                return Files.readString(path, StandardCharsets.US_ASCII);
            } catch (IOException e) {
                throw new IllegalArgumentException("cannot read " + path + ": " + e.getMessage(), e);
            }
        }
    }

    // ------------------------------------------------------------------ pki iaca

    @Command(name = "iaca", description = "IACA certificate operations.", mixinStandardHelpOptions = true,
            subcommands = Iaca.Create.class)
    static class Iaca {

        @Command(name = "create", mixinStandardHelpOptions = true,
                description = "Create an offline IACA key and self-signed Annex B IACA certificate.")
        static class Create implements Callable<Integer> {

            @Option(names = {"-k", "--keystore"}, required = true,
                    description = "PKCS#12 file that holds the IACA key (protected by -p)")
            Path keystore;
            @Option(names = {"-p", "--password"}, arity = "0..1", interactive = true,
                    description = "IACA keystore password (prompted when -p has no value; "
                            + PkiFiles.KEYSTORE_PASSWORD_ENV + " when the option is absent)")
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
                    description = "write the key as an encrypted PKCS#8 PEM instead of a PKCS#12 keystore")
            Path pemOut;

            @Override
            public Integer call() {
                try {
                    return create();
                } catch (IOException e) {
                    return error(2, new IllegalStateException("cannot write the IACA: " + e.getMessage(), e));
                } catch (RuntimeException e) {
                    return error(2, e);
                }
            }

            private Integer create() throws IOException {
                char[] secret = PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "-p");
                if (validityYears < 1 || validityYears > 20) {
                    throw new IllegalArgumentException("--validity-years is " + validityYears
                            + "; Annex B allows 1 to 20 calendar years");
                }
                Instant start = Instant.now().truncatedTo(ChronoUnit.SECONDS);
                Duration validity = Duration.between(start, start.atZone(ZoneOffset.UTC).plusYears(validityYears).toInstant());
                KeyPair keyPair = PkiFiles.keyPair(algorithm);
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
                    return PkiCommand.violations(violations, "IACA");
                }
                if (pemOut != null) {
                    if (Files.exists(pemOut)) {
                        throw new IllegalArgumentException("refusing to overwrite " + pemOut);
                    }
                    // the key first (so `openssl pkey -in iaca.pem` reads it), then the certificate, so the same file
                    // can stand in for the keystore wherever this CLI takes --iaca
                    write(pemOut, (Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), secret)
                            + Pem.writeCertificate(iaca)).getBytes(StandardCharsets.US_ASCII));
                } else {
                    KeyStore store = PkiFiles.readOrCreate(keystore, secret);
                    if (PkiFiles.contains(store, alias)) {
                        throw new IllegalArgumentException("alias already exists in " + keystore + ": " + alias);
                    }
                    PkiFiles.add(store, alias, keyPair.getPrivate(), secret, List.of(iaca));
                    PkiFiles.write(store, keystore, secret);
                }
                // the certificate is the only thing on stdout, so `> iaca.pem` yields a publishable file
                System.out.print(Pem.writeCertificate(iaca));
                System.err.println("IACA created: alias=" + alias + " store="
                        + (pemOut != null ? pemOut : keystore));
                System.err.println("sha256=" + PkiFiles.sha256(iaca));
                return 0;
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
            @Option(names = {"-p", "--password"}, arity = "0..1", interactive = true,
                    description = "IACA keystore password (" + PkiFiles.KEYSTORE_PASSWORD_ENV + " when absent)")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = "--csr", description = "PKCS#10 request to certify (DER or PEM), e.g. from a keymanager")
            Path csr;
            @Option(names = "--generate", description = "generate a new Document Signer key in -k instead of a CSR")
            boolean generate;
            @Option(names = {"-k", "--keystore"}, description = "issuer PKCS#12 keystore for --generate") Path keystore;
            @Option(names = {"-P", "--issuer-password"}, arity = "0..1", interactive = true,
                    description = "issuer keystore password (" + PkiFiles.ISSUER_PASSWORD_ENV + " when absent)")
            char[] issuerPassword;
            @Option(names = "--alias", description = "alias of the generated key, e.g. mdl-dsc@2026-11")
            String alias;
            @Option(names = "--cn", description = "Document Signer CN (default: the CSR's CN, else a demo name)")
            String commonName;
            @Option(names = "--validity-days", defaultValue = "365", description = "lifetime in days, 1..457")
            int validityDays;
            @Option(names = "--alg", defaultValue = "ES256", description = "key algorithm for --generate")
            String algorithm;
            @Option(names = "--out", required = true, description = "output chain PEM, [DSC, IACA] leaf first")
            Path out;

            @Override
            public Integer call() {
                try {
                    return issue();
                } catch (IOException e) {
                    return error(2, new IllegalStateException("cannot write the Document Signer: " + e.getMessage(), e));
                } catch (RuntimeException e) {
                    return error(2, e);
                }
            }

            private Integer issue() throws IOException {
                if ((csr == null) == !generate) {
                    throw new IllegalArgumentException("pass exactly one of --csr <file> or --generate");
                }
                char[] secret = PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "-p");
                IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                if (csr != null) {
                    Csr request = Csr.parse(Files.readAllBytes(csr));
                    String name = commonName != null ? commonName : PkiFiles.commonName(request.subject());
                    return Dsc.issue(authority, request.publicKey(), null, name, validityDays, out,
                            null, null, null, null);
                }
                if (keystore == null) {
                    throw new IllegalArgumentException("--generate needs -k <issuer.p12>");
                }
                if (alias == null || alias.isBlank()) {
                    throw new IllegalArgumentException("--generate needs --alias <name>");
                }
                char[] issuerSecret = PkiFiles.password(issuerPassword, PkiFiles.ISSUER_PASSWORD_ENV, "-P");
                KeyStore store = PkiFiles.readOrCreate(keystore, issuerSecret);
                if (PkiFiles.contains(store, alias)) {
                    throw new IllegalArgumentException("alias already exists in " + keystore + ": " + alias);
                }
                KeyPair keyPair = PkiFiles.keyPair(algorithm);
                return Dsc.issue(authority, keyPair.getPublic(), keyPair.getPrivate(),
                        commonName != null ? commonName : DEFAULT_DS_CN, validityDays, out,
                        store, keystore, issuerSecret, alias);
            }
        }

        @Command(name = "rotate", mixinStandardHelpOptions = true,
                description = "Issue a new versioned Document Signer (mdl-dsc@yyyy-MM) and keep the old ones.")
        static class Rotate implements Callable<Integer> {

            @Option(names = "--iaca", required = true, description = "IACA PKCS#12 keystore, or a PEM key+certificate")
            Path iaca;
            @Option(names = {"-p", "--password"}, arity = "0..1", interactive = true,
                    description = "IACA keystore password (" + PkiFiles.KEYSTORE_PASSWORD_ENV + " when absent)")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = {"-k", "--keystore"}, required = true, description = "issuer PKCS#12 keystore")
            Path keystore;
            @Option(names = {"-P", "--issuer-password"}, arity = "0..1", interactive = true,
                    description = "issuer keystore password (" + PkiFiles.ISSUER_PASSWORD_ENV + " when absent)")
            char[] issuerPassword;
            @Option(names = "--alias-prefix", defaultValue = "mdl-dsc",
                    description = "alias prefix; the new alias is <prefix>@<yyyy-MM>")
            String aliasPrefix;
            @Option(names = "--cn", description = "Document Signer CN (default: a demo name with the month)")
            String commonName;
            @Option(names = "--validity-days", defaultValue = "365", description = "lifetime in days, 1..457")
            int validityDays;
            @Option(names = "--alg", defaultValue = "ES256", description = "key algorithm for the new key")
            String algorithm;
            @Option(names = "--out", description = "output chain PEM; stdout when omitted") Path out;

            @Override
            public Integer call() {
                try {
                    return rotate();
                } catch (IOException e) {
                    return error(2, new IllegalStateException("cannot write the Document Signer: " + e.getMessage(), e));
                } catch (RuntimeException e) {
                    return error(2, e);
                }
            }

            private Integer rotate() throws IOException {
                String month = YearMonth.now(ZoneOffset.UTC).toString();
                String alias = aliasPrefix + "@" + month;
                char[] secret = PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "-p");
                char[] issuerSecret = PkiFiles.password(issuerPassword, PkiFiles.ISSUER_PASSWORD_ENV, "-P");
                IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                KeyStore store = PkiFiles.read(keystore, issuerSecret);
                if (PkiFiles.contains(store, alias)) {
                    throw new IllegalArgumentException("this month's Document Signer already exists: " + alias
                            + " in " + keystore + "; nothing to rotate until the next month");
                }
                KeyPair keyPair = PkiFiles.keyPair(algorithm);
                String name = commonName != null ? commonName : DEFAULT_DS_CN + " " + month;
                int code = Dsc.issue(authority, keyPair.getPublic(), keyPair.getPrivate(), name, validityDays,
                        out, store, keystore, issuerSecret, alias);
                if (code == 0) {
                    System.err.println("kept the older Document Signers in " + keystore
                            + "; load the new one with x509-file:mdl-dsc (newest valid entry wins)");
                }
                return code;
            }
        }

        /**
         * Signs one Document Signer, validates it, writes the chain and, for a generated key, stores the key with the
         * chain. The caller has already refused an existing alias, so nothing is overwritten.
         */
        static int issue(IacaKey authority, PublicKey subjectKey, PrivateKey subjectPrivate, String commonName,
                         int validityDays, Path out, KeyStore store, Path storePath, char[] storePassword,
                         String alias) throws IOException {
            if (validityDays < 1 || validityDays > IsoMdocProfiles.DS_MAX_VALIDITY.toDays()) {
                throw new IllegalArgumentException("--validity-days is " + validityDays + "; Annex B allows 1 to "
                        + IsoMdocProfiles.DS_MAX_VALIDITY.toDays());
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
                PkiFiles.write(store, storePath, storePassword);
            }
            if (out != null) {
                write(out, Pem.writeCertificates(chain).getBytes(StandardCharsets.US_ASCII));
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

    // ------------------------------------------------------------------ pki crl

    @Command(name = "crl", description = "CRL operations.", mixinStandardHelpOptions = true,
            subcommands = Crl.Issue.class)
    static class Crl {

        @Command(name = "issue", mixinStandardHelpOptions = true,
                description = "Sign an X.509 v2 CRL with the IACA; the CRL number must increase.")
        static class Issue implements Callable<Integer> {

            @Option(names = "--iaca", required = true, description = "IACA PKCS#12 keystore, or a PEM key+certificate")
            Path iaca;
            @Option(names = {"-p", "--password"}, arity = "0..1", interactive = true,
                    description = "IACA keystore password (" + PkiFiles.KEYSTORE_PASSWORD_ENV + " when absent)")
            char[] password;
            @Option(names = "--iaca-alias", defaultValue = "iaca", description = "IACA key alias in the keystore")
            String iacaAlias;
            @Option(names = "--revoke", description = "serial to revoke, hexadecimal (0x prefixed or not); repeatable")
            List<String> revoke = new ArrayList<>();
            @Option(names = "--crl-number", required = true, description = "cRLNumber, greater than the previous one")
            String crlNumber;
            @Option(names = "--next-update-days", defaultValue = "30", description = "days until the next CRL is due")
            int nextUpdateDays;
            @Option(names = "--force", description = "accept a CRL number that does not increase (audited on stderr)")
            boolean force;
            @Option(names = "--out", required = true, description = "output CRL; DER for a .der name, PEM otherwise")
            Path out;

            @Override
            public Integer call() {
                try {
                    return issue();
                } catch (IOException e) {
                    return error(2, new IllegalStateException("cannot write the CRL: " + e.getMessage(), e));
                } catch (RuntimeException e) {
                    return error(2, e);
                }
            }

            private Integer issue() throws IOException {
                if (nextUpdateDays < 1) {
                    throw new IllegalArgumentException("--next-update-days must be at least 1");
                }
                BigInteger number = parseNumber(crlNumber);
                char[] secret = PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "-p");
                IacaKey authority = IacaKey.load(iaca, secret, iacaAlias);
                Path state = stateFile(iaca);
                BigInteger previous = previousNumber(state);
                if (previous != null && number.compareTo(previous) <= 0 && !force) {
                    throw new IllegalArgumentException("the CRL number " + number + " does not increase on the last"
                            + " published one " + previous + " (" + state + "); pass a larger --crl-number or --force");
                }
                Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
                Instant next = now.plus(Duration.ofDays(nextUpdateDays));
                Instant iacaNotAfter = authority.certificate().getNotAfter().toInstant().truncatedTo(ChronoUnit.SECONDS);
                if (next.isAfter(iacaNotAfter)) {
                    next = iacaNotAfter;
                }
                CrlBuilder builder = CrlBuilder.forIaca(authority.certificate(), authority.keyPair())
                        .crlNumber(number).thisUpdate(now).nextUpdate(next);
                List<BigInteger> serials = new ArrayList<>();
                for (String serial : revoke) {
                    BigInteger value = parseSerial(serial);
                    serials.add(value);
                    builder.revoke(value, now);
                }
                X509CRL crl = builder.build();
                List<AnnexBValidator.Violation> violations =
                        AnnexBValidator.validateCrl(crl, authority.certificate(), now);
                if (!violations.isEmpty()) {
                    return PkiCommand.violations(violations, "CRL");
                }
                boolean der = out.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".der");
                write(out, der ? encoded(crl) : Pem.writeCrl(crl).getBytes(StandardCharsets.US_ASCII));
                BigInteger watermark = previous == null || number.compareTo(previous) > 0 ? number : previous;
                Files.writeString(state, watermark + System.lineSeparator(), StandardCharsets.US_ASCII);
                if (number.compareTo(watermark) < 0) {
                    System.err.println("warning: the CRL number " + number + " is below the last published "
                            + watermark + "; --force accepted it and the watermark stays at " + watermark);
                }
                System.out.println("crlNumber=" + number);
                System.out.println("revoked=" + serials.size());
                System.out.println("thisUpdate=" + crl.getThisUpdate().toInstant());
                System.out.println("nextUpdate=" + crl.getNextUpdate().toInstant());
                System.out.println("sha256=" + PkiFiles.sha256(encoded(crl)));
                System.out.println("out=" + out);
                return 0;
            }

            private static BigInteger parseNumber(String value) {
                try {
                    BigInteger number = new BigInteger(value.trim());
                    if (number.signum() < 0) {
                        throw new IllegalArgumentException("--crl-number must not be negative");
                    }
                    return number;
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("--crl-number is not a decimal integer: " + value);
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
                        throw new IllegalArgumentException("--revoke " + value + " is not a positive serial number");
                    }
                    return serial;
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("--revoke " + value + " is not hexadecimal");
                }
            }
        }

        /** The monotonic counter next to the IACA keystore: {@code iaca.p12.crlnumber}, a decimal number. */
        static Path stateFile(Path keystore) {
            return keystore.resolveSibling(keystore.getFileName() + ".crlnumber");
        }

        static BigInteger previousNumber(Path state) throws IOException {
            if (!Files.exists(state)) {
                return null;
            }
            String text = Files.readString(state, StandardCharsets.US_ASCII).trim();
            if (text.isEmpty()) {
                return null;
            }
            try {
                return new BigInteger(text);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("the CRL number state file " + state
                        + " does not hold a decimal number: " + text);
            }
        }
    }

    // ------------------------------------------------------------------ pki check

    @Command(name = "check", mixinStandardHelpOptions = true, exitCodeOnInvalidInput = 1,
            description = "Validate a chain against the Annex B profile; exit 0 clean, 2 violations, 1 usage.")
    static class Check implements Callable<Integer> {

        @Option(names = "--chain", required = true, description = "certificate chain PEM; [DSC, IACA] or one object")
        Path chain;
        @Option(names = "--profile", required = true, description = "iaca or mdoc-dsc") String profile;
        @Option(names = "--iaca", description = "IACA PEM, when the chain holds only the object to check")
        Path iaca;
        @Option(names = "--crl", description = "CRL PEM or DER to validate against the IACA") Path crl;

        @Override
        public Integer call() {
            try {
                return check();
            } catch (IOException e) {
                return error(1, new IllegalStateException("cannot read the input: " + e.getMessage(), e));
            } catch (RuntimeException e) {
                return error(1, e);
            }
        }

        private Integer check() throws IOException {
            List<X509Certificate> certificates = Pem.readCertificates(pem(chain));
            List<AnnexBValidator.Violation> violations = new ArrayList<>();
            X509Certificate authority;
            switch (profile) {
                case IACA_PROFILE -> {
                    authority = certificates.get(0);
                    violations.addAll(AnnexBValidator.validateIaca(authority));
                }
                case DS_PROFILE -> {
                    X509Certificate ds = certificates.get(0);
                    authority = iaca != null ? Pem.readCertificate(pem(iaca))
                            : certificates.size() > 1 ? certificates.get(1) : null;
                    if (authority == null) {
                        throw new IllegalArgumentException("no IACA: pass --iaca or a two-certificate --chain");
                    }
                    violations.addAll(AnnexBValidator.validateDs(ds, authority));
                }
                default -> throw new IllegalArgumentException("--profile is " + profile + "; use "
                        + IACA_PROFILE + " or " + DS_PROFILE);
            }
            if (crl != null) {
                violations.addAll(AnnexBValidator.validateCrl(readCrl(crl), authority));
            }
            if (!violations.isEmpty()) {
                return PkiCommand.violations(violations, profile + (crl != null ? " + crl" : ""));
            }
            System.out.println("ok " + profile + (crl != null ? " crl" : ""));
            return 0;
        }

        private static X509CRL readCrl(Path path) throws IOException {
            byte[] bytes = Files.readAllBytes(path);
            if (path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".der")) {
                try {
                    return (X509CRL) java.security.cert.CertificateFactory.getInstance("X.509")
                            .generateCRL(new java.io.ByteArrayInputStream(bytes));
                } catch (java.security.cert.CertificateException | java.security.cert.CRLException e) {
                    throw new IllegalArgumentException("cannot read the DER CRL " + path + ": " + e.getMessage(), e);
                }
            }
            return Pem.readCrl(new String(bytes, StandardCharsets.US_ASCII));
        }
    }
}
