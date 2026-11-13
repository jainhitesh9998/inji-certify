package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyPublisher;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.bouncycastle.asn1.x500.X500Name;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "keys", description = "Generate, list, export and import issuer keys.", mixinStandardHelpOptions = true,
        subcommands = {KeysCommand.Generate.class, KeysCommand.ListKeys.class, KeysCommand.Jwks.class,
                KeysCommand.CsrCommand.class, KeysCommand.ImportKey.class})
class KeysCommand {

    @Command(name = "generate", description = "Generate a key with a self-signed certificate and store it in the keystore.", mixinStandardHelpOptions = true)
    static class Generate implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--alias", required = true, description = "key alias (also the kid)") String alias;
        @Option(names = "--alg", required = true, description = "ES256, ES256K, EdDSA, RS256, PS256") SignatureAlgorithm algorithm;
        @Option(names = "--subject", defaultValue = "CN=Inji Certify issuer", description = "certificate subject DN") String subject;
        @Option(names = "--purpose", defaultValue = "vc-signing") String purpose;

        @Override
        public Integer call() {
            return PkiCommand.execute(this::generate, "cannot write the keystore");
        }

        private Integer generate() throws Exception {
            PkiFiles.requireLowerCaseAlias(alias, "--alias");
            Path path = SecureFiles.canonical(keystore.keystore);
            SecureFiles.requireSingleLink(path);
            try (SecureFiles.Lock lock = SecureFiles.lock(path)) {
                char[] password = keystore.password();
                boolean exists = Files.exists(path);
                KeyStore store = PkiFiles.readOrCreate(path, password);
                if (PkiFiles.contains(store, alias)) {
                    System.err.println("alias already exists: " + alias);
                    return 2;
                }
                // generated in a scratch provider, then added to the keystore read under the lock
                SigningKey key = new JcaKeyProvider().generate(alias, algorithm, subject, purpose);
                PkiFiles.add(store, alias, (PrivateKey) key.providerHandle(), password, key.chain().leafFirst());
                PkiFiles.write(store, path, password, exists);
                PublicKeyDescriptor descriptor = key.descriptor();
                System.out.println(alias + "\t" + descriptor.algorithm().joseName() + "\tkid=" + descriptor.kid() + "\tvalidUntil=" + descriptor.notAfter());
                return 0;
            } finally {
                keystore.clear();
            }
        }
    }

    @Command(name = "list", description = "List the keys in the keystore.", mixinStandardHelpOptions = true)
    static class ListKeys implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;

        @Override
        public Integer call() {
            try {
                List<PublicKeyDescriptor> keys = keystore.load().publicKeys(KeyFilter.ALL);
                for (PublicKeyDescriptor key : keys) {
                    System.out.println(key.kid() + "\t" + key.algorithm().joseName() + "\t" + key.purpose() + "\tvalidUntil=" + key.notAfter());
                }
                return 0;
            } finally {
                keystore.clear();
            }
        }
    }

    @Command(name = "jwks", description = "Print the public keys as a JWK Set (what an issuer publishes at jwks.json).", mixinStandardHelpOptions = true)
    static class Jwks implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;

        @Override
        public Integer call() {
            try {
                System.out.println(new KeyPublisher(List.of(keystore.load())).jwks(KeyFilter.validNow()).toString(true));
                return 0;
            } finally {
                keystore.clear();
            }
        }
    }

    @Command(name = "csr", mixinStandardHelpOptions = true,
            description = "Create a PKCS#10 request for an existing keystore key, e.g. to upload to a CA.")
    static class CsrCommand implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--alias", required = true, description = "alias of the existing key") String alias;
        @Option(names = "--cn", description = "request subject: one CN with this value, taken verbatim (default: the"
                + " key's certificate subject, attribute order kept)")
        String commonName;
        @Option(names = "--out", description = "output PEM (stdout when omitted)") Path out;
        @Option(names = {"--overwrite", "--force"}, description = "replace an existing --out file") boolean overwrite;

        @Override
        public Integer call() {
            return PkiCommand.execute(this::csr, "cannot write the request");
        }

        private Integer csr() throws Exception {
            try {
                SecureFiles.requireDistinct(SecureFiles.paths("-k", keystore.keystore), SecureFiles.paths("--out", out));
                PkiCommand.refuseExisting(out, overwrite, PkiCommand.OutKind.CSR);
                JcaKeyProvider provider = keystore.load();
                SigningKey key = provider.resolve(new KeyRef(provider.id(), alias));
                if (!(key.providerHandle() instanceof PrivateKey privateKey)) {
                    throw new IllegalArgumentException("key " + alias + " is not held as a JCA private key");
                }
                X500Name subject = commonName != null
                        ? PkiFiles.commonNameSubject(commonName)
                        : key.chain().leaf().map(PkiFiles::subject).orElse(PkiFiles.commonNameSubject(alias));
                String pem = PkiFiles.csrPem(privateKey, key.descriptor().publicKey(), subject);
                if (out == null) {
                    System.out.print(pem);
                } else {
                    SecureFiles.write(out, pem.getBytes(StandardCharsets.US_ASCII), SecureFiles.Visibility.PUBLIC,
                            overwrite);
                }
                return 0;
            } finally {
                keystore.clear();
            }
        }
    }

    @Command(name = "import", mixinStandardHelpOptions = true,
            description = "Import a PEM private key and its certificate chain into the PKCS#12 keystore; the chain must"
                    + " be a valid RFC 5280 path up to a self-signed root or --anchor. An IACA key is never imported.")
    static class ImportKey implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--alias", required = true, description = "alias of the imported key") String alias;
        @Option(names = "--key", required = true, description = "PEM private key (PKCS#8 or SEC1, encrypted or not),"
                + " EC P-256/384/521")
        Path key;
        @Option(names = "--key-password", arity = "0..1", interactive = true,
                description = "PEM key password; " + PkiFiles.KEY_PASSWORD_ENV + " when absent, prompted when the key"
                        + " is encrypted and neither is set")
        char[] keyPassword;
        @Option(names = "--chain", required = true, description = "PEM certificate chain, leaf first")
        Path chain;
        @Option(names = "--anchor", description = "PEM certificate the chain ends under, when its last certificate is"
                + " not self-signed (e.g. the IACA for a leaf-only DSC)")
        Path anchor;
        @Option(names = "--profile", description = "mdoc-dsc: the key is a Document Signer; [DSC, IACA] (from the"
                + " chain, or the chain and --anchor) must pass Annex B and is what the entry stores")
        String profile;

        @Override
        public Integer call() {
            return PkiCommand.execute(this::importKey, "cannot import the key");
        }

        private Integer importKey() throws Exception {
            char[] keySecret = null;
            try {
                if (profile != null && !PkiCommand.DS_PROFILE.equals(profile)) {
                    throw new UsageException("--profile is " + profile + "; the only profile is "
                            + PkiCommand.DS_PROFILE);
                }
                PkiFiles.requireLowerCaseAlias(alias, "--alias");
                Path path = SecureFiles.canonical(keystore.keystore);
                SecureFiles.requireDistinct(SecureFiles.paths("--key", key, "--chain", chain, "--anchor", anchor),
                        SecureFiles.paths("-k", path, "the lock of -k", SecureFiles.lockFile(path)));
                SecureFiles.requireSingleLink(path);
                String keyPem = Files.readString(key, StandardCharsets.US_ASCII);
                if (Pem.isEncryptedPrivateKey(keyPem)) {
                    keySecret = PkiFiles.password(keyPassword, PkiFiles.KEY_PASSWORD_ENV, "PEM key password",
                            "--key-password");
                }
                PrivateKey privateKey = Pem.readPrivateKey(keyPem, keySecret);
                PkiFiles.requireSupportedKey(privateKey, "--key " + key);
                List<X509Certificate> certificates = Pem.readCertificates(
                        Files.readString(chain, StandardCharsets.US_ASCII));
                if (certificates.isEmpty()) {
                    throw new UsageException(chain + " holds no certificate");
                }
                if (PkiCommand.DS_PROFILE.equals(profile) && certificates.size() < 2 && anchor == null) {
                    throw new UsageException("--profile mdoc-dsc needs the IACA: a [DSC, IACA] chain, or --anchor"
                            + " iaca.pem");
                }
                PkiFiles.requireSupportedKey(certificates.get(0).getPublicKey(), "the first certificate of " + chain);
                if (!PkiFiles.matches(privateKey, certificates.get(0).getPublicKey())) {
                    throw new IllegalArgumentException("the private key does not belong to the first certificate of "
                            + chain + "; the chain must be leaf first");
                }
                X509Certificate anchorCertificate = anchor == null ? null
                        : Pem.readCertificate(Files.readString(anchor, StandardCharsets.US_ASCII));
                PkiFiles.verifyChain(certificates, anchorCertificate, Instant.now());
                if (AnnexBValidator.validateIaca(certificates.get(0)).isEmpty()) {
                    throw new IllegalArgumentException("KEY_IS_IACA: the key's certificate is an Annex B IACA; an IACA"
                            + " key stays offline (D3) and never enters an issuer keystore. Pass the IACA PEM key and"
                            + " certificate to the --iaca option of the pki commands instead");
                }
                refuseCaKey(certificates.get(0));
                List<X509Certificate> stored = certificates;
                if (PkiCommand.DS_PROFILE.equals(profile)) {
                    stored = documentSignerChain(certificates, anchorCertificate);
                    if (stored == null) {
                        return 2;
                    }
                } else {
                    refuseIssuerKey(certificates, anchorCertificate);
                }
                String storedAlias;
                try (SecureFiles.Lock lock = SecureFiles.lock(path)) {
                    char[] storePassword = keystore.password();
                    boolean exists = Files.exists(path);
                    KeyStore store = PkiFiles.readOrCreate(path, storePassword);
                    if (PkiFiles.contains(store, alias)) {
                        throw new IllegalArgumentException("alias already exists in " + keystore.keystore + ": "
                                + alias);
                    }
                    PkiFiles.add(store, alias, privateKey, storePassword, stored);
                    PkiFiles.write(store, path, storePassword, exists);
                    // what a reader of the file sees, which the lower-case rule keeps equal to --alias
                    storedAlias = PkiFiles.aliases(PkiFiles.read(path, storePassword)).stream()
                            .filter(alias::equalsIgnoreCase).findFirst().orElse(alias);
                }
                System.out.println("alias=" + storedAlias);
                System.out.println("chain=" + stored.size());
                System.out.println("sha256=" + PkiFiles.sha256(stored.get(0)));
                return 0;
            } finally {
                PkiFiles.clear(keySecret, keyPassword);
                keystore.clear();
            }
        }

        /**
         * {@code KEY_IS_CA}: the key's own certificate is a CA's (basicConstraints {@code CA:true}, or keyUsage
         * keyCertSign or cRLSign), whether or not it is an Annex B IACA. A CA key, an IACA's or any other, stays offline
         * (D3) and never enters an issuer keystore, which holds signing keys with end-entity certificates only.
         */
        static void refuseCaKey(X509Certificate certificate) {
            List<String> reasons = new ArrayList<>();
            if (certificate.getBasicConstraints() >= 0) {
                reasons.add("basicConstraints CA:true");
            }
            boolean[] usage = certificate.getKeyUsage();
            if (usage != null && usage.length > 5 && usage[5]) {
                reasons.add("keyUsage keyCertSign");
            }
            if (usage != null && usage.length > 6 && usage[6]) {
                reasons.add("keyUsage cRLSign");
            }
            if (!reasons.isEmpty()) {
                throw new IllegalArgumentException("KEY_IS_CA: the key's certificate "
                        + certificate.getSubjectX500Principal().getName() + " is a CA certificate ("
                        + String.join(", ", reasons) + "); a CA key, an IACA's or any other, stays offline (D3) and"
                        + " never enters an issuer keystore. Import the signing key with an end-entity certificate"
                        + " (basicConstraints CA:false, no keyCertSign or cRLSign; with OpenSSL, req -x509 adds"
                        + " CA:true unless given -addext basicConstraints=critical,CA:FALSE)");
            }
        }

        /**
         * Refuses a key that is also the key of a certificate above it (in the chain or {@code --anchor}): that is the
         * issuer's private key, an IACA's or another CA's, and a CA key is never an issuer signing key (D3).
         */
        private static void refuseIssuerKey(List<X509Certificate> chain, X509Certificate anchor) {
            List<X509Certificate> issuers = new ArrayList<>(chain.subList(1, chain.size()));
            if (anchor != null) {
                issuers.add(anchor);
            }
            X509Certificate leaf = chain.get(0);
            for (X509Certificate issuer : issuers) {
                if (!PkiFiles.sameCertificate(leaf, issuer) && PkiFiles.sameKey(leaf.getPublicKey(),
                        issuer.getPublicKey())) {
                    throw new IllegalArgumentException("KEY_IS_ISSUER_KEY: the key is also the key of its issuer "
                            + issuer.getSubjectX500Principal().getName() + "; a CA key never enters an issuer"
                            + " keystore (D3)");
                }
            }
        }

        /** {@code [DSC, IACA]} judged by Annex B, or {@code null} after printing the violations. */
        private static List<X509Certificate> documentSignerChain(List<X509Certificate> certificates,
                                                                 X509Certificate anchor) {
            if (certificates.size() > 2) {
                throw new IllegalArgumentException("a Document Signer chain is [DSC, IACA]; the chain has "
                        + certificates.size() + " certificates");
            }
            X509Certificate dsc = certificates.get(0);
            X509Certificate iaca = certificates.size() == 2 ? certificates.get(1) : anchor;
            List<AnnexBValidator.Violation> violations = new ArrayList<>(AnnexBValidator.validateIaca(iaca));
            violations.addAll(AnnexBValidator.validateDs(dsc, iaca));
            PkiCommand.Check.sameKey(dsc, iaca).ifPresent(violations::add);
            if (!violations.isEmpty()) {
                PkiCommand.violations(violations, "Document Signer chain");
                return null;
            }
            return List.of(dsc, iaca);
        }
    }
}
