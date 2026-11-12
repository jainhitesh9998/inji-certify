package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyPublisher;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "keys", description = "Generate, list and export issuer keys.", mixinStandardHelpOptions = true,
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
            JcaKeyProvider provider = keystore.load();
            if (provider.aliases().contains(alias)) {
                System.err.println("alias already exists: " + alias);
                return 2;
            }
            PublicKeyDescriptor descriptor = provider.generate(alias, algorithm, subject, purpose).descriptor();
            keystore.save(provider);
            System.out.println(alias + "\t" + descriptor.algorithm().joseName() + "\tkid=" + descriptor.kid() + "\tvalidUntil=" + descriptor.notAfter());
            return 0;
        }
    }

    @Command(name = "list", description = "List the keys in the keystore.", mixinStandardHelpOptions = true)
    static class ListKeys implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;

        @Override
        public Integer call() {
            List<PublicKeyDescriptor> keys = keystore.load().publicKeys(KeyFilter.ALL);
            for (PublicKeyDescriptor key : keys) {
                System.out.println(key.kid() + "\t" + key.algorithm().joseName() + "\t" + key.purpose() + "\tvalidUntil=" + key.notAfter());
            }
            return 0;
        }
    }

    @Command(name = "jwks", description = "Print the public keys as a JWK Set (what an issuer publishes at jwks.json).", mixinStandardHelpOptions = true)
    static class Jwks implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;

        @Override
        public Integer call() {
            System.out.println(new KeyPublisher(List.of(keystore.load())).jwks(KeyFilter.validNow()).toString(true));
            return 0;
        }
    }

    @Command(name = "csr", mixinStandardHelpOptions = true,
            description = "Create a PKCS#10 request for an existing keystore key, e.g. to upload to a CA.")
    static class CsrCommand implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--alias", required = true, description = "alias of the existing key") String alias;
        @Option(names = "--cn", description = "request subject CN (default: the key's certificate subject)")
        String commonName;
        @Option(names = "--out", description = "output PEM (stdout when omitted)") Path out;

        @Override
        public Integer call() {
            try {
                JcaKeyProvider provider = keystore.load();
                SigningKey key = provider.resolve(new KeyRef(provider.id(), alias));
                if (!(key.providerHandle() instanceof PrivateKey privateKey)) {
                    throw new IllegalArgumentException("key " + alias + " is not held as a JCA private key");
                }
                String subject = commonName != null
                        ? "CN=" + commonName
                        : key.chain().leaf().map(c -> c.getSubjectX500Principal().getName())
                                .orElse("CN=" + alias);
                String pem = PkiFiles.csrPem(privateKey, key.descriptor().publicKey(), subject);
                if (out == null) {
                    System.out.print(pem);
                } else {
                    PkiCommand.write(out, pem.getBytes(StandardCharsets.US_ASCII));
                }
                return 0;
            } catch (IOException e) {
                return PkiCommand.error(2, new IllegalStateException("cannot write the request: " + e.getMessage(), e));
            } catch (RuntimeException e) {
                return PkiCommand.error(2, e);
            }
        }
    }

    @Command(name = "import", mixinStandardHelpOptions = true,
            description = "Import a PEM private key and certificate chain into the PKCS#12 keystore.")
    static class ImportKey implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--alias", required = true, description = "alias of the imported key") String alias;
        @Option(names = "--key", required = true, description = "PEM private key (PKCS#8, encrypted or not)")
        Path key;
        @Option(names = "--key-password", arity = "0..1", interactive = true,
                description = "PEM key password (" + PkiFiles.KEY_PASSWORD_ENV + " when the option is absent)")
        char[] keyPassword;
        @Option(names = "--chain", required = true, description = "PEM certificate chain, leaf first")
        Path chain;

        @Override
        public Integer call() {
            try {
                char[] storePassword = keystore.password();
                KeyStore store = PkiFiles.readOrCreate(keystore.keystore, storePassword);
                if (PkiFiles.contains(store, alias)) {
                    throw new IllegalArgumentException("alias already exists in " + keystore.keystore + ": " + alias);
                }
                PrivateKey privateKey = Pem.readPrivateKey(
                        Files.readString(key, StandardCharsets.US_ASCII), keySecret());
                List<X509Certificate> certificates = Pem.readCertificates(
                        Files.readString(chain, StandardCharsets.US_ASCII));
                if (!PkiFiles.matches(privateKey, certificates.get(0).getPublicKey())) {
                    throw new IllegalArgumentException("the private key does not belong to the first certificate of "
                            + chain + "; the chain must be leaf first");
                }
                PkiFiles.add(store, alias, privateKey, storePassword, certificates);
                PkiFiles.write(store, keystore.keystore, storePassword);
                System.out.println("alias=" + alias);
                System.out.println("sha256=" + PkiFiles.sha256(certificates.get(0)));
                return 0;
            } catch (IOException e) {
                return PkiCommand.error(2, new IllegalStateException("cannot import the key: " + e.getMessage(), e));
            } catch (RuntimeException e) {
                return PkiCommand.error(2, e);
            }
        }

        /** The key password; a plaintext key needs none, so an absent one is not an error here. */
        private char[] keySecret() {
            if (keyPassword != null && keyPassword.length > 0) {
                return keyPassword;
            }
            String env = System.getenv(PkiFiles.KEY_PASSWORD_ENV);
            return env == null || env.isEmpty() ? null : env.toCharArray();
        }
    }
}
