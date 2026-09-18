package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyPublisher;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "keys", description = "Generate, list and export issuer keys.", mixinStandardHelpOptions = true,
        subcommands = {KeysCommand.Generate.class, KeysCommand.ListKeys.class, KeysCommand.Jwks.class})
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
}
