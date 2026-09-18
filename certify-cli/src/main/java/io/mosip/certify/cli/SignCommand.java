package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KidStrategy;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "sign", description = "Sign a payload with a keystore key.", mixinStandardHelpOptions = true,
        subcommands = {SignCommand.Jws.class, SignCommand.Cose.class})
class SignCommand {

    static byte[] readInput(Path in) throws IOException {
        return in == null ? System.in.readAllBytes() : Files.readAllBytes(in);
    }

    static SigningKey key(JcaKeyProvider provider, String alias, SignatureAlgorithm algorithm) {
        SigningKey key = provider.resolve(new KeyRef(provider.id(), alias));
        return algorithm == null ? key : key.withAlgorithm(algorithm);
    }

    @Command(name = "jws", description = "Compact JWS (JWT when --typ JWT) over a JSON payload; header carries alg, kid and optionally x5c/x5t#S256.", mixinStandardHelpOptions = true)
    static class Jws implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--key", required = true, description = "key alias") String alias;
        @Option(names = "--alg", description = "override the key's algorithm within its family (PS256 over an RSA key)") SignatureAlgorithm algorithm;
        @Option(names = "--typ", description = "typ header (JWT, dc+sd-jwt, ...)") String typ;
        @Option(names = "--x5c", description = "include the certificate chain in the header") boolean x5c;
        @Option(names = "--x5t", description = "include x5t#S256 in the header") boolean x5t;
        @Option(names = "--kid", defaultValue = "PROVIDER", description = "kid strategy: PROVIDER, JWK_THUMBPRINT, X5T_S256, NONE") String kid;
        @Option(names = "--detached", description = "detached, unencoded payload (RFC 7797), as Linked Data JWS suites use") boolean detached;
        @Option(names = "--in", description = "payload file (stdin when omitted)") Path in;
        @Option(names = "--out", description = "output file (stdout when omitted)") Path out;

        @Override
        public Integer call() throws IOException {
            JcaKeyProvider provider = keystore.load();
            SigningKey key = key(provider, alias, algorithm);
            JwsHeaderPolicy policy = detached
                    ? new JwsHeaderPolicy(typ, kidStrategy(), x5c ? JwsHeaderPolicy.ChainInclusion.FULL : JwsHeaderPolicy.ChainInclusion.NONE, x5t, false, true, Map.of())
                    : new JwsHeaderPolicy(typ, kidStrategy(), x5c ? JwsHeaderPolicy.ChainInclusion.FULL : JwsHeaderPolicy.ChainInclusion.NONE, x5t, true, false, Map.of());
            String jws = JwsEnvelope.sign(readInput(in), policy, key, provider);
            write(out, jws.getBytes(StandardCharsets.US_ASCII), true);
            return 0;
        }

        private KidStrategy kidStrategy() {
            return switch (kid) {
                case "JWK_THUMBPRINT" -> KidStrategy.JWK_THUMBPRINT;
                case "X5T_S256" -> KidStrategy.X5T_S256;
                case "NONE" -> KidStrategy.NONE;
                default -> KidStrategy.PROVIDER;
            };
        }
    }

    @Command(name = "cose", description = "COSE_Sign1 over a byte payload: alg in the protected header, x5chain unprotected; --tagged for CWT-style tag 18.", mixinStandardHelpOptions = true)
    static class Cose implements Callable<Integer> {
        @Mixin KeystoreOptions keystore;
        @Option(names = "--key", required = true, description = "key alias") String alias;
        @Option(names = "--tagged", description = "wrap in CBOR tag 18") boolean tagged;
        @Option(names = "--kid", description = "add the kid (label 4) to the header") boolean kid;
        @Option(names = "--in", description = "payload file (stdin when omitted)") Path in;
        @Option(names = "--out", required = true, description = "output file (binary CBOR)") Path out;

        @Override
        public Integer call() throws IOException {
            JcaKeyProvider provider = keystore.load();
            SigningKey key = key(provider, alias, null);
            CoseHeaderPolicy policy = new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.FULL, kid ? KidStrategy.PROVIDER : null, tagged);
            byte[] sign1 = CoseEnvelope.sign1(readInput(in), policy, key, provider);
            write(out, sign1, false);
            return 0;
        }
    }

    static void write(Path out, byte[] bytes, boolean newline) throws IOException {
        if (out == null) {
            System.out.write(bytes);
            if (newline) {
                System.out.println();
            }
            System.out.flush();
        } else {
            Files.write(out, bytes);
        }
    }
}
