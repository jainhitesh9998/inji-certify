package io.mosip.certify.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * {@code certify} command line: the signing library and the file-backed key provider without the service.
 *
 * <pre>
 *   certify keys generate --keystore keys.p12 --password s3cret --alias issuer-es256 --alg ES256
 *   certify keys list     --keystore keys.p12 --password s3cret
 *   certify keys jwks     --keystore keys.p12 --password s3cret
 *   certify sign jws      --keystore keys.p12 --password s3cret --key issuer-es256 --typ JWT --in claims.json
 *   certify sign cose     --keystore keys.p12 --password s3cret --key issuer-es256 --in payload.cbor --out issuer-auth.cbor
 * </pre>
 */
@Command(name = "certify", mixinStandardHelpOptions = true, version = "certify-cli 1.0.0-beta.1",
        description = "Sign credentials and manage issuer keys with Inji Certify's signing library.",
        subcommands = {KeysCommand.class, SignCommand.class})
public class CertifyCli implements Runnable {

    public static void main(String[] args) {
        System.exit(new CommandLine(new CertifyCli()).execute(args));
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }
}
