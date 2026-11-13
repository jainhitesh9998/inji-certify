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
 *   certify pki iaca create -k iaca.p12 --country IN --cn "Lorem Ipsum Demo IACA" \
 *       --issuer-alt-uri https://credentials.example.test --crl-uri https://credentials.example.test/iaca.crl
 *   certify pki dsc issue --iaca iaca.p12 --generate -k issuer.p12 --alias mdl-dsc@2026-11 --out dsc-chain.pem
 *   (passwords: CERTIFY_IACA_PASSWORD for the IACA, CERTIFY_KEYSTORE_PASSWORD for keystores, or a prompt)
 * </pre>
 */
@Command(name = "certify", mixinStandardHelpOptions = true, version = "certify-cli 1.0.0-beta.1",
        description = "Sign credentials and manage issuer keys with Inji Certify's signing library.",
        subcommands = {KeysCommand.class, SignCommand.class, PkiCommand.class})
public class CertifyCli implements Runnable {

    public static void main(String[] args) {
        System.exit(commandLine().execute(args));
    }

    /**
     * The command hierarchy with picocli's parameter errors mapped to exit code {@code 1} on every subcommand (picocli's
     * default is 2, which the {@code pki} commands keep for refusals and findings).
     */
    static CommandLine commandLine() {
        CommandLine commandLine = new CommandLine(new CertifyCli());
        usageExitCode(commandLine);
        return commandLine;
    }

    private static void usageExitCode(CommandLine commandLine) {
        commandLine.getCommandSpec().exitCodeOnInvalidInput(1);
        commandLine.getSubcommands().values().forEach(CertifyCli::usageExitCode);
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }
}
