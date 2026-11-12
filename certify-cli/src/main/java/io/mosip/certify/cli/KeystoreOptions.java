package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The PKCS#12 file the {@code jca} provider works on; created on first write. The password is the option value, or the
 * {@code CERTIFY_KEYSTORE_PASSWORD} environment variable when the option is absent, so a script can keep it out of the
 * process argument list; it is prompted only when {@code -p} is given without a value. It is never echoed.
 */
class KeystoreOptions {

    @Option(names = {"-k", "--keystore"}, required = true, description = "PKCS#12 keystore file")
    Path keystore;

    @Option(names = {"-p", "--password"}, required = false, interactive = true, arity = "0..1",
            description = "keystore password (prompted when -p has no value; "
                    + PkiFiles.KEYSTORE_PASSWORD_ENV + " when the option is absent)")
    char[] password;

    char[] password() {
        return PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "-p");
    }

    JcaKeyProvider load() {
        return Files.exists(keystore) ? JcaKeyProvider.fromPkcs12(keystore, password()) : new JcaKeyProvider();
    }

    void save(JcaKeyProvider provider) {
        provider.saveAsPkcs12(keystore, password());
    }
}
