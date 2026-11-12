package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The PKCS#12 file the {@code jca} provider works on; created on first write. The password is the option value, else
 * {@code CERTIFY_KEYSTORE_PASSWORD}, else a no-echo prompt when a console is attached; {@code -p} without a value
 * prompts too. It is resolved once per command, never echoed, and cleared by {@link #clear()}.
 */
class KeystoreOptions {

    @Option(names = {"-k", "--keystore"}, required = true, description = "PKCS#12 keystore file")
    Path keystore;

    @Option(names = {"-p", "--password"}, required = false, interactive = true, arity = "0..1",
            description = "keystore password; " + PkiFiles.KEYSTORE_PASSWORD_ENV
                    + " when absent, prompted when neither")
    char[] password;

    private char[] resolved;

    /** The password, resolved on first use; the same array until {@link #clear()}. */
    char[] password() {
        if (resolved == null) {
            resolved = PkiFiles.password(password, PkiFiles.KEYSTORE_PASSWORD_ENV, "keystore password", "-p");
        }
        return resolved;
    }

    JcaKeyProvider load() {
        return Files.exists(keystore) ? JcaKeyProvider.fromPkcs12(keystore, password()) : new JcaKeyProvider();
    }

    /** Overwrites the resolved password and the option value. */
    void clear() {
        PkiFiles.clear(resolved, password);
        resolved = null;
    }
}
