package io.mosip.certify.cli;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;

/** The PKCS#12 file the {@code jca} provider works on; created on first write. */
class KeystoreOptions {

    @Option(names = {"-k", "--keystore"}, required = true, description = "PKCS#12 keystore file")
    Path keystore;

    @Option(names = {"-p", "--password"}, required = true, interactive = true, arity = "0..1", description = "keystore password (prompted when omitted)")
    char[] password;

    JcaKeyProvider load() {
        return Files.exists(keystore) ? JcaKeyProvider.fromPkcs12(keystore, password) : new JcaKeyProvider();
    }

    void save(JcaKeyProvider provider) {
        provider.saveAsPkcs12(keystore, password);
    }
}
