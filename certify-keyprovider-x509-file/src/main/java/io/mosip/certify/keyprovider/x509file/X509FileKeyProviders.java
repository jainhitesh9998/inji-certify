package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Builds the provider from the properties: loads the file, generates what dev mode allows, checks what production needs. */
public final class X509FileKeyProviders {

    private X509FileKeyProviders() {}

    public static JcaKeyProvider open(X509FileProperties properties) {
        if (properties.path() == null) {
            throw new SigningException("certify.keyprovider.x509-file.path is required");
        }
        char[] password = properties.password() == null ? new char[0] : properties.password().toCharArray();
        boolean exists = Files.exists(properties.path());
        if (!exists && !properties.devMode()) {
            throw new SigningException("Keystore " + properties.path() + " does not exist and dev mode is off");
        }
        JcaKeyProvider provider = exists ? JcaKeyProvider.fromPkcs12(properties.id(), properties.path(), password) : new JcaKeyProvider(properties.id());
        List<X509FileProperties.KeySpec> required = properties.keys() == null ? List.of() : properties.keys();
        for (X509FileProperties.KeySpec key : required) {
            SignatureAlgorithm.fromJose(key.algorithm()).orElseThrow(() -> new SigningException("Unknown algorithm " + key.algorithm() + " for key " + key.alias()));
        }
        Set<String> before = Set.copyOf(provider.aliases());
        List<X509FileProperties.KeySpec> missing = required.stream().filter(k -> !before.contains(k.alias())).toList();
        if (!missing.isEmpty()) {
            if (!properties.devMode()) {
                throw new SigningException("Keystore " + properties.path() + " lacks the required keys " + missing.stream().map(X509FileProperties.KeySpec::alias).toList());
            }
            // HAIP forbids a self-signed signing certificate: generated keys chain to a dev CA held in the same keystore
            if (!provider.aliases().contains(properties.caAlias())) {
                provider.generateCa(properties.caAlias(), SignatureAlgorithm.ES256, properties.caSubject(), "dev-ca");
            }
            for (X509FileProperties.KeySpec key : missing) {
                String subject = key.subject() == null || key.subject().isBlank() ? "CN=Inji Certify " + key.alias() : key.subject();
                provider.generateSignedBy(key.alias(), SignatureAlgorithm.fromJose(key.algorithm()).orElseThrow(), subject, properties.purpose(), properties.caAlias());
            }
            try {
                if (properties.path().getParent() != null) {
                    Files.createDirectories(properties.path().getParent());
                }
            } catch (IOException e) {
                throw new SigningException("Cannot create the keystore directory for " + properties.path(), e);
            }
            provider.saveAsPkcs12(properties.path(), password);
        }
        return provider;
    }
}
