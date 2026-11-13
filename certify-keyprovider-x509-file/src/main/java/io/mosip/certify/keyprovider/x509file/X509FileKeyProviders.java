package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.x509file.X509FileProperties.IacaSpec;
import io.mosip.certify.keyprovider.x509file.X509FileProperties.KeySpec;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds the provider from the properties: loads the file, generates what dev mode allows, imports the PEM keys and
 * checks what production needs (docs/design/20-mdl-issuer.md M-05).
 *
 * <p>Three things can be configured, and an existing deployment uses only the first: {@code path}/{@code password} plus
 * {@code keys} with the P3-08 dev CA, which is unchanged; an Annex B {@code iaca} block with keys whose
 * {@code profile: mdoc-dsc}, which dev mode generates and every start validates; and {@code pem-keys}, a Document
 * Signer key and {@code [DSC, IACA]} chain the operator already holds.
 */
public final class X509FileKeyProviders {

    private X509FileKeyProviders() {}

    public static JcaKeyProvider open(X509FileProperties properties) {
        Path path = properties.path();
        List<X509FileProperties.PemKeySpec> pemKeys = properties.pemKeys() == null ? List.of() : properties.pemKeys();
        boolean pemOnly = !pemKeys.isEmpty();
        if (path == null && !pemOnly) {
            throw new SigningException("certify.keyprovider.x509-file.path is required");
        }
        char[] password = properties.password() == null ? new char[0] : properties.password().toCharArray();
        boolean exists = path != null && Files.exists(path);
        if (path != null && !exists && !properties.devMode()) {
            // a configured keystore that is missing is a mistake even next to pem-keys: its keys would silently vanish
            throw new SigningException("Keystore " + path + " does not exist and dev mode is off");
        }
        // purposes are derived from each certificate on load, so a generated IACA or DSC keeps its purpose on restart
        JcaKeyProvider provider = exists
                ? JcaKeyProvider.fromPkcs12(properties.id(), path, password,
                        properties.purpose() == null ? JcaKeyProvider.PURPOSE_VC_SIGNING : properties.purpose(),
                        properties.caAlias(), properties.iaca() == null ? null : MdocKeys.iacaAlias(properties.iaca()))
                : new JcaKeyProvider(properties.id());
        List<KeySpec> required = properties.keys() == null ? List.of() : properties.keys();
        for (KeySpec key : required) {
            SignatureAlgorithm.fromJose(key.algorithm())
                    .orElseThrow(() -> new SigningException("Unknown algorithm " + key.algorithm() + " for key " + key.alias()));
        }
        boolean generated = generate(properties, provider, required, path);
        MdocKeys.validate(properties, provider);
        if (generated && path != null) {
            try {
                if (path.getParent() != null) {
                    Files.createDirectories(path.getParent());
                }
            } catch (IOException e) {
                throw new SigningException("Cannot create the keystore directory for " + path, e);
            }
            provider.saveAsPkcs12(path, password);
        }
        // after the keystore is written: an operator's PEM key stays in its own file and never enters the PKCS#12
        MdocKeys.importPemKeys(properties, provider);
        return provider;
    }

    /**
     * Generates what dev mode is allowed to generate and returns whether anything was written: the Annex B IACA first,
     * so the Document Signers can chain to it, then the missing keys. A plain key keeps the P3-08 behaviour exactly
     * (signed by the dev CA), so a configuration without {@code iaca} sees no change.
     */
    private static boolean generate(X509FileProperties properties, JcaKeyProvider provider, List<KeySpec> required,
                                    Path path) {
        boolean generated = false;
        IacaSpec iacaSpec = properties.iaca();
        if (iacaSpec != null) {
            String alias = MdocKeys.iacaAlias(iacaSpec);
            if (!provider.aliases().contains(alias)) {
                if (!properties.devMode()) {
                    throw new SigningException(keystore(path) + " lacks the IACA key '" + alias + "' and dev mode is off");
                }
                requirePathForGeneration(path, "the IACA '" + alias + "'");
                provider.generateIaca(alias, MdocKeys.iacaSpec(iacaSpec));
                generated = true;
            }
            MdocKeys.requireIaca(provider, iacaSpec);
        }
        List<KeySpec> missing = required.stream().filter(k -> !provider.aliases().contains(k.alias())).toList();
        if (!missing.isEmpty() && !properties.devMode()) {
            throw new SigningException(keystore(path) + " lacks the required keys "
                    + missing.stream().map(KeySpec::alias).toList());
        }
        if (!missing.isEmpty()) {
            requirePathForGeneration(path, "the keys " + missing.stream().map(KeySpec::alias).toList());
        }
        if (missing.stream().anyMatch(k -> !k.mdocDsc()) && !provider.aliases().contains(properties.caAlias())) {
            // HAIP forbids a self-signed signing certificate: generated keys chain to a dev CA held in the same keystore
            provider.generateCa(properties.caAlias(), SignatureAlgorithm.ES256, properties.caSubject(), "dev-ca");
            generated = true;
        }
        for (KeySpec key : missing) {
            if (key.mdocDsc()) {
                if (iacaSpec == null) {
                    throw new SigningException("Key " + key.alias() + " has profile mdoc-dsc but"
                            + " certify.keyprovider.x509-file.iaca is not configured");
                }
                provider.generateMdocDsc(key.alias(), MdocKeys.algorithm(key), MdocKeys.commonName(key),
                        key.validityDays(), MdocKeys.iacaAlias(iacaSpec));
            } else {
                String subject = key.subject() == null || key.subject().isBlank()
                        ? "CN=Inji Certify " + key.alias() : key.subject();
                provider.generateSignedBy(key.alias(), SignatureAlgorithm.fromJose(key.algorithm()).orElseThrow(),
                        subject, properties.purpose(), properties.caAlias());
            }
            generated = true;
        }
        return generated;
    }

    /** How messages name the keystore: its path, or the PEM-only configuration that has none. */
    static String keystore(Path path) {
        return path == null ? "The PEM-only configuration (no certify.keyprovider.x509-file.path)" : "Keystore " + path;
    }

    /**
     * Dev mode writes what it generates into the keystore, so the keys survive a restart and a Document Signer keeps
     * matching the mDLs it signed; without {@code path} it would generate new keys on every start.
     */
    private static void requirePathForGeneration(Path path, String what) {
        if (path == null) {
            throw new SigningException("Dev mode would generate " + what + " but has nowhere to keep it: set"
                    + " certify.keyprovider.x509-file.path to the PKCS#12 keystore dev mode should write (for example"
                    + " /var/lib/certify/x509-file.p12), or configure these keys as pem-keys");
        }
    }

    /**
     * The IACA certificates this provider can publish: the dev-mode IACA (or any {@code mdoc-iaca} key) and the anchor
     * every Document Signer chain ends at. The trust-anchor registry of M-06 reads this; nothing here serves HTTP.
     */
    public static List<X509Certificate> iacaCertificates(KeyProvider provider) {
        return MdocKeys.iacaCertificates(provider);
    }
}
