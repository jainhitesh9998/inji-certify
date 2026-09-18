package io.mosip.certify.keyprovider.x509file;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.util.List;

/**
 * {@code certify.keyprovider.x509-file.*} (docs/design/14-configuration.md): a PKCS#12 file as issuer key store.
 *
 * @param enabled  off by default; keymanager stays the default provider
 * @param id       the provider id used in key references ({@code x509-file:alias})
 * @param path     the PKCS#12 file
 * @param password its password
 * @param devMode  generate the keys listed under {@code keys} (self-signed certificates) and create the file when
 *                 missing; never on in production
 * @param keys     the keys the provider must hold (alias, algorithm, subject DN); in dev mode they are generated,
 *                 otherwise they must exist in the file
 * @param purpose  purpose recorded on generated keys
 */
@ConfigurationProperties(prefix = "certify.keyprovider.x509-file")
public record X509FileProperties(@DefaultValue("false") boolean enabled, @DefaultValue("x509-file") String id, Path path, String password,
                                 @DefaultValue("false") boolean devMode, List<KeySpec> keys, @DefaultValue("vc-signing") String purpose) {

    /** One required key. */
    public record KeySpec(String alias, String algorithm, String subject) {}
}
