package io.mosip.certify.keyprovider.x509file;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.util.List;

/**
 * {@code certify.keyprovider.x509-file.*} (docs/design/14-configuration.md): a PKCS#12 file as issuer key store, with
 * an optional ISO/IEC 18013-5:2021 Annex B dev mode and PEM key import (docs/design/20-mdl-issuer.md M-05).
 *
 * @param enabled  off by default; keymanager stays the default provider
 * @param id       the provider id used in key references ({@code x509-file:alias})
 * @param path     the PKCS#12 file
 * @param password its password
 * @param devMode  generate the keys listed under {@code keys} (self-signed certificates) and create the file when
 *                 missing; never on in production
 * @param keys     the keys the provider must hold (alias, algorithm, subject DN); in dev mode they are generated,
 *                 otherwise they must exist in the file
 * @param caAlias  alias of the dev CA that signs generated keys (dev mode); {@code caSubject} its subject
 * @param purpose  purpose recorded on generated keys
 * @param iaca     an Annex B Issuing Authority CA to generate in dev mode; when set, every key with
 *                 {@code profile: mdoc-dsc} is generated as a Document Signer under it
 * @param pemKeys  Document Signer keys and chains an operator already holds, read from PEM files (production)
 */
@ConfigurationProperties(prefix = "certify.keyprovider.x509-file")
public record X509FileProperties(@DefaultValue("false") boolean enabled, @DefaultValue("x509-file") String id, Path path, String password,
                                 @DefaultValue("false") boolean devMode, List<KeySpec> keys, @DefaultValue("vc-signing") String purpose,
                                 @DefaultValue("dev-ca") String caAlias, @DefaultValue("CN=Inji Certify Dev CA") String caSubject,
                                 IacaSpec iaca, List<PemKeySpec> pemKeys) {

    /** Boot binds the canonical constructor; the annotation is required because of the convenience constructor below. */
    @ConstructorBinding
    public X509FileProperties {
    }

    /** The pre-M-05 shape, so a caller that predates the mDL properties needs no change. */
    public X509FileProperties(boolean enabled, String id, Path path, String password, boolean devMode, List<KeySpec> keys,
                              String purpose, String caAlias, String caSubject) {
        this(enabled, id, path, password, devMode, keys, purpose, caAlias, caSubject, null, null);
    }

    /**
     * One required key.
     *
     * @param alias        the key alias; {@code alias@version} (e.g. {@code mdl-dsc@2026-11}) is one version of a
     *                     rotated key
     * @param algorithm    JOSE algorithm name ({@code ES256}, {@code EdDSA}, ...)
     * @param subject      subject DN used for a generated certificate; for {@code profile: mdoc-dsc} its CN is the
     *                     Document Signer common name
     * @param profile      {@code plain} (default) for the P3-08 dev CA path, {@code mdoc-dsc} for an Annex B Document
     *                     Signer under the configured IACA
     * @param validityDays certificate lifetime for generated keys, in days; {@code null} for the provider default
     *                     (365 days plain, 457 days Annex B maximum for a Document Signer)
     */
    public record KeySpec(String alias, String algorithm, String subject,
                          @DefaultValue("plain") String profile, Integer validityDays) {

        @ConstructorBinding
        public KeySpec {
        }

        public KeySpec(String alias, String algorithm, String subject) {
            this(alias, algorithm, subject, null, null);
        }

        public boolean mdocDsc() {
            return "mdoc-dsc".equalsIgnoreCase(profile);
        }
    }

    /**
     * The Annex B Issuing Authority CA (ISO/IEC 18013-5:2021 Annex B, decisions D2 and D3). Set the block to have dev
     * mode generate the IACA; every key with {@code profile: mdoc-dsc} then chains to it. In production the block may
     * be set too, to name an IACA already in the keystore for validation.
     *
     * @param alias        the keystore alias of the IACA key and certificate
     * @param country      subject country (C), ISO 3166-1 alpha-2
     * @param state        subject state (ST), optional
     * @param commonName   subject common name (CN); say Demo or Test for a non-production authority
     * @param issuerAltName issuerAltName, a URI or an email address
     * @param crlUri       CRL distribution point, an absolute http(s) URI; a Document Signer copies it
     * @param validityYears requested IACA lifetime in years; {@code null} for the 20-year Annex B maximum
     * @param algorithm    IACA signing algorithm; Annex B allows ES256, ES384 and ES512 (P-256/384/521)
     */
    public record IacaSpec(@DefaultValue("iaca") String alias, String country, String state, String commonName,
                           String issuerAltName, String crlUri, Integer validityYears,
                           @DefaultValue("ES256") String algorithm) {
    }

    /**
     * A key an operator already holds as PEM files.
     *
     * @param alias       the key alias, optionally {@code alias@version}
     * @param key         the private key file (PKCS#8 or SEC1/RSA, optionally encrypted)
     * @param keyPassword the password of an encrypted key; {@code null} for a plaintext one
     * @param chain       the certificate chain file, leaf first: {@code [DSC, IACA]} for an mDL Document Signer
     */
    public record PemKeySpec(String alias, Path key, String keyPassword, Path chain) {
    }
}
