package io.mosip.certify.keyprovider.x509file;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.jca.MdocIacaSpec;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.keyprovider.x509file.X509FileProperties.IacaSpec;
import io.mosip.certify.keyprovider.x509file.X509FileProperties.KeySpec;
import io.mosip.certify.keyprovider.x509file.X509FileProperties.PemKeySpec;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The ISO/IEC 18013-5:2021 Annex B part of the {@code x509-file} provider (docs/design/20-mdl-issuer.md M-05):
 * turning properties into generation parameters, validating what a deployment holds with {@link AnnexBValidator}, and
 * exposing the IACA certificate the trust-anchor registry (M-06) publishes.
 *
 * <p>A Document Signer is refused at startup when it does not meet Annex B, so an mDL issuer never signs with a
 * certificate a verifier will reject. That includes a DSC without the mDL extended key usage, one whose chain does
 * not end at an IACA, and an IACA that does not conform.
 */
final class MdocKeys {

    /** The purpose recorded on an imported Document Signer; it tells the mDL configuration what it signs with. */
    static final String DSC_PURPOSE = "mdoc-dsc";

    /** The Annex B key algorithms: P-256, P-384 and P-521 (certify-pki's allowlist, decision log 2026-11-13). */
    private static final Set<SignatureAlgorithm> ANNEX_B_ALGORITHMS = Set.of(SignatureAlgorithm.ES256,
            SignatureAlgorithm.ES384, SignatureAlgorithm.ES512);

    private MdocKeys() {}

    /** The IACA alias in the keystore, {@code iaca} when the configuration leaves it out. */
    static String iacaAlias(IacaSpec spec) {
        return spec.alias() == null || spec.alias().isBlank() ? "iaca" : spec.alias();
    }

    /**
     * The generated IACA's parameters. {@code issuerAltName} is an email when it carries an {@code @} and no scheme
     * ({@code pki@example.test}) and a URI otherwise ({@code https://...} or {@code mailto:...}); the IACA profile
     * accepts either.
     */
    static MdocIacaSpec iacaSpec(IacaSpec spec) {
        SignatureAlgorithm algorithm = algorithm(spec.algorithm() == null ? "ES256" : spec.algorithm(),
                "IACA", "an IACA");
        String altName = spec.issuerAltName();
        boolean email = altName != null && altName.contains("@") && !altName.contains(":");
        return new MdocIacaSpec(algorithm, spec.country(), spec.state(), spec.commonName(),
                email ? null : altName, email ? altName : null, spec.crlUri(), spec.validityYears());
    }

    /** The key's algorithm; an Annex B certificate key must be an EC key one of ES256/384/512 names. */
    static SignatureAlgorithm algorithm(KeySpec key) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(key.algorithm())
                .orElseThrow(() -> new SigningException("Unknown algorithm " + key.algorithm() + " for key " + key.alias()));
        return key.mdocDsc() ? algorithm(algorithm.joseName(), key.alias(), "a Document Signer") : algorithm;
    }

    private static SignatureAlgorithm algorithm(String joseName, String alias, String what) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(joseName)
                .orElseThrow(() -> new SigningException("Unknown algorithm " + joseName + " for key " + alias));
        if (!ANNEX_B_ALGORITHMS.contains(algorithm)) {
            throw new SigningException(what + " key " + alias + " uses " + algorithm.joseName()
                    + "; ISO/IEC 18013-5 Annex B allows ES256, ES384 and ES512");
        }
        return algorithm;
    }

    /** The Document Signer common name: the CN of {@code keys[].subject}, the whole value when it has no CN. */
    static String commonName(KeySpec key) {
        String subject = key.subject();
        if (subject == null || subject.isBlank()) {
            return "Inji Certify " + key.alias();
        }
        if (!subject.contains("=")) {
            return subject;
        }
        try {
            for (Rdn rdn : new LdapName(subject).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            throw new SigningException("Key " + key.alias() + " has an unreadable subject DN '" + subject + "'", e);
        }
        return subject;
    }

    /** Validates the configured IACA, when there is one, and every configured Annex B Document Signer against it. */
    static void validate(X509FileProperties properties, JcaKeyProvider provider) {
        List<KeySpec> keys = properties.keys() == null ? List.of() : properties.keys();
        for (KeySpec key : keys) {
            if (!key.mdocDsc()) {
                continue;
            }
            X509Certificate dsc = leaf(provider, key.alias());
            if (!hasMdlEku(dsc)) {
                throw new SigningException("Key " + key.alias() + " has profile mdoc-dsc but its certificate has no mDL"
                        + " extended key usage " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE);
            }
            X509Certificate iaca = iacaFor(properties, provider, key.alias());
            conforming("IACA of Document Signer " + key.alias(), AnnexBValidator.validateIaca(iaca));
            conforming("Document Signer " + key.alias(), AnnexBValidator.validateDs(dsc, iaca));
        }
    }

    /** Validates the IACA an alias names, e.g. one already in the keystore of a production deployment. */
    static void requireIaca(JcaKeyProvider provider, String alias) {
        conforming("IACA " + alias, AnnexBValidator.validateIaca(leaf(provider, alias)));
    }

    /**
     * Reads every {@code pem-keys[]} entry: the private key (encrypted or not, through {@code certify-pki} {@code Pem})
     * and the chain, leaf first. A leaf with the mDL EKU is a Document Signer: its chain must end at an Annex B IACA
     * and pass {@link AnnexBValidator#validateDs} with it.
     */
    static void importPemKeys(X509FileProperties properties, JcaKeyProvider provider) {
        for (PemKeySpec spec : properties.pemKeys() == null ? List.<PemKeySpec>of() : properties.pemKeys()) {
            char[] password = spec.keyPassword() == null ? null : spec.keyPassword().toCharArray();
            PrivateKey privateKey = Pem.readPrivateKey(read(spec.key(), spec.alias()), password);
            List<X509Certificate> chain = Pem.readCertificates(read(spec.chain(), spec.alias()));
            boolean mdocDsc = hasMdlEku(chain.get(0));
            if (mdocDsc) {
                if (chain.size() < 2) {
                    throw new SigningException("DS_IACA_MISSING: PEM key " + spec.alias() + " carries the mDL EKU but"
                            + " its chain holds only the Document Signer; mount the [DSC, IACA] chain");
                }
                X509Certificate iaca = chain.get(chain.size() - 1);
                conforming("IACA of chain " + spec.alias(), AnnexBValidator.validateIaca(iaca));
                conforming("Document Signer " + spec.alias(), AnnexBValidator.validateDs(chain.get(0), iaca));
            }
            provider.add(spec.alias(), privateKey, new CertificateChain(chain), null,
                    mdocDsc ? DSC_PURPOSE : properties.purpose());
        }
    }

    /**
     * The IACA certificates of a provider: an IACA entry a dev-mode deployment generated, and the anchor at the end of
     * every Document Signer chain (production). What M-06's trust-anchor registry publishes, so verifiers can fetch it.
     * A candidate is the last certificate of a chain; it counts when it is self-signed and passes the Annex B IACA
     * profile, which excludes the P3-08 dev CA and a plain self-signed dev key.
     */
    static List<X509Certificate> iacaCertificates(KeyProvider provider) {
        Map<String, X509Certificate> anchors = new LinkedHashMap<>();
        for (PublicKeyDescriptor descriptor : provider.publicKeys(KeyFilter.ALL)) {
            List<X509Certificate> chain = descriptor.chain().leafFirst();
            if (chain.isEmpty()) {
                continue;
            }
            X509Certificate candidate = chain.get(chain.size() - 1);
            if (candidate.getSubjectX500Principal().equals(candidate.getIssuerX500Principal())
                    && AnnexBValidator.validateIaca(candidate).isEmpty()) {
                anchors.putIfAbsent(anchorKey(candidate), candidate);
            }
        }
        return List.copyOf(anchors.values());
    }

    private static String anchorKey(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new SigningException("Cannot encode the IACA certificate " + certificate.getSubjectX500Principal(), e);
        }
    }

    /** The IACA a Document Signer is checked against: the configured one, else its chain's anchor. */
    private static X509Certificate iacaFor(X509FileProperties properties, JcaKeyProvider provider, String alias) {
        IacaSpec spec = properties.iaca();
        if (spec != null && provider.aliases().contains(iacaAlias(spec))) {
            return leaf(provider, iacaAlias(spec));
        }
        List<X509Certificate> chain = provider.resolve(ref(provider, alias)).chain().leafFirst();
        if (chain.size() > 1) {
            return chain.get(chain.size() - 1);
        }
        throw new SigningException("DS_IACA_MISSING: key " + alias + " has no IACA in its chain and"
                + " certify.keyprovider.x509-file.iaca is not configured");
    }

    private static X509Certificate leaf(JcaKeyProvider provider, String alias) {
        return provider.resolve(ref(provider, alias)).chain().leaf()
                .orElseThrow(() -> new SigningException("Key " + alias + " has no certificate"));
    }

    private static KeyRef ref(JcaKeyProvider provider, String alias) {
        return KeyRef.parse(provider.id() + ":" + alias);
    }

    private static boolean hasMdlEku(X509Certificate certificate) {
        try {
            List<String> eku = certificate.getExtendedKeyUsage();
            return eku != null && eku.contains(IsoMdocProfiles.DS_EXTENDED_KEY_USAGE);
        } catch (CertificateParsingException e) {
            throw new SigningException("Cannot read the extended key usage of "
                    + certificate.getSubjectX500Principal(), e);
        }
    }

    private static void conforming(String what, List<AnnexBValidator.Violation> violations) {
        if (!violations.isEmpty()) {
            throw new SigningException(what + " does not meet ISO/IEC 18013-5:2021 Annex B: " + violations.stream()
                    .map(AnnexBValidator.Violation::toString).collect(Collectors.joining("; ")));
        }
    }

    private static String read(Path file, String alias) {
        if (file == null) {
            throw new SigningException("PEM key " + alias + " needs both a key and a chain file");
        }
        try {
            return Files.readString(file, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new SigningException("Cannot read " + file + " of PEM key " + alias, e);
        }
    }
}
