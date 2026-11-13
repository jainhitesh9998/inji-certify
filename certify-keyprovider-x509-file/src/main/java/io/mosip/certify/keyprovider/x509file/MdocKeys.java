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
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
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
 * not end at an IACA, and an IACA that does not conform. Settings that shaped a certificate already in the keystore
 * are compared with it on every start: a certificate cannot change in place, so a difference refuses startup instead
 * of being ignored.
 */
final class MdocKeys {

    /** The purpose recorded on an imported Document Signer; it tells the mDL configuration what it signs with. */
    static final String DSC_PURPOSE = JcaKeyProvider.PURPOSE_MDOC_DSC;

    /** The Annex B key algorithms: P-256, P-384 and P-521 (certify-pki's allowlist, decision log 2026-11-13). */
    private static final Set<SignatureAlgorithm> ANNEX_B_ALGORITHMS = Set.of(SignatureAlgorithm.ES256,
            SignatureAlgorithm.ES384, SignatureAlgorithm.ES512);

    private static final double DAYS_PER_YEAR = 365.2425;

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

    /**
     * Validates every configured Annex B Document Signer: the mDL EKU, the IACA its chain ends at (or the configured
     * one, for a leaf-only entry), {@link AnnexBValidator#validateDs} against it, and the {@code keys[]} settings it
     * was generated from. The exact entry is checked, never the rotation's current one, so an expired version does not
     * stop a start; it simply is never chosen to sign.
     */
    static void validate(X509FileProperties properties, JcaKeyProvider provider) {
        List<KeySpec> keys = properties.keys() == null ? List.of() : properties.keys();
        for (KeySpec key : keys) {
            if (!key.mdocDsc()) {
                continue;
            }
            List<X509Certificate> chain = entry(provider, key.alias()).chain().leafFirst();
            X509Certificate dsc = chain.get(0);
            if (!JcaKeyProvider.hasMdlEku(dsc)) {
                throw new SigningException("Key " + key.alias() + " has profile mdoc-dsc but its certificate has no mDL"
                        + " extended key usage " + IsoMdocProfiles.DS_EXTENDED_KEY_USAGE);
            }
            X509Certificate iaca = iacaFor(properties, provider, key.alias(), chain);
            conforming("IACA of Document Signer " + key.alias(), AnnexBValidator.validateIaca(iaca));
            conforming("Document Signer " + key.alias(), AnnexBValidator.validateDs(dsc, iaca));
            checkDscSettings(key, dsc, iaca);
        }
    }

    /**
     * Validates the IACA an alias names, generated by dev mode or already in a production keystore, and compares it
     * with every {@code iaca.*} setting that is given.
     */
    static void requireIaca(JcaKeyProvider provider, IacaSpec spec) {
        String alias = iacaAlias(spec);
        X509Certificate iaca = leaf(entry(provider, alias), alias);
        conforming("IACA " + alias, AnnexBValidator.validateIaca(iaca));
        checkIacaSettings(spec, alias, iaca);
    }

    /**
     * Reads every {@code pem-keys[]} entry: the private key (encrypted or not, through {@code certify-pki} {@code Pem})
     * and the chain, leaf first, each certificate signed by the next. The private key must be the one the leaf
     * certifies (proved by signing a random challenge and verifying it with the leaf's public key). A leaf with the
     * mDL EKU is a Document Signer: its chain must be exactly {@code [DSC, IACA]} (Annex B has no intermediate CAs)
     * and pass {@link AnnexBValidator#validateDs} against that IACA.
     *
     * <p>Called after the keystore has been written, so a PEM key is never copied into the PKCS#12 file.
     */
    static void importPemKeys(X509FileProperties properties, JcaKeyProvider provider) {
        for (PemKeySpec spec : properties.pemKeys() == null ? List.<PemKeySpec>of() : properties.pemKeys()) {
            if (provider.aliases().contains(spec.alias())) {
                String holder = properties.path() == null ? "another pem-keys entry"
                        : "a key already in the keystore " + properties.path() + " or another pem-keys entry";
                throw new SigningException("PEM key " + spec.alias() + " has the alias of " + holder
                        + "; give one of them another alias");
            }
            char[] password = spec.keyPassword() == null ? null : spec.keyPassword().toCharArray();
            PrivateKey privateKey = Pem.readPrivateKey(read(spec.key(), spec.alias()), password);
            List<X509Certificate> chain = Pem.readCertificates(read(spec.chain(), spec.alias()));
            if (chain.isEmpty()) {
                throw new SigningException("PEM key " + spec.alias() + ": " + spec.chain() + " holds no certificate");
            }
            boolean mdocDsc = JcaKeyProvider.hasMdlEku(chain.get(0));
            if (mdocDsc) {
                if (chain.size() < 2) {
                    throw new SigningException("DS_IACA_MISSING: PEM key " + spec.alias() + " carries the mDL EKU but"
                            + " its chain holds only the Document Signer; mount the [DSC, IACA] chain");
                }
                if (chain.size() > 2) {
                    throw new SigningException("PEM key " + spec.alias() + " carries the mDL EKU and its chain holds "
                            + chain.size() + " certificates; ISO/IEC 18013-5 Annex B has no intermediate CAs, so the"
                            + " chain must be exactly [DSC, IACA]");
                }
                // Annex B first: its named rules (DS_ISSUER_MISMATCH, ...) say more than a broken link would
                X509Certificate iaca = chain.get(1);
                conforming("IACA of chain " + spec.alias(), AnnexBValidator.validateIaca(iaca));
                conforming("Document Signer " + spec.alias(), AnnexBValidator.validateDs(chain.get(0), iaca));
            }
            requireLinkedChain(spec.alias(), chain);
            requireMatchingKey(spec.alias(), privateKey, chain.get(0));
            provider.add(spec.alias(), privateKey, new CertificateChain(chain), null,
                    JcaKeyProvider.purposeOf(spec.alias(), chain.get(0), properties.purpose(), properties.caAlias(),
                            properties.iaca() == null ? null : iacaAlias(properties.iaca())));
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

    /** The IACA settings given in {@code iaca.*} that the certificate in the keystore does not carry refuse startup. */
    static void checkIacaSettings(IacaSpec spec, String alias, X509Certificate iaca) {
        List<String> differences = new ArrayList<>();
        differ(differences, "iaca.country", spec.country(), rdn(iaca, BCStyle.C));
        differ(differences, "iaca.state", spec.state(), rdn(iaca, BCStyle.ST));
        differ(differences, "iaca.common-name", spec.commonName(), rdn(iaca, BCStyle.CN));
        if (spec.issuerAltName() != null && !issuerAltNames(iaca).contains(spec.issuerAltName())) {
            differences.add("iaca.issuer-alt-name is '" + spec.issuerAltName() + "', the IACA carries "
                    + issuerAltNames(iaca));
        }
        differ(differences, "iaca.crl-uri", spec.crlUri(), crlUri(iaca));
        if (spec.algorithm() != null && !spec.algorithm().equalsIgnoreCase(algorithmOf(iaca.getPublicKey()))) {
            differences.add("iaca.algorithm is '" + spec.algorithm() + "', the IACA key is "
                    + algorithmOf(iaca.getPublicKey()));
        }
        if (spec.validityYears() != null) {
            long years = Math.round(days(iaca) / DAYS_PER_YEAR);
            if (years != spec.validityYears()) {
                differences.add("iaca.validity-years is " + spec.validityYears() + ", the IACA is valid for "
                        + years + " years (" + iaca.getNotBefore().toInstant() + " to "
                        + iaca.getNotAfter().toInstant() + ")");
            }
        }
        if (!differences.isEmpty()) {
            throw new SigningException("The IACA '" + alias + "' in the keystore does not match"
                    + " certify.keyprovider.x509-file.iaca: " + String.join("; ", differences) + ". An IACA is a trust"
                    + " anchor verifiers already hold and is never regenerated automatically: restore these settings,"
                    + " or set iaca.alias to a new alias (for example '" + alias + "-2') so dev mode generates a new"
                    + " IACA, and distribute it to verifiers; Document Signers already issued keep their own IACA");
        }
    }

    /** The {@code keys[]} settings of a Document Signer that its certificate in the keystore does not carry. */
    static void checkDscSettings(KeySpec key, X509Certificate dsc, X509Certificate iaca) {
        List<String> differences = new ArrayList<>();
        if (key.subject() != null && !key.subject().isBlank()) {
            differ(differences, "keys[].subject (CN)", commonName(key), rdn(dsc, BCStyle.CN));
        }
        if (key.algorithm() != null && !key.algorithm().equalsIgnoreCase(algorithmOf(dsc.getPublicKey()))) {
            differences.add("keys[].algorithm is '" + key.algorithm() + "', the Document Signer key is "
                    + algorithmOf(dsc.getPublicKey()));
        }
        if (key.validityDays() != null) {
            long days = Math.round(days(dsc));
            // a DSC whose requested validity would outlive its IACA ends with the IACA (certify-pki DsBuilder): the
            // expected end is min(notBefore + validity-days - 1 s, IACA notAfter), so the clamp excuses a shorter
            // certificate only when the configured validity really reaches the IACA's end
            Instant notBefore = dsc.getNotBefore().toInstant().truncatedTo(ChronoUnit.SECONDS);
            Instant requestedEnd = notBefore.plus(Duration.ofDays(key.validityDays())).minusSeconds(1);
            Instant iacaEnd = iaca.getNotAfter().toInstant().truncatedTo(ChronoUnit.SECONDS);
            Instant expectedEnd = requestedEnd.isBefore(iacaEnd) ? requestedEnd : iacaEnd;
            long expectedDays = Math.round(Duration.between(notBefore, expectedEnd.plusSeconds(1)).getSeconds()
                    / 86_400.0);
            if (days != expectedDays) {
                differences.add("keys[].validity-days is " + key.validityDays() + ", the Document Signer is valid for "
                        + days + " days (" + dsc.getNotBefore().toInstant() + " to " + dsc.getNotAfter().toInstant()
                        + (dsc.getNotAfter().toInstant().truncatedTo(ChronoUnit.SECONDS).equals(iacaEnd)
                                ? ", ending with its IACA" : "") + ")");
            }
        }
        if (!differences.isEmpty()) {
            String base = key.alias().contains("@") ? key.alias().substring(0, key.alias().lastIndexOf('@')) : key.alias();
            throw new SigningException("The Document Signer '" + key.alias() + "' in the keystore does not match its"
                    + " configuration: " + String.join("; ", differences) + ". A certificate cannot change in place:"
                    + " restore these settings, or add a new version of the key (for example '" + base + "@"
                    + YearMonth.now(ZoneOffset.UTC) + "') so dev mode issues a new Document Signer, and keep this"
                    + " version for the credentials it signed");
        }
    }

    private static void differ(List<String> differences, String property, String configured, String actual) {
        if (configured != null && !configured.equals(actual)) {
            differences.add(property + " is '" + configured + "', the certificate has "
                    + (actual == null ? "none" : "'" + actual + "'"));
        }
    }

    private static double days(X509Certificate certificate) {
        // notAfter is inclusive (RFC 5280 4.1.2.5): a one-day certificate ends one second before the next day
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant().plusSeconds(1);
        return Duration.between(notBefore, notAfter).getSeconds() / 86_400.0;
    }

    /** ES256, ES384 or ES512 for a P-256/384/521 key; the JCA key algorithm otherwise. */
    static String algorithmOf(PublicKey key) {
        if (key instanceof ECPublicKey ec) {
            return switch (ec.getParams().getCurve().getField().getFieldSize()) {
                case 256 -> "ES256";
                case 384 -> "ES384";
                case 521 -> "ES512";
                default -> "EC-" + ec.getParams().getCurve().getField().getFieldSize();
            };
        }
        return key.getAlgorithm();
    }

    private static String rdn(X509Certificate certificate, ASN1ObjectIdentifier type) {
        X500Name name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        RDN[] rdns = name.getRDNs(type);
        if (rdns.length == 0) {
            return null;
        }
        ASN1Encodable value = rdns[0].getFirst().getValue();
        return value instanceof ASN1String string ? string.getString() : value.toString();
    }

    private static List<String> issuerAltNames(X509Certificate certificate) {
        try {
            Collection<List<?>> names = certificate.getIssuerAlternativeNames();
            List<String> out = new ArrayList<>();
            if (names != null) {
                for (List<?> name : names) {
                    if (name.size() > 1 && name.get(1) instanceof String value) {
                        out.add(value);
                    }
                }
            }
            return out;
        } catch (CertificateParsingException e) {
            throw new SigningException("Cannot read the issuerAltName of " + certificate.getSubjectX500Principal(), e);
        }
    }

    private static String crlUri(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extension == null) {
            return null;
        }
        try {
            CRLDistPoint points = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extension));
            for (DistributionPoint point : points.getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();
                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                for (GeneralName general : GeneralNames.getInstance(name.getName()).getNames()) {
                    if (general.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return DERIA5String.getInstance(general.getName()).getString();
                    }
                }
            }
            return null;
        } catch (IOException | RuntimeException e) {
            throw new SigningException("Cannot read the CRL distribution point of "
                    + certificate.getSubjectX500Principal(), e);
        }
    }

    /** Leaf first, each certificate signed by the next: a chain in another order is refused, not reordered. */
    private static void requireLinkedChain(String alias, List<X509Certificate> chain) {
        for (int i = 0; i + 1 < chain.size(); i++) {
            X509Certificate child = chain.get(i);
            X509Certificate parent = chain.get(i + 1);
            boolean linked = child.getIssuerX500Principal().equals(parent.getSubjectX500Principal());
            if (linked) {
                try {
                    child.verify(parent.getPublicKey());
                } catch (GeneralSecurityException e) {
                    linked = false;
                }
            }
            if (!linked) {
                throw new SigningException("PEM key " + alias + ": certificate " + (i + 1) + " of the chain ("
                        + child.getSubjectX500Principal() + ") is not signed by certificate " + (i + 2) + " ("
                        + parent.getSubjectX500Principal() + "); the chain file must be leaf first, each certificate"
                        + " followed by its issuer");
            }
        }
    }

    /**
     * Proves the private key belongs to the leaf certificate: a random challenge signed with the key must verify
     * with the certificate's public key. Comparing algorithms or curves alone would accept another key of the same
     * kind, which would sign credentials no verifier can check against the published chain.
     */
    static void requireMatchingKey(String alias, PrivateKey privateKey, X509Certificate leaf) {
        PublicKey publicKey = leaf.getPublicKey();
        String algorithm = switch (publicKey) {
            case ECPublicKey ignored -> "SHA256withECDSA";
            case RSAPublicKey ignored -> "SHA256withRSA";
            default -> "Ed25519".equalsIgnoreCase(publicKey.getAlgorithm())
                    || "EdDSA".equalsIgnoreCase(publicKey.getAlgorithm()) ? "Ed25519" : null;
        };
        if (algorithm == null) {
            throw new SigningException("PEM key " + alias + ": unsupported certificate key type " + publicKey.getAlgorithm());
        }
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        boolean matches;
        try {
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            matches = verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            // a key of another type than the certificate's cannot even initialise the signature
            matches = false;
        }
        if (!matches) {
            throw new SigningException("PEM key " + alias + ": the private key does not match the public key of the"
                    + " leaf certificate " + leaf.getSubjectX500Principal() + " (serial " + leaf.getSerialNumber()
                    + "); mount the key the Document Signer certificate was issued for");
        }
    }

    private static String anchorKey(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new SigningException("Cannot encode the IACA certificate " + certificate.getSubjectX500Principal(), e);
        }
    }

    /**
     * The IACA a Document Signer is checked against: the anchor its chain ends at, so Document Signers issued under a
     * previous IACA alias keep validating after an IACA rotation; the configured IACA for a leaf-only entry.
     */
    private static X509Certificate iacaFor(X509FileProperties properties, JcaKeyProvider provider, String alias,
                                           List<X509Certificate> chain) {
        if (chain.size() > 1) {
            return chain.get(chain.size() - 1);
        }
        IacaSpec spec = properties.iaca();
        if (spec != null && provider.aliases().contains(iacaAlias(spec))) {
            return leaf(entry(provider, iacaAlias(spec)), iacaAlias(spec));
        }
        throw new SigningException("DS_IACA_MISSING: key " + alias + " has no IACA in its chain and"
                + " certify.keyprovider.x509-file.iaca is not configured");
    }

    /** The entry stored under exactly this alias, whatever its dates; rotation does not apply here. */
    private static PublicKeyDescriptor entry(JcaKeyProvider provider, String alias) {
        return provider.publicKeys(KeyFilter.ALL).stream()
                .filter(descriptor -> descriptor.kid().equals(alias))
                .findFirst()
                .orElseThrow(() -> new SigningException("No key with alias '" + alias + "' in provider "
                        + provider.id()));
    }

    private static X509Certificate leaf(PublicKeyDescriptor descriptor, String alias) {
        return descriptor.chain().leaf().orElseThrow(() -> new SigningException("Key " + alias + " has no certificate"));
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
