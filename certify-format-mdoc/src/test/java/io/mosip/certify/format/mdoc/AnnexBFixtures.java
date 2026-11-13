package io.mosip.certify.format.mdoc;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TrustAnchorRegistry;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * ISO/IEC 18013-5 Annex B certificates built with {@code certify-pki} (the code x509-file dev mode delegates to), so a
 * test holds the IACA's private key and can issue Document Signers, CRLs and deliberately broken certificates.
 */
final class AnnexBFixtures {

    static final String CRL_URI = "https://credentials.example.test/v1/certify/mdoc/iaca/test-iaca.crl";
    /** Before the formatter fixtures' request clock ({@link MdlFixtures#NOW}), which is fixed when that class loads. */
    static final Instant ISSUED = Instant.now().minus(1, ChronoUnit.HOURS);
    static final KeyPair IACA_KEYS = p256();
    static final X509Certificate IACA = IsoMdocProfiles.iaca(IACA_KEYS).country("IN").organization("Lorem Ipsum Demo")
            .commonName("Lorem Ipsum Demo Test IACA").issuerAltUri("https://credentials.example.test")
            .crlDistributionPoint(CRL_URI).notBefore(ISSUED).build();
    static final KeyPair DSC_KEYS = p256();
    static final X509Certificate DSC = IsoMdocProfiles.ds(DSC_KEYS, IACA, IACA_KEYS).commonName("Lorem Ipsum Demo Test DSC").notBefore(ISSUED).build();

    /** A second, unconfigured IACA of the same country and its Document Signer. */
    static final KeyPair OTHER_IACA_KEYS = p256();
    static final X509Certificate OTHER_IACA = IsoMdocProfiles.iaca(OTHER_IACA_KEYS).country("IN")
            .commonName("Lorem Ipsum Other Test IACA").issuerAltUri("https://other.example.test")
            .crlDistributionPoint("https://other.example.test/iaca.crl").notBefore(ISSUED).build();
    static final KeyPair OTHER_DSC_KEYS = p256();
    static final X509Certificate OTHER_DSC = IsoMdocProfiles.ds(OTHER_DSC_KEYS, OTHER_IACA, OTHER_IACA_KEYS)
            .commonName("Lorem Ipsum Other Test DSC").notBefore(ISSUED).build();

    static final JcaKeyProvider KEYS = provider();

    private AnnexBFixtures() {}

    private static JcaKeyProvider provider() {
        JcaKeyProvider provider = new JcaKeyProvider("jca");
        provider.add("annexb-dsc", DSC_KEYS.getPrivate(), CertificateChain.of(DSC, IACA), SignatureAlgorithm.ES256, "mdoc-dsc");
        provider.add("other-dsc", OTHER_DSC_KEYS.getPrivate(), CertificateChain.of(OTHER_DSC, OTHER_IACA), SignatureAlgorithm.ES256, "mdoc-dsc");
        return provider;
    }

    static SigningKey dsc() {
        return KEYS.resolve(KeyRef.parse("jca:annexb-dsc"));
    }

    static SigningKey otherDsc() {
        return KEYS.resolve(KeyRef.parse("jca:other-dsc"));
    }

    /** A registry trusting {@code iacas} under ids {@code iaca-0}, {@code iaca-1}…, with CRLs by id. */
    static TrustAnchorRegistry registry(List<X509Certificate> iacas, Map<String, X509CRL> crls) {
        List<TrustAnchorRegistry.Anchor> anchors = new java.util.ArrayList<>();
        for (int i = 0; i < iacas.size(); i++) {
            anchors.add(new TrustAnchorRegistry.Anchor("iaca-" + i, TrustAnchorRegistry.MDOC_IACA, iacas.get(i)));
        }
        return new TrustAnchorRegistry() {
            @Override
            public List<Anchor> entries(String purpose) {
                return TrustAnchorRegistry.MDOC_IACA.equals(purpose) ? List.copyOf(anchors) : List.of();
            }

            @Override
            public Optional<X509CRL> crl(String anchorId) {
                return Optional.ofNullable(crls.get(anchorId));
            }
        };
    }

    static TrustAnchorRegistry trusting(X509Certificate... iacas) {
        return registry(List.of(iacas), Map.of());
    }

    static X509CRL crlRevoking(BigInteger... serials) {
        CrlBuilder builder = CrlBuilder.forIaca(IACA, IACA_KEYS).crlNumber(BigInteger.ONE)
                .thisUpdate(Instant.now().minus(1, ChronoUnit.MINUTES));
        for (BigInteger serial : serials) {
            builder.revoke(serial, Instant.now().minus(2, ChronoUnit.MINUTES));
        }
        return builder.build();
    }

    /**
     * A certificate for {@code subjectKeys} signed by the IACA key with nothing an Annex B DS carries (no AKI, no key
     * usage, no EKU) and an arbitrary validity, which the {@code certify-pki} builders refuse to produce.
     */
    static X509Certificate bareCertificate(KeyPair subjectKeys, String subject, Instant notBefore, Instant notAfter) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(IACA.getSubjectX500Principal().getEncoded()), new BigInteger(72, new java.security.SecureRandom()).setBit(71),
                    Date.from(notBefore), Date.from(notAfter), new X500Name(subject), subjectKeys.getPublic());
            return new JcaX509CertificateConverter().getCertificate(builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").build(IACA_KEYS.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair p256() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
