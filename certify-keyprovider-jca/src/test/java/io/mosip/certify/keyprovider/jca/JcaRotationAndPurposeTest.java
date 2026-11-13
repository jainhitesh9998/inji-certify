package io.mosip.certify.keyprovider.jca;

import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-05 review: version order (numeric tie-break, aligned with the CLI's {@code <prefix>@yyyy-MM[.N]} labels), the
 * single-entry carve-out that never applies to a Document Signer, purposes derived from the certificate on reload,
 * and {@link JcaKeyProvider#keyRefs()}.
 */
class JcaRotationAndPurposeTest {

    private static final String CRL = "https://credentials.example.test/iaca.crl";

    @Test
    void versionLabelsCompareTheirNumbersAsNumbers() {
        List<String> labels = new ArrayList<>(List.of("2026-11.10", "2027-01", "2026-11.2", "2026-11", "2026-11.1",
                "2026-9", "2026-10"));
        Collections.shuffle(labels);
        labels.sort(VersionLabels.ORDER);
        assertEquals(List.of("2026-9", "2026-10", "2026-11", "2026-11.1", "2026-11.2", "2026-11.10", "2027-01"), labels);
        assertTrue(VersionLabels.compare(null, "1") < 0, "an unversioned entry sorts first");
        assertEquals(0, VersionLabels.compare("2026-11.02", "2026-11.02"));
        assertTrue(VersionLabels.compare("2026-11.02", "2026-11.2") != 0, "different labels never compare equal");
    }

    @Test
    void equalNotBeforeIsBrokenByTheNumericVersionNotTheText() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys, Instant.now().minus(30, ChronoUnit.DAYS));
        Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        for (String alias : List.of("mdl-dsc@2026-11.10", "mdl-dsc@2026-11.2", "mdl-dsc@2026-11")) {
            addDsc(provider, alias, iaca, iacaKeys, notBefore, 300);
        }

        assertEquals("mdl-dsc@2026-11.10", provider.resolve(KeyRef.parse("x509-file:mdl-dsc")).kid(),
                "2026-11.10 is the newest version, although '2026-11.10' < '2026-11.2' as text");
        assertEquals(List.of("mdl-dsc@2026-11", "mdl-dsc@2026-11.2", "mdl-dsc@2026-11.10"),
                provider.publicKeys(KeyRef.parse("x509-file:mdl-dsc")).stream().map(PublicKeyDescriptor::kid).toList(),
                "publicKeys lists oldest first, in the same order");
        assertEquals("mdl-dsc@2026-11.2", provider.resolve(KeyRef.parse("x509-file:mdl-dsc@2026-11.2")).kid());
        assertEquals(List.of(new KeyRef("x509-file", "mdl-dsc")), provider.keyRefs(), "one reference per alias");
    }

    @Test
    void notBeforeDecidesBeforeTheVersionLabel() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys, Instant.now().minus(30, ChronoUnit.DAYS));
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        addDsc(provider, "mdl-dsc@2026-12", iaca, iacaKeys, Instant.now().minus(2, ChronoUnit.DAYS), 300);
        addDsc(provider, "mdl-dsc@2026-11", iaca, iacaKeys, Instant.now().minus(1, ChronoUnit.DAYS), 300);

        assertEquals("mdl-dsc@2026-11", provider.resolve(KeyRef.parse("x509-file:mdl-dsc")).kid(),
                "the certificate issued last wins, whatever its label says");
        assertEquals(List.of("mdl-dsc@2026-12", "mdl-dsc@2026-11"),
                provider.publicKeys(KeyRef.parse("x509-file:mdl-dsc")).stream().map(PublicKeyDescriptor::kid).toList());
    }

    @Test
    void anExpiredSingleDocumentSignerNeverSignsWhileAnExpiredPlainKeyStillResolves() throws Exception {
        KeyPair iacaKeys = ecKeyPair();
        X509Certificate iaca = iaca(iacaKeys, Instant.now().minus(900, ChronoUnit.DAYS));
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        addDsc(provider, "mdl-dsc", iaca, iacaKeys, Instant.now().minus(500, ChronoUnit.DAYS), 400);
        // the same certificate recorded under a plain purpose is still a Document Signer: it carries the mDL EKU
        addDsc(provider, "mdl-dsc-untagged", iaca, iacaKeys, Instant.now().minus(500, ChronoUnit.DAYS), 400);
        KeyPair plainKeys = ecKeyPair();
        provider.add("legacy", plainKeys.getPrivate(), CertificateChain.of(expiredPlain(plainKeys)), null, "vc-signing");

        SigningException refused = assertThrows(SigningException.class,
                () -> provider.resolve(KeyRef.parse("x509-file:mdl-dsc")));
        assertTrue(refused.getMessage().contains("never signed outside"), refused.getMessage());
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("x509-file:mdl-dsc-untagged")));
        assertEquals("legacy", provider.resolve(KeyRef.parse("x509-file:legacy")).kid(),
                "a plain key with one unversioned entry resolves whatever its dates, as before M-05");
    }

    @Test
    void purposesAreDerivedFromTheCertificateAfterARestart(@TempDir Path dir) {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateIaca("iaca", new MdocIacaSpec(SignatureAlgorithm.ES256, "IN", null, "Demo IACA",
                "https://credentials.example.test/mdoc/iaca", null, CRL, null));
        provider.generateMdocDsc("mdl-dsc@2026-11", SignatureAlgorithm.ES256, "Demo DSC", 300, "iaca");
        provider.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca");
        provider.generateSignedBy("issuer-es256", SignatureAlgorithm.ES256, "CN=VC issuer", "vc-signing", "dev-ca");
        provider.generate("dev-eddsa", SignatureAlgorithm.EdDSA, "CN=dev", "vc-signing");
        Map<String, String> before = purposes(provider);
        Path file = dir.resolve("issuer.p12");
        provider.saveAsPkcs12(file, "pw".toCharArray());

        JcaKeyProvider restarted = JcaKeyProvider.fromPkcs12("x509-file", file, "pw".toCharArray());

        assertEquals(Map.of("iaca", "mdoc-iaca", "mdl-dsc@2026-11", "mdoc-dsc", "dev-ca", "dev-ca",
                "issuer-es256", "vc-signing", "dev-eddsa", "vc-signing"), purposes(restarted));
        assertEquals(before, purposes(restarted), "the purposes of the first start, not vc-signing for everything");
        assertEquals(java.util.Set.of("iaca", "mdl-dsc", "dev-ca", "issuer-es256", "dev-eddsa"),
                restarted.keyRefs().stream().map(KeyRef::alias).collect(Collectors.toSet()),
                "one unversioned reference per alias");
        assertTrue(restarted.publicKeys(KeyFilter.ALL).stream()
                .filter(d -> d.kid().equals("iaca")).noneMatch(PublicKeyDescriptor::isSigningKey),
                "an IACA is never published as a signing key");
    }

    /** Round 3: only the configured dev CA alias is a dev CA; any other CA key an operator keeps stays vc-signing. */
    @Test
    void anOperatorCaKeyKeepsThePlainPurposeOnlyTheConfiguredDevCaIsOne(@TempDir Path dir) {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca");
        provider.generateCa("operator-ca", SignatureAlgorithm.ES256, "CN=Operator signing CA", "vc-signing");
        provider.generateCa("my-dev-ca", SignatureAlgorithm.ES256, "CN=Renamed Dev CA", "dev-ca");
        Path file = dir.resolve("operator.p12");
        provider.saveAsPkcs12(file, "pw".toCharArray());

        assertEquals(Map.of("dev-ca", "dev-ca", "operator-ca", "vc-signing", "my-dev-ca", "vc-signing"),
                purposes(JcaKeyProvider.fromPkcs12("x509-file", file, "pw".toCharArray())), "default ca-alias dev-ca");
        assertEquals(Map.of("dev-ca", "vc-signing", "operator-ca", "vc-signing", "my-dev-ca", "dev-ca"),
                purposes(JcaKeyProvider.fromPkcs12("x509-file", file, "pw".toCharArray(), "vc-signing", "my-dev-ca",
                        null)), "ca-alias: my-dev-ca");
    }

    private static Map<String, String> purposes(JcaKeyProvider provider) {
        return provider.publicKeys(KeyFilter.ALL).stream()
                .collect(Collectors.toMap(PublicKeyDescriptor::kid, PublicKeyDescriptor::purpose));
    }

    private static X509Certificate iaca(KeyPair keys, Instant notBefore) throws Exception {
        return IsoMdocProfiles.iaca(keys).notBefore(notBefore).country("IN").commonName("Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca").crlDistributionPoint(CRL).build();
    }

    private static void addDsc(JcaKeyProvider provider, String alias, X509Certificate iaca, KeyPair iacaKeys,
                               Instant notBefore, int days) throws Exception {
        KeyPair keys = ecKeyPair();
        X509Certificate dsc = IsoMdocProfiles.ds(keys, iaca, iacaKeys).commonName("Demo DSC").notBefore(notBefore)
                .validity(Duration.ofDays(days)).build();
        String purpose = alias.endsWith("-untagged") ? "vc-signing" : "mdoc-dsc";
        provider.add(alias, keys.getPrivate(), CertificateChain.of(dsc, iaca), SignatureAlgorithm.ES256, purpose);
    }

    private static X509Certificate expiredPlain(KeyPair keys) throws Exception {
        Instant start = Instant.now().minus(400, ChronoUnit.DAYS);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=legacy"),
                BigInteger.valueOf(start.toEpochMilli()), Date.from(start), Date.from(start.plus(30, ChronoUnit.DAYS)),
                new X500Name("CN=legacy"), keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
