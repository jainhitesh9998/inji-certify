package io.mosip.certify.keyprovider.jca;

import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateChainPolicy;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Dev chains: a CA-signed leaf, the anchor left out of x5c, and the chain check before signing. */
class DevChainTest {

    @Test
    void aLeafSignedByTheDevCaChainsAndDropsTheAnchor() {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateCa("dev-ca", SignatureAlgorithm.ES256, "CN=Inji Certify Dev CA", "dev-ca");
        SigningKey leaf = provider.generateSignedBy("issuer-es256", SignatureAlgorithm.ES256, "CN=Issuer", "vc-signing", "dev-ca");

        CertificateChain chain = leaf.chain();
        assertEquals(2, chain.leafFirst().size(), "leaf then CA");
        X509Certificate leafCert = chain.leaf().orElseThrow();
        X509Certificate ca = chain.root().orElseThrow();
        assertEquals(ca.getSubjectX500Principal(), leafCert.getIssuerX500Principal(), "the leaf is issued by the CA");
        assertEquals(-1, leafCert.getBasicConstraints(), "the leaf is not a CA");
        assertEquals(Integer.MAX_VALUE, ca.getBasicConstraints(), "the CA is a CA");
        assertEquals(1, chain.withoutAnchor().leafFirst().size(), "HAIP: no anchor in x5c");
        CertificateChain lone = CertificateChain.of(leafCert);
        assertSame(lone, lone.withoutAnchor(), "a lone certificate stays");
        assertEquals(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, JwsHeaderPolicy.sdJwtVc().withX5c(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR).x5c());
        CertificateChainPolicy.check(chain, Instant.now());
    }

    @Test
    void theChainPolicyRefusesBrokenLinksAndDates() {
        JcaKeyProvider provider = new JcaKeyProvider("x509-file");
        provider.generateCa("ca-a", SignatureAlgorithm.ES256, "CN=CA A", "dev-ca");
        provider.generateCa("ca-b", SignatureAlgorithm.ES256, "CN=CA B", "dev-ca");
        SigningKey leaf = provider.generateSignedBy("leaf", SignatureAlgorithm.ES256, "CN=Leaf", "vc-signing", "ca-a");
        X509Certificate otherCa = provider.resolve(new io.mosip.certify.signing.KeyRef("x509-file", "ca-b")).chain().leaf().orElseThrow();
        CertificateChain wrongIssuer = CertificateChain.of(leaf.chain().leaf().orElseThrow(), otherCa);
        assertThrows(SigningException.class, () -> CertificateChainPolicy.check(wrongIssuer, Instant.now()), "leaf not signed by the CA it is chained to");
        assertThrows(SigningException.class, () -> CertificateChainPolicy.check(leaf.chain(), Instant.now().plus(400, ChronoUnit.DAYS)), "expired leaf");
        CertificateChainPolicy.check(CertificateChain.EMPTY, Instant.now());
    }
}
