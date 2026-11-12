package io.mosip.certify.pki;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateRevokedException;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The JDK PKIX validator, an implementation Certify does not own, builds DS to IACA and checks the IACA-signed CRL. */
class PkixPathTest {

    private static PKIXParameters parameters(X509Certificate iaca, X509CRL... crls) throws Exception {
        PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(iaca, null)));
        parameters.setRevocationEnabled(false);
        if (crls.length > 0) {
            parameters.addCertStore(java.security.cert.CertStore.getInstance("Collection",
                    new java.security.cert.CollectionCertStoreParameters(List.of(crls))));
            PKIXRevocationChecker checker = (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
            checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.NO_FALLBACK));
            parameters.addCertPathChecker(checker);
            parameters.setRevocationEnabled(true);
        }
        return parameters;
    }

    private static CertPath path(X509Certificate leaf) throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
    }

    @Test
    void theDocumentSignerPathValidatesToTheIaca() throws Exception {
        Fixture fixture = new Fixture();
        CertPathValidator.getInstance("PKIX").validate(path(fixture.ds), parameters(fixture.iaca));
    }

    @Test
    void theDocumentSignerPathValidatesWithTheIacaSignedCrl() throws Exception {
        Fixture fixture = new Fixture();
        CertPathValidator.getInstance("PKIX").validate(path(fixture.ds), parameters(fixture.iaca, fixture.crl()));
    }

    @Test
    void aRevokedDocumentSignerFailsPathValidation() throws Exception {
        Fixture fixture = new Fixture();
        X509CRL crl = fixture.crl(fixture.ds.getSerialNumber(), java.time.Instant.now());
        assertEquals(fixture.ds.getSerialNumber(), crl.getRevokedCertificate(fixture.ds.getSerialNumber()).getSerialNumber());

        java.security.cert.CertPathValidatorException exception = assertThrows(
                java.security.cert.CertPathValidatorException.class, () -> CertPathValidator.getInstance("PKIX")
                        .validate(path(fixture.ds), parameters(fixture.iaca, crl)));
        assertTrue(exception.getCause() instanceof CertificateRevokedException, () -> "cause: " + exception.getCause());
    }

    @Test
    void aDocumentSignerFromAnotherIacaDoesNotValidate() throws Exception {
        Fixture fixture = new Fixture();
        KeyPair otherKeyPair = BadCerts.ec(256);
        X509Certificate otherIaca = IsoMdocProfiles.iaca(otherKeyPair)
                .country("IN").commonName("Another IACA")
                .issuerAltUri("https://other.example.test/iaca")
                .crlDistributionPoint("https://other.example.test/iaca.crl")
                .build();

        assertThrows(java.security.cert.CertPathValidatorException.class, () -> CertPathValidator.getInstance("PKIX")
                .validate(path(fixture.ds), parameters(otherIaca)));
    }
}
