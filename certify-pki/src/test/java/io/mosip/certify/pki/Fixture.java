package io.mosip.certify.pki;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;

/** A conforming IACA, Document Signer and CRL set that the profile tests start from. */
final class Fixture {

    static final String CRL_URI = "https://credentials.example.test/mdoc/iaca/lorem-ipsum-demo-iaca.crl";

    final KeyPair iacaKeyPair;
    final X509Certificate iaca;
    final KeyPair dsKeyPair;
    final X509Certificate ds;

    Fixture() {
        this(256);
    }

    Fixture(int curveBits) {
        iacaKeyPair = BadCerts.ec(curveBits);
        iaca = IsoMdocProfiles.iaca(iacaKeyPair)
                .country("IN")
                .state("Karnataka")
                .organization("Lorem Ipsum Demo")
                .commonName("Lorem Ipsum Demo IACA")
                .issuerAltUri("https://credentials.example.test/mdoc/iaca")
                .issuerAltEmail("pki@example.test")
                .crlDistributionPoint(CRL_URI)
                .build();
        dsKeyPair = BadCerts.ec(curveBits);
        ds = IsoMdocProfiles.ds(dsKeyPair, iaca, iacaKeyPair)
                .commonName("Lorem Ipsum Demo DSC")
                .build();
    }

    X509CRL crl() {
        return CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.ONE).build();
    }

    X509CRL crl(BigInteger revokedSerial, Instant revokedAt) {
        return CrlBuilder.forIaca(iaca, iacaKeyPair)
                .crlNumber(BigInteger.TWO)
                .revoke(revokedSerial, revokedAt)
                .build();
    }
}
