package io.mosip.certify.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

/**
 * An X.509 v2 certificate revocation list signed by an IACA, as ISO/IEC 18013-5:2021 Annex B refers to from the CRL
 * distribution point of IACA and Document Signer certificates. The CRL carries the IACA authority key identifier, a
 * CRL number, thisUpdate and nextUpdate, and a reason for every revoked serial.
 */
public final class CrlBuilder {

    private final X509Certificate iaca;
    private final KeyPair iacaKeyPair;
    private Instant thisUpdate = Instant.now();
    private Instant nextUpdate;
    private BigInteger crlNumber;
    private final X509v2CRLBuilder entries;

    private CrlBuilder(X509Certificate iaca, KeyPair iacaKeyPair, Instant thisUpdate) {
        this.iaca = Objects.requireNonNull(iaca, "iaca");
        this.iacaKeyPair = Objects.requireNonNull(iacaKeyPair, "iacaKeyPair");
        if (!java.util.Arrays.equals(iaca.getPublicKey().getEncoded(), iacaKeyPair.getPublic().getEncoded())) {
            throw new PkiException("IACA_KEY_MISMATCH: the IACA signing key does not match the IACA certificate");
        }
        this.thisUpdate = thisUpdate;
        this.entries = new X509v2CRLBuilder(X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
    }

    /** A v2 CRL issued by the given IACA; {@code thisUpdate} defaults to now. */
    public static CrlBuilder forIaca(X509Certificate iaca, KeyPair iacaKeyPair) {
        return new CrlBuilder(iaca, iacaKeyPair, Instant.now());
    }

    public CrlBuilder thisUpdate(Instant thisUpdate) {
        this.thisUpdate = Objects.requireNonNull(thisUpdate, "thisUpdate");
        this.entries.setThisUpdate(Date.from(thisUpdate));
        return this;
    }

    /** nextUpdate, default 30 days after thisUpdate; it must be later than thisUpdate. */
    public CrlBuilder nextUpdate(Instant nextUpdate) {
        this.nextUpdate = Objects.requireNonNull(nextUpdate, "nextUpdate");
        return this;
    }

    /** CRL number, default the epoch second of thisUpdate. */
    public CrlBuilder crlNumber(BigInteger crlNumber) {
        this.crlNumber = Objects.requireNonNull(crlNumber, "crlNumber");
        return this;
    }

    /** Revoke a serial with an RFC 5280 reason code ({@link CRLReason}). */
    public CrlBuilder revoke(BigInteger serial, Instant revokedAt, int reason) {
        entries.addCRLEntry(Objects.requireNonNull(serial, "serial"), Date.from(Objects.requireNonNull(revokedAt, "revokedAt")), reason);
        return this;
    }

    /** Revoke a serial as unspecified. */
    public CrlBuilder revoke(BigInteger serial, Instant revokedAt) {
        return revoke(serial, revokedAt, CRLReason.unspecified);
    }

    public X509CRL build() {
        Instant next = nextUpdate != null ? nextUpdate : thisUpdate.plus(Duration.ofDays(30));
        if (!next.isAfter(thisUpdate)) {
            throw new PkiException("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE: nextUpdate must be after thisUpdate");
        }
        entries.setNextUpdate(Date.from(next));
        try {
            entries.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
            entries.addExtension(Extension.cRLNumber, false,
                    new CRLNumber(crlNumber != null ? crlNumber : BigInteger.valueOf(thisUpdate.getEpochSecond())));
        } catch (CertIOException e) {
            throw new PkiException("Cannot add an extension to the CRL", e);
        }
        String algorithm = Certificates.signatureAlgorithm(iacaKeyPair.getPublic());
        return Certificates.crl(entries.build(Certificates.signer(iacaKeyPair.getPrivate(), algorithm)));
    }
}
