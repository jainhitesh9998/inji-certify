package io.mosip.certify.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * An X.509 v2 certificate revocation list signed by an IACA, as ISO/IEC 18013-5:2021 Annex B refers to from the CRL
 * distribution point of IACA and Document Signer certificates. The CRL carries the IACA authority key identifier, a CRL
 * number, thisUpdate and nextUpdate.
 *
 * <p>Revoked entries carry no entry extensions: Annex B Table B.9 prohibits them, so there is no reason code and no
 * invalidity date. A relying party that needs a reason has to get it out of band.
 *
 * <p>The CRL number is mandatory and the caller's responsibility: RFC 5280 section 5.2.3 makes it a monotonically
 * increasing counter per issuer, and only the operator (or the CLI that publishes the CRL) knows the previous one.
 * {@link #forIaca} will not invent one from the clock, because two CRLs published in the same second would then share
 * a number and a verifier could not tell the newer from the older.
 */
public final class CrlBuilder {

    /** RFC 5280 section 5.2.3: the CRL number is a non-negative integer of at most 20 octets. */
    private static final BigInteger MAX_CRL_NUMBER = BigInteger.ONE.shiftLeft(159);

    /** nextUpdate when the caller does not set one: 30 days after thisUpdate. */
    private static final Duration DEFAULT_REFRESH = Duration.ofDays(30);

    private final X509Certificate iaca;
    private final KeyPair iacaKeyPair;
    private final List<Entry> entries = new ArrayList<>();
    private Instant thisUpdate = Instant.now();
    private Instant nextUpdate;
    private BigInteger crlNumber;

    private record Entry(BigInteger serial, Instant revokedAt) {}

    private CrlBuilder(X509Certificate iaca, KeyPair iacaKeyPair, Instant thisUpdate) {
        this.iaca = Objects.requireNonNull(iaca, "iaca");
        this.iacaKeyPair = Objects.requireNonNull(iacaKeyPair, "iacaKeyPair");
        if (!Arrays.equals(iaca.getPublicKey().getEncoded(), iacaKeyPair.getPublic().getEncoded())) {
            throw new PkiException("IACA_KEY_MISMATCH: the IACA signing key does not match the IACA certificate");
        }
        this.thisUpdate = Objects.requireNonNull(thisUpdate, "thisUpdate").truncatedTo(ChronoUnit.SECONDS);
    }

    /** A v2 CRL issued by the given IACA; {@code thisUpdate} defaults to now. */
    public static CrlBuilder forIaca(X509Certificate iaca, KeyPair iacaKeyPair) {
        return new CrlBuilder(iaca, iacaKeyPair, Instant.now());
    }

    public CrlBuilder thisUpdate(Instant thisUpdate) {
        this.thisUpdate = Objects.requireNonNull(thisUpdate, "thisUpdate").truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    /** nextUpdate, default 30 days after thisUpdate; it must be later than thisUpdate. */
    public CrlBuilder nextUpdate(Instant nextUpdate) {
        this.nextUpdate = Objects.requireNonNull(nextUpdate, "nextUpdate").truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    /**
     * The CRL number, mandatory: a non-negative integer of at most 20 octets that must increase with every CRL the IACA
     * publishes. The builder refuses to guess one.
     */
    public CrlBuilder crlNumber(BigInteger crlNumber) {
        this.crlNumber = Objects.requireNonNull(crlNumber, "crlNumber");
        return this;
    }

    /** Revoke a serial from the given instant. Annex B Table B.9 allows no entry extensions, so there is no reason. */
    public CrlBuilder revoke(BigInteger serial, Instant revokedAt) {
        BigInteger value = Objects.requireNonNull(serial, "serial");
        if (value.signum() <= 0) {
            throw new PkiException("CRL_ENTRY_INVALID: the serial " + value + " is not a positive integer");
        }
        entries.add(new Entry(value, Objects.requireNonNull(revokedAt, "revokedAt").truncatedTo(ChronoUnit.SECONDS)));
        return this;
    }

    public X509CRL build() {
        if (crlNumber == null) {
            throw new PkiException("CRL_NUMBER_MISSING: RFC 5280 section 5.2.3 requires a cRLNumber; the caller owns"
                    + " the monotonic counter");
        }
        if (crlNumber.signum() < 0 || crlNumber.compareTo(MAX_CRL_NUMBER) > 0) {
            throw new PkiException("CRL_NUMBER_INVALID: the cRLNumber " + crlNumber + " is outside 0..2^159");
        }
        Instant next = nextUpdate != null ? nextUpdate : thisUpdate.plus(DEFAULT_REFRESH);
        if (!next.isAfter(thisUpdate)) {
            throw new PkiException("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE: nextUpdate must be after thisUpdate");
        }
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(next));
        for (Entry entry : entries) {
            builder.addCRLEntry(entry.serial(), Date.from(entry.revokedAt()), (Extensions) null);
        }
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(Certificates.keyIdentifier(iaca)));
            builder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
        } catch (CertIOException e) {
            throw new PkiException("Cannot add an extension to the CRL", e);
        }
        String algorithm = Certificates.signatureAlgorithm(iacaKeyPair.getPublic(), "IACA");
        return Certificates.crl(builder.build(Certificates.signer(iacaKeyPair.getPrivate(), algorithm)));
    }
}
