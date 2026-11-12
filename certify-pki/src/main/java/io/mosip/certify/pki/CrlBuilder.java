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
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An X.509 v2 certificate revocation list signed by an IACA, for the CRL distribution point of IACA and Document Signer
 * certificates. The CRL carries the IACA authority key identifier, a CRL number, thisUpdate and nextUpdate.
 *
 * <p>Revoked entries carry no entry extensions, so there is no reason code and no invalidity date: the Annex B CRL
 * profile, as the reviewers read it, allows none (decision log, 2026-11-13; to be confirmed against the purchased ISO
 * text). A relying party that needs a reason has to get it out of band.
 *
 * <p>The CRL number is mandatory and the caller's responsibility: RFC 5280 section 5.2.3 makes it a monotonically
 * increasing counter per issuer, and only the operator (or the CLI that publishes the CRL) knows the previous one.
 * {@link #forIaca} will not invent one from the clock, because two CRLs published in the same second would then share
 * a number and a verifier could not tell the newer from the older.
 *
 * <p>The builder refuses what the validator would report: an IACA that fails {@link AnnexBValidator#validateIaca} (one
 * without {@code cRLSign} cannot sign a CRL), a CRL number outside 0..2^159-1, a revocation dated after thisUpdate, a
 * serial revoked twice and a nextUpdate after the IACA expires.
 */
public final class CrlBuilder {

    /** nextUpdate when the caller does not set one: 30 days after thisUpdate, or the IACA's notAfter if sooner. */
    private static final Duration DEFAULT_REFRESH = Duration.ofDays(30);

    private final X509Certificate iaca;
    private final KeyPair iacaKeyPair;
    private final Map<BigInteger, Instant> entries = new LinkedHashMap<>();
    /** thisUpdate as set by the caller; {@code null} means the instant {@link #build} runs. */
    private Instant thisUpdate;
    private Instant nextUpdate;
    private BigInteger crlNumber;

    private CrlBuilder(X509Certificate iaca, KeyPair iacaKeyPair) {
        this.iaca = Objects.requireNonNull(iaca, "iaca");
        this.iacaKeyPair = Objects.requireNonNull(iacaKeyPair, "iacaKeyPair");
        if (!Arrays.equals(iaca.getPublicKey().getEncoded(), iacaKeyPair.getPublic().getEncoded())) {
            throw new PkiException("IACA_KEY_MISMATCH: the IACA signing key does not match the IACA certificate");
        }
        List<AnnexBValidator.Violation> violations = AnnexBValidator.validateIaca(iaca);
        if (!violations.isEmpty()) {
            throw new PkiException("CRL_IACA_INVALID: the IACA does not meet the Annex B profile, so it cannot sign"
                    + " a CRL: " + violations.get(0));
        }
    }

    /** A v2 CRL issued by the given IACA, which must pass {@link AnnexBValidator#validateIaca}. */
    public static CrlBuilder forIaca(X509Certificate iaca, KeyPair iacaKeyPair) {
        return new CrlBuilder(iaca, iacaKeyPair);
    }

    /** thisUpdate, truncated to whole seconds; default the instant {@link #build} runs. */
    public CrlBuilder thisUpdate(Instant thisUpdate) {
        this.thisUpdate = Objects.requireNonNull(thisUpdate, "thisUpdate").truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    /**
     * nextUpdate; it must be later than thisUpdate and no later than the IACA's notAfter. Default 30 days after
     * thisUpdate, or the IACA's notAfter when that is sooner.
     */
    public CrlBuilder nextUpdate(Instant nextUpdate) {
        this.nextUpdate = Objects.requireNonNull(nextUpdate, "nextUpdate").truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    /**
     * The CRL number, mandatory: a non-negative integer of at most 20 DER content octets (at most 2^159 - 1) that must
     * increase with every CRL the IACA publishes. The builder refuses to guess one.
     */
    public CrlBuilder crlNumber(BigInteger crlNumber) {
        this.crlNumber = Objects.requireNonNull(crlNumber, "crlNumber");
        return this;
    }

    /**
     * Revoke a serial from the given instant, truncated to whole seconds. A serial can be revoked once, and not after
     * thisUpdate (or after now, while thisUpdate is left to default to the build instant). There is no reason code:
     * entries carry no extensions.
     */
    public CrlBuilder revoke(BigInteger serial, Instant revokedAt) {
        BigInteger value = Objects.requireNonNull(serial, "serial");
        if (value.signum() <= 0) {
            throw new PkiException("CRL_ENTRY_INVALID: the serial " + value + " is not a positive integer");
        }
        if (entries.containsKey(value)) {
            throw new PkiException("CRL_ENTRY_DUPLICATE: the serial " + value + " is already revoked in this CRL");
        }
        Instant at = Objects.requireNonNull(revokedAt, "revokedAt").truncatedTo(ChronoUnit.SECONDS);
        checkRevocationDate(value, at, thisUpdate != null ? thisUpdate : Instant.now());
        entries.put(value, at);
        return this;
    }

    public X509CRL build() {
        if (crlNumber == null) {
            throw new PkiException("CRL_NUMBER_MISSING: RFC 5280 section 5.2.3 requires a cRLNumber; the caller owns"
                    + " the monotonic counter");
        }
        if (!fitsCrlNumber(crlNumber)) {
            throw new PkiException("CRL_NUMBER_INVALID: the cRLNumber " + crlNumber
                    + " is outside 0..2^159-1 (20 DER content octets)");
        }
        Instant issued = thisUpdate != null ? thisUpdate : Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant iacaNotAfter = iaca.getNotAfter().toInstant();
        if (!issued.isBefore(iacaNotAfter)) {
            throw new PkiException("CRL_IACA_EXPIRED: the IACA expires at " + iacaNotAfter
                    + ", before the CRL's thisUpdate " + issued);
        }
        Instant next;
        if (nextUpdate != null) {
            next = nextUpdate;
            if (next.isAfter(iacaNotAfter)) {
                throw new PkiException("CRL_NEXT_UPDATE_AFTER_IACA: nextUpdate " + next + " is after the IACA expires at "
                        + iacaNotAfter);
            }
        } else {
            Instant refresh = issued.plus(DEFAULT_REFRESH);
            next = refresh.isAfter(iacaNotAfter) ? iacaNotAfter.truncatedTo(ChronoUnit.SECONDS) : refresh;
        }
        if (!next.isAfter(issued)) {
            throw new PkiException("CRL_NEXT_UPDATE_BEFORE_THIS_UPDATE: nextUpdate must be after thisUpdate");
        }
        entries.forEach((serial, revokedAt) -> checkRevocationDate(serial, revokedAt, issued));

        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                X500Name.getInstance(iaca.getSubjectX500Principal().getEncoded()), Date.from(issued));
        builder.setNextUpdate(Date.from(next));
        entries.forEach((serial, revokedAt) -> builder.addCRLEntry(serial, Date.from(revokedAt), (Extensions) null));
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

    /** RFC 5280 section 5.2.3: a non-negative cRLNumber of at most 20 DER content octets, so 0..2^159-1. */
    static boolean fitsCrlNumber(BigInteger number) {
        return number != null && number.signum() >= 0 && Serials.octets(number) <= Serials.MAX_OCTETS;
    }

    private static void checkRevocationDate(BigInteger serial, Instant revokedAt, Instant thisUpdate) {
        if (revokedAt.isAfter(thisUpdate)) {
            throw new PkiException("CRL_ENTRY_DATE_INVALID: the serial " + serial + " is revoked at " + revokedAt
                    + ", after the CRL's thisUpdate " + thisUpdate);
        }
    }
}
