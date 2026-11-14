package io.mosip.certify.status;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Token Status List (draft-ietf-oauth-status-list) settings: the key that signs every <b>JWT</b> list ({@code key-ref}
 * as {@code provider:alias}, e.g. {@code x509-file:sdjwt-es256}; keymanager's EC key when absent), its JOSE algorithm,
 * how much of its chain the list's {@code x5c} carries, the list size in bits, and how long a fetched list may be
 * cached ({@code ttl}).
 *
 * <p>Re-signing a stale list when it is served ({@link TokenStatusListService#jwt}): {@code renew-wait} is how long a
 * request for an expired list (or one under another URI) waits for the request that is signing it again before it is
 * answered 503, so a stalled signer (HSM, keymanager) holds one thread per list rather than every request thread;
 * {@code renew-backoff} is how long after a failed re-sign the list is not signed again: the stored list is served
 * while it is still valid, 503 otherwise.
 *
 * <p>{@code mdoc} decides what an {@code mso_mdoc} entry points at ({@link #mdoc()}, section 4.6 of
 * docs/design/wp/M-11-status-list-under-iaca.md): a CWT list signed by the Document Signer that signed the mDLs on it
 * (the default, ISO/IEC 18013-5 second edition 12.3.6.3 and D-M11-3), or today's shared JWT list with
 * {@code token-format=jwt} (D-M11-3's escape hatch). {@code size-bits}, {@code ttl} and the renewal settings apply to
 * both forms; {@code key-ref} signs JWT lists only.
 *
 * <p>{@code batch} is how the status-list batch job holds back a CWT list it cannot update ({@link #batch()}): a
 * transient failure is retried with a bounded back-off, a permanent refusal is quarantined for a while; either way the
 * list's transactions stay pending, in order, and other lists are not held up.
 */
@ConfigurationProperties(prefix = "certify.status.token-status-list")
public record TokenStatusListProperties(String keyRef, @DefaultValue("ES256") String alg, @DefaultValue("without-anchor") String x5c,
                                        @DefaultValue("131072") int sizeBits, @DefaultValue("PT1H") Duration ttl,
                                        @DefaultValue("PT5S") Duration renewWait, @DefaultValue("PT30S") Duration renewBackoff,
                                        @DefaultValue Mdoc mdoc, @DefaultValue Batch batch) {

    @ConstructorBinding
    public TokenStatusListProperties {
        batch = batch == null ? new Batch(null, null, null) : batch;
        renewWait = renewWait == null || renewWait.isNegative() ? Duration.ofSeconds(5) : renewWait;
        renewBackoff = renewBackoff == null || renewBackoff.isNegative() ? Duration.ofSeconds(30) : renewBackoff;
        mdoc = mdoc == null ? new Mdoc(null, null, null) : mdoc;
        if (sizeBits < 8 || sizeBits % 8 != 0 || sizeBits > TokenStatusListCwt.MAX_BITS) {
            // a list whose bit array is not a whole number of bytes, or larger than the codec's own ceiling, cannot be
            // stored and read back consistently (review round 1, nit 8)
            throw new IllegalArgumentException("certify.status.token-status-list.size-bits must be a positive multiple of"
                    + " 8 and at most " + TokenStatusListCwt.MAX_BITS + ", got " + sizeBits);
        }
    }

    /** The shape before {@code batch}: the batch job's default back-off and quarantine. */
    public TokenStatusListProperties(String keyRef, String alg, String x5c, int sizeBits, Duration ttl, Duration renewWait,
                                     Duration renewBackoff, Mdoc mdoc) {
        this(keyRef, alg, x5c, sizeBits, ttl, renewWait, renewBackoff, mdoc, null);
    }

    /**
     * How the status-list batch job holds back a CWT list whose update failed (M-11d review round 2). Holding a list back
     * never drops or reorders its transactions: they stay pending, the list is excluded from the job's selection while it
     * is held, and once it is retried its transactions are applied oldest first.
     *
     * @param retryBackoff    after a transient failure (the key provider or HSM unavailable, a stale IACA CRL, a signer
     *                        not yet valid) the list is retried on the next run; after each further consecutive failure it
     *                        waits this long, doubled every time, up to {@code retry-backoff-max}
     * @param retryBackoffMax the longest wait between two attempts on a list that keeps failing transiently
     * @param quarantine      after a permanent refusal (a revoked or rotated-away Document Signer, a signer the IACA did
     *                        not issue, a stored token its pinned signer did not sign) the list is retried after this long,
     *                        or sooner when the IACA trust material (an anchor or its CRL) changes, so an operator's fix is
     *                        picked up without a restart
     */
    public record Batch(@DefaultValue("PT1M") Duration retryBackoff, @DefaultValue("PT15M") Duration retryBackoffMax,
                        @DefaultValue("PT1H") Duration quarantine) {

        public Batch {
            retryBackoff = retryBackoff == null ? Duration.ofMinutes(1) : retryBackoff;
            retryBackoffMax = retryBackoffMax == null ? Duration.ofMinutes(15) : retryBackoffMax;
            quarantine = quarantine == null ? Duration.ofHours(1) : quarantine;
            if (retryBackoff.isNegative() || retryBackoff.isZero()) {
                throw new IllegalArgumentException("certify.status.token-status-list.batch.retry-backoff must be positive,"
                        + " got " + retryBackoff);
            }
            if (retryBackoffMax.compareTo(retryBackoff) < 0) {
                throw new IllegalArgumentException("certify.status.token-status-list.batch.retry-backoff-max must be at"
                        + " least retry-backoff (" + retryBackoff + "), got " + retryBackoffMax);
            }
            if (quarantine.isNegative() || quarantine.isZero()) {
                throw new IllegalArgumentException("certify.status.token-status-list.batch.quarantine must be positive,"
                        + " got " + quarantine);
            }
        }
    }

    /**
     * What an {@code mso_mdoc} entry points at (section 4.6).
     *
     * @param tokenFormat {@code cwt} (default): an mDoc entry goes to a CWT list, which ISO/IEC 18013-5 second edition
     *                    12.3.6.3 requires and every wallet that verifies an mDoc's status reads; {@code jwt}: today's
     *                    shared JWT list signed by {@code key-ref}, kept as the escape hatch (D-M11-3)
     * @param signer       {@code document-signer} (default): the Document Signer that signed the mDLs on a list signs
     *                    the list (D-M11-1 (a), TSL section 11.3); {@code dedicated} is refused until M-11h builds it
     * @param keyRef       the {@code provider:alias} of a dedicated status signer; only meaningful with
     *                    {@code signer=dedicated}, and refused without it so a deployment cannot believe it changed
     *                    who signs while the Document Signer still does
     */
    public record Mdoc(@DefaultValue("cwt") String tokenFormat, @DefaultValue("document-signer") String signer, String keyRef) {

        /** CWT Status List Tokens for {@code mso_mdoc} (ISO/IEC 18013-5 second edition 12.3.6.3; D-M11-3). */
        public static final String FORMAT_CWT = "cwt";
        /** Today's shared JWT lists for {@code mso_mdoc}, byte for byte (D-M11-3's escape hatch). */
        public static final String FORMAT_JWT = "jwt";
        /** The Document Signer that signed the mDLs on a list signs the list (D-M11-1 (a)). */
        public static final String SIGNER_DOCUMENT = "document-signer";
        /** A signer the IACA issued for status-list signing only (D-M11-1 (b); M-11h). */
        public static final String SIGNER_DEDICATED = "dedicated";

        public Mdoc {
            tokenFormat = tokenFormat == null || tokenFormat.isBlank() ? FORMAT_CWT : tokenFormat;
            signer = signer == null || signer.isBlank() ? SIGNER_DOCUMENT : signer;
            keyRef = keyRef == null || keyRef.isBlank() ? null : keyRef;
            if (!FORMAT_CWT.equals(tokenFormat) && !FORMAT_JWT.equals(tokenFormat)) {
                throw new IllegalArgumentException("certify.status.token-status-list.mdoc.token-format must be '"
                        + FORMAT_CWT + "' or '" + FORMAT_JWT + "', got '" + tokenFormat + "'");
            }
            if (!SIGNER_DOCUMENT.equals(signer) && !SIGNER_DEDICATED.equals(signer)) {
                throw new IllegalArgumentException("certify.status.token-status-list.mdoc.signer must be '"
                        + SIGNER_DOCUMENT + "' or '" + SIGNER_DEDICATED + "', got '" + signer + "'");
            }
            if (SIGNER_DEDICATED.equals(signer)) {
                throw new IllegalArgumentException("certify.status.token-status-list.mdoc.signer=dedicated is available"
                        + " from M-11h; this build signs mDoc status lists with the Document Signer that signed the"
                        + " mDLs on them (certify.status.token-status-list.mdoc.signer=document-signer, D-M11-1)");
            }
            if (keyRef != null) {
                throw new IllegalArgumentException("certify.status.token-status-list.mdoc.key-ref names the dedicated"
                        + " status signer and is refused without certify.status.token-status-list.mdoc.signer=dedicated"
                        + " (M-11h); JWT lists are signed by certify.status.token-status-list.key-ref");
            }
        }
    }
}
