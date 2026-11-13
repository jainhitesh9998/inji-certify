package io.mosip.certify.status;

import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pins a CWT status list to the signer that signed it, and resolves that signer again when the list is re-signed
 * (docs/design/wp/M-11-status-list-under-iaca.md sections 4.3 and 4.4).
 *
 * <p>A list is created for exactly one signer: the token's protected {@code x5chain} is the only statement of who
 * signed it (TSL section 11.3), and Credo accepts a list for an mDL only when the list's validated chain equals the
 * mDL's issuance chain. So the stored envelope records two things: the key reference to sign with, and the SHA-256 of
 * the leaf certificate. The reference is version-pinned where the provider keeps versions — an {@code x509-file} or
 * {@code jca} alias is {@code mdl-dsc}, but its key's {@code kid} is the entry's full alias {@code mdl-dsc@2026-11} —
 * and is the configured reference where it does not (keymanager rotates under one reference). {@link #resolve} then
 * refuses a signer whose certificate changed: a persisted index belongs to the certificate that allocated it.
 */
public class StatusListSigners {

    private static final Logger log = LoggerFactory.getLogger(StatusListSigners.class);

    /** The refusal for a pinned reference whose certificate is no longer the pinned one. */
    public static final String GONE = "STATUS_SIGNER_GONE";

    private final KeyProviderRegistry keyProviders;
    private final Clock clock;

    public StatusListSigners(KeyProviderRegistry keyProviders) {
        this(keyProviders, Clock.systemUTC());
    }

    /** As the bean, with the clock that decides whether the pinned signer is past its {@code notAfter} (tests). */
    public StatusListSigners(KeyProviderRegistry keyProviders, Clock clock) {
        this.keyProviders = Objects.requireNonNull(keyProviders, "keyProviders");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The signer a list is bound to: the key reference to re-sign with, and the base64url SHA-256 of the leaf
     * certificate that signs it (the envelope's {@code signer.x5tS256}, section 4.4).
     */
    public record Pinned(KeyRef keyRef, String x5tS256) {

        public Pinned {
            Objects.requireNonNull(keyRef, "keyRef");
            if (x5tS256 == null || x5tS256.isBlank()) {
                throw new IllegalArgumentException("Pinned needs the SHA-256 of the signer's leaf certificate");
            }
        }
    }

    /**
     * Pins the signer of a status list, from the {@link SigningContext} that signs it (or that signed the mDLs it
     * indexes).
     *
     * <p>The reference is the signing context's own configured reference, version-pinned when the provider reports a
     * versioned {@code kid} for it: the {@code kid} of an {@code x509-file}/{@code jca} key is its full alias
     * ({@code alias@version}), so a rotation leaves the list on the version that allocated its indices. A provider that
     * rotates inside one reference (keymanager) keeps the configured reference. The pinned reference is resolved once
     * to confirm it still names a certificate with the same SHA-256; when it does not, the configured reference is kept
     * and the mismatch logged at DEBUG, so a list is never pinned to a key that cannot re-sign it.
     *
     * @throws IllegalStateException {@code STATUS_SIGNER_NO_CHAIN} when the signing key has no certificate: without one
     *                               a list has no signer to pin and no verification path
     */
    public Pinned pin(SigningContext signing) {
        Objects.requireNonNull(signing, "signing");
        X509Certificate leaf = leaf(signing.key());
        String x5tS256 = x5tS256(leaf);
        KeyRef configured = signing.config().keyRef();
        KeyRef pinned = versionedRef(configured, signing.key().kid());
        if (!pinned.equals(configured)) {
            try {
                X509Certificate resolvedLeaf = leaf(keyProviders.provider(pinned.provider()).resolve(pinned));
                if (!x5tS256.equals(x5tS256(resolvedLeaf))) {
                    log.debug("Status list signer {} resolves to {} (SHA-256 {}), not the signing certificate {} (SHA-256 {});"
                                    + " keeping the configured reference {}", pinned, resolvedLeaf.getSubjectX500Principal(),
                            x5tS256(resolvedLeaf), leaf.getSubjectX500Principal(), x5tS256, configured);
                    pinned = configured;
                }
            } catch (RuntimeException e) {
                log.debug("Status list signer {} could not be resolved ({}); keeping the configured reference {}",
                        pinned, e.getMessage(), configured);
                pinned = configured;
            }
        }
        return new Pinned(pinned, x5tS256);
    }

    /**
     * The signing context that re-signs a list pinned by {@link #pin}, with the key's own algorithm (the one its
     * certificate describes, not whatever the current configuration says): moving a list to another algorithm or
     * certificate would change who signed it.
     *
     * @throws IllegalStateException    {@code STATUS_SIGNER_GONE} when the pinned reference now names another
     *                                  certificate (a keymanager key rotated under the same reference), and
     *                                  {@code STATUS_SIGNER_NO_CHAIN} when it names none
     * @throws StatusListRetiredException when the pinned certificate is past its {@code notAfter}: the list is not
     *                                  signed again (D-M11-7)
     */
    public SigningContext resolve(Pinned pinned) {
        Objects.requireNonNull(pinned, "pinned");
        KeyProvider provider = keyProviders.provider(pinned.keyRef().provider());
        SigningKey key = provider.resolve(pinned.keyRef());
        X509Certificate leaf = leaf(key);
        String x5tS256 = x5tS256(leaf);
        if (!x5tS256.equals(pinned.x5tS256())) {
            throw new IllegalStateException(GONE + ": the pinned signer " + pinned.keyRef() + " now holds "
                    + leaf.getSubjectX500Principal() + " (SHA-256 " + x5tS256 + "), not the certificate the list was"
                    + " allocated against (SHA-256 " + pinned.x5tS256() + "); a status list is re-signed only by the"
                    + " signer whose certificates the mDLs on it carry (docs/design/wp/M-11-status-list-under-iaca.md"
                    + " section 4.3)");
        }
        Instant notAfter = leaf.getNotAfter().toInstant();
        if (clock.instant().isAfter(notAfter)) {
            throw new StatusListRetiredException("the pinned status list signer " + pinned.keyRef() + " ("
                    + leaf.getSubjectX500Principal() + ") expired at " + notAfter
                    + ", so the list is retired rather than signed again; every mDL that indexed it has expired too"
                    + " (D-M11-7)");
        }
        return new SigningContext(SigningConfig.of(pinned.keyRef(), key.algorithm()), key, provider);
    }

    /** The base64url, unpadded SHA-256 of a certificate's DER: the envelope's {@code signer.x5tS256}. */
    public static String x5tS256(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        try {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Cannot hash the status list signer certificate", e);
        }
    }

    /** The leaf certificate of a resolved key, refused when the provider reported none. */
    private static X509Certificate leaf(SigningKey key) {
        CertificateChain chain = key.chain();
        if (chain == null || chain.isEmpty() || chain.leaf().isEmpty()) {
            throw new IllegalStateException(StatusListSignerPolicy.NO_CHAIN + ": the key " + key.ref()
                    + " has no certificate, so a status list cannot be pinned to it or re-signed by it; a Status List"
                    + " Token names its signer in the protected x5chain (TSL section 11.3, ISO/IEC 18013-5 second"
                    + " edition 12.3.6.3)");
        }
        return chain.leaf().orElseThrow();
    }

    /**
     * The configured reference, version-pinned when the provider's {@code kid} is the alias or a version of it (the
     * {@code x509-file}/{@code jca} family: {@code mdl-dsc@2026-11}); otherwise the configured reference itself.
     */
    private static KeyRef versionedRef(KeyRef configured, String kid) {
        if (kid == null) {
            return configured;
        }
        String alias = configured.alias();
        if (kid.equals(alias) || kid.startsWith(alias + "@")) {
            return KeyRef.parse(configured.provider() + ":" + kid);
        }
        return configured;
    }
}
