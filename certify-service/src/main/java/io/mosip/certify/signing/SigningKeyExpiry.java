package io.mosip.certify.signing;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Visibility for signing certificates that are about to expire (docs/design/06a-x509-pki-and-mdoc.md; M-05 item 5):
 * one startup WARN for every published certificate expiring within {@value #WARN_DAYS} days, and the Micrometer gauge
 * {@code certify.signing.key.expires_in_days{keyRef}} with the same number per key.
 *
 * <p>It lives in {@code certify-service}, not in a key-provider module: the providers publish
 * {@link PublicKeyDescriptor}s and must not depend on Micrometer, and here every provider is covered at once,
 * keymanager included. A Document Signer has an Annex B lifetime of at most 457 days, so a DSC that is not rotated
 * in time turns every mDL it signs into one a verifier rejects; the gauge is what an alert watches.
 *
 * <p>Gauge values are days remaining, recomputed on every scrape and negative once the certificate has expired. A
 * provider whose keys cannot be listed (a key manager that is down) is logged and skipped: expiry reporting must never
 * stop the application from starting.
 */
public final class SigningKeyExpiry {

    /** The gauge, tagged {@code keyRef=provider:alias} (or the provider's own kid). */
    public static final String METRIC = "certify.signing.key.expires_in_days";

    /** Certificates expiring within this many days produce a startup warning. */
    public static final int WARN_DAYS = 30;

    private static final Logger LOG = LoggerFactory.getLogger(SigningKeyExpiry.class);

    private final List<KeyProvider> providers;
    private final Clock clock;

    public SigningKeyExpiry(List<KeyProvider> providers) {
        this(providers, Clock.systemUTC());
    }

    SigningKeyExpiry(List<KeyProvider> providers, Clock clock) {
        this.providers = List.copyOf(providers);
        this.clock = clock;
    }

    /** One gauge per published certificate that has an expiry. */
    public void register(MeterRegistry registry) {
        for (Map.Entry<String, PublicKeyDescriptor> published : published()) {
            PublicKeyDescriptor descriptor = published.getValue();
            if (descriptor.notAfter() == null) {
                continue;
            }
            registry.gauge(METRIC, Tags.of("keyRef", published.getKey()), descriptor,
                    d -> daysUntil(d.notAfter()));
        }
    }

    /** Logs one WARN per certificate expiring within {@link #WARN_DAYS} days and returns their key references. */
    public List<String> warnExpiringSoon() {
        List<String> expiring = new ArrayList<>();
        Instant now = clock.instant();
        for (Map.Entry<String, PublicKeyDescriptor> published : published()) {
            Instant notAfter = published.getValue().notAfter();
            if (notAfter == null) {
                continue;
            }
            Duration left = Duration.between(now, notAfter);
            if (left.compareTo(Duration.ofDays(WARN_DAYS)) <= 0) {
                expiring.add(published.getKey());
                LOG.warn("Signing key {} expires at {} ({} days left); rotate it before it does",
                        published.getKey(), notAfter, left.toDays());
            }
        }
        return expiring;
    }

    private List<Map.Entry<String, PublicKeyDescriptor>> published() {
        List<Map.Entry<String, PublicKeyDescriptor>> out = new ArrayList<>();
        for (KeyProvider provider : providers) {
            try {
                for (PublicKeyDescriptor descriptor : provider.publicKeys(KeyFilter.ALL)) {
                    out.add(new AbstractMap.SimpleImmutableEntry<>(provider.id() + ":" + descriptor.kid(), descriptor));
                }
            } catch (RuntimeException e) {
                LOG.warn("Cannot list the keys of provider {} for expiry reporting: {}", provider.id(), e.toString());
            }
        }
        return out;
    }

    private double daysUntil(Instant notAfter) {
        return Duration.between(clock.instant(), notAfter).toMillis() / (double) Duration.ofDays(1).toMillis();
    }
}
