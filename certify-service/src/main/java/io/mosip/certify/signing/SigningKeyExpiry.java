package io.mosip.certify.signing;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Visibility for signing certificates that are about to expire (docs/design/06a-x509-pki-and-mdoc.md; M-05): a WARN
 * for every current key expiring within {@code certify.signing.key-expiry.warn-days} (30) days, and the Micrometer
 * gauge {@code certify.signing.key.expires_in_days{keyRef}} per current key.
 *
 * <p>It lives in {@code certify-service}, not in a key-provider module: the providers publish
 * {@link PublicKeyDescriptor}s and must not depend on Micrometer, and here every provider is covered at once,
 * keymanager included. A Document Signer has an Annex B lifetime of at most 457 days, so a DSC that is not rotated
 * in time turns every mDL it signs into one a verifier rejects; the gauge is what an alert watches.
 *
 * <p><b>When.</b> Nothing is read while beans are created: keymanager provisions its keys in an
 * {@code ApplicationRunner}, and a read before that would see (and briefly cache) an empty key list, so token signing
 * and the JWKS would miss the service key. The first report runs on {@link ApplicationReadyEvent}, which Spring Boot
 * publishes after every runner, and the gauges are then reconciled with the providers every
 * {@code reconcile-interval} (one hour), so a key that appears later (a rotation, a provider that was unavailable at
 * startup) gets its gauge and a key that is gone loses it.
 *
 * <p><b>What.</b> For each alias a provider holds ({@link KeyProvider#keyRefs()}), the current key: the one an
 * unversioned reference resolves to, or, when no version is valid now, the latest-expiring one, so an alias left
 * without a valid key shows a negative number instead of disappearing. Rotated-out versions (an expired keymanager
 * certificate, an older DSC in its rotation window) are not reported: they no longer sign. The tag is the reference
 * that pins the key, {@code provider:alias@version} ({@code keymanager:CERTIFY_SERVICE@<kid>},
 * {@code x509-file:mdl-dsc@2027-02}), which parses as a {@link KeyRef}. A provider that cannot enumerate its aliases is
 * reported key by key, keys valid now only, tagged {@code provider:kid}.
 *
 * <p><b>Values.</b> Days remaining as a fraction, recomputed on every scrape from a strongly held expiry instant (not
 * from a descriptor a provider may replace), negative once expired. A provider whose keys cannot be listed (a key
 * manager that is down) is logged and keeps its previous gauges until it answers again.
 */
public final class SigningKeyExpiry implements ApplicationListener<ApplicationReadyEvent>, AutoCloseable {

    /** The gauge, tagged {@code keyRef=provider:alias@version}. */
    public static final String METRIC = "certify.signing.key.expires_in_days";

    private static final Logger LOG = LoggerFactory.getLogger(SigningKeyExpiry.class);

    /** One reported key: which provider it belongs to, the pinned reference, and its expiry. */
    record ReportedKey(String providerId, String keyRef, Instant notAfter) {}

    /** The strongly held state behind one gauge; Micrometer's own reference to it may be weak. */
    private static final class Tracked {
        final String providerId;
        volatile Instant notAfter;
        Gauge gauge;

        Tracked(String providerId, Instant notAfter) {
            this.providerId = providerId;
            this.notAfter = notAfter;
        }
    }

    private final List<KeyProvider> providers;
    private final MeterRegistry registry;
    private final SigningKeyExpiryProperties properties;
    private final Clock clock;
    private final Map<String, Tracked> tracked = new ConcurrentHashMap<>();
    private final Set<String> warned = ConcurrentHashMap.newKeySet();
    private ScheduledExecutorService scheduler;

    public SigningKeyExpiry(List<KeyProvider> providers, MeterRegistry registry, SigningKeyExpiryProperties properties) {
        this(providers, registry, properties, Clock.systemUTC());
    }

    SigningKeyExpiry(List<KeyProvider> providers, MeterRegistry registry, SigningKeyExpiryProperties properties,
                     Clock clock) {
        this.providers = List.copyOf(providers);
        this.registry = registry;
        this.properties = properties == null ? SigningKeyExpiryProperties.DEFAULTS : properties;
        this.clock = clock;
    }

    /** The first report, after every key has been provisioned; then the periodic reconciliation. */
    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        reconcile();
        start();
    }

    synchronized void start() {
        Duration interval = properties.reconcileInterval();
        if (scheduler != null || interval == null || interval.isZero() || interval.isNegative()) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "certify-signing-key-expiry");
            thread.setDaemon(true);
            return thread;
        });
        long millis = interval.toMillis();
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                reconcile();
            } catch (RuntimeException e) {
                LOG.warn("Signing key expiry reconciliation failed; retrying in {}", interval, e);
            }
        }, millis, millis, TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    /**
     * Reads every provider once and brings the gauges in line: registers the keys that are new, updates the expiry of
     * the ones that stay, removes the ones that are gone (only for providers that answered), and logs a WARN once for
     * each current key that enters the warning window. Returns the key references inside the window.
     */
    public synchronized List<String> reconcile() {
        Set<String> answered = new HashSet<>();
        List<ReportedKey> current = new ArrayList<>();
        for (KeyProvider provider : providers) {
            try {
                current.addAll(currentKeys(provider));
                answered.add(provider.id());
            } catch (RuntimeException e) {
                LOG.warn("Cannot list the keys of provider {} for expiry reporting; keeping its previous gauges: {}",
                        provider.id(), e.toString());
            }
        }
        Set<String> seen = new HashSet<>();
        for (ReportedKey key : current) {
            seen.add(key.keyRef());
            Tracked state = tracked.computeIfAbsent(key.keyRef(), ref -> register(key));
            state.notAfter = key.notAfter();
        }
        tracked.entrySet().removeIf(entry -> {
            boolean gone = answered.contains(entry.getValue().providerId) && !seen.contains(entry.getKey());
            if (gone && registry != null && entry.getValue().gauge != null) {
                registry.remove(entry.getValue().gauge);
            }
            return gone;
        });
        return warn(current);
    }

    /** The key references with a gauge, for tests and diagnostics. */
    Set<String> gauged() {
        return Set.copyOf(tracked.keySet());
    }

    private List<String> warn(List<ReportedKey> current) {
        Instant now = clock.instant();
        Duration window = Duration.ofDays(properties.warnDays());
        List<String> expiring = new ArrayList<>();
        Set<String> inWindow = new HashSet<>();
        for (ReportedKey key : current) {
            Duration left = Duration.between(now, key.notAfter());
            if (left.compareTo(window) > 0) {
                continue;
            }
            expiring.add(key.keyRef());
            inWindow.add(key.keyRef());
            if (!warned.add(key.keyRef())) {
                continue; // warned already; the gauge keeps counting down
            }
            if (left.isNegative() || left.isZero()) {
                LOG.warn("Signing key {} expired at {} and no valid version of its alias replaces it; rotate it now",
                        key.keyRef(), key.notAfter());
            } else {
                LOG.warn("Signing key {} expires at {} ({} days left); rotate it before it does",
                        key.keyRef(), key.notAfter(), left.toDays());
            }
        }
        warned.retainAll(inWindow);
        return expiring;
    }

    private Tracked register(ReportedKey key) {
        Tracked state = new Tracked(key.providerId(), key.notAfter());
        if (registry != null) {
            state.gauge = Gauge.builder(METRIC, state, s -> daysUntil(s.notAfter))
                    .tag("keyRef", key.keyRef())
                    .description("Days until the current signing certificate of a key expires; negative once expired")
                    .baseUnit("days")
                    .strongReference(true)
                    .register(registry);
        }
        return state;
    }

    /** The current key of each alias of the provider, or its keys valid now when it cannot list aliases. */
    private List<ReportedKey> currentKeys(KeyProvider provider) {
        List<ReportedKey> out = new ArrayList<>();
        List<KeyRef> aliases = provider.keyRefs();
        if (aliases.isEmpty()) {
            Instant now = clock.instant();
            for (PublicKeyDescriptor descriptor : provider.publicKeys(KeyFilter.ALL)) {
                if (descriptor.notAfter() != null && descriptor.isValidAt(now)) {
                    out.add(new ReportedKey(provider.id(), provider.id() + ":" + descriptor.kid(), descriptor.notAfter()));
                }
            }
            return out;
        }
        Map<String, ReportedKey> byRef = new LinkedHashMap<>();
        for (KeyRef alias : aliases) {
            currentOf(provider, alias)
                    .filter(descriptor -> descriptor.notAfter() != null)
                    .ifPresent(descriptor -> byRef.putIfAbsent(pinned(alias, descriptor),
                            new ReportedKey(provider.id(), pinned(alias, descriptor), descriptor.notAfter())));
        }
        out.addAll(byRef.values());
        return out;
    }

    /** What an unversioned reference resolves to; the latest-expiring version when none is valid now. */
    private Optional<PublicKeyDescriptor> currentOf(KeyProvider provider, KeyRef alias) {
        List<PublicKeyDescriptor> versions = provider.publicKeys(alias);
        if (versions == null || versions.isEmpty()) {
            return Optional.empty();
        }
        try {
            String kid = provider.resolve(alias).descriptor().kid();
            Optional<PublicKeyDescriptor> resolved = versions.stream().filter(d -> d.kid().equals(kid)).findFirst();
            if (resolved.isPresent()) {
                return resolved;
            }
        } catch (RuntimeException e) {
            // no version is valid now: report the one that expired last, so the alias shows a negative number
        }
        return versions.stream()
                .filter(d -> d.notAfter() != null)
                .max(Comparator.comparing(PublicKeyDescriptor::notAfter));
    }

    /**
     * The reference that names exactly this key: {@code provider:kid} when the provider's kid is already the alias or
     * {@code alias@version} (x509-file, jca), else {@code provider:alias@kid} (keymanager pins a certificate by kid).
     */
    static String pinned(KeyRef alias, PublicKeyDescriptor descriptor) {
        String kid = descriptor.kid();
        if (kid.equals(alias.alias()) || kid.startsWith(alias.alias() + "@")) {
            return alias.provider() + ":" + kid;
        }
        return new KeyRef(alias.provider(), alias.alias(), kid).toString();
    }

    private double daysUntil(Instant notAfter) {
        return Duration.between(clock.instant(), notAfter).toMillis() / (double) Duration.ofDays(1).toMillis();
    }
}
