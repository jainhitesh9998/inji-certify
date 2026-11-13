package io.mosip.certify.trust;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.TrustAnchorRegistry;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code mdoc-iaca} trust anchors of {@code certify.pki.trust-anchors} plus the IACAs the x509-file provider holds
 * (docs/design/20-mdl-issuer.md M-06), each with its CRL. Every certificate passes
 * {@link AnnexBValidator#validateIaca} and every CRL {@link AnnexBValidator#validateCrl} before the application starts,
 * or the application refuses to start: an anchor the DSC policy would trust must be one a verifier can trust.
 *
 * <p>An anchor's id names its downloads ({@code /mdoc/iaca/<id>.crl}): the configured {@code id}, else the
 * {@code <id>} of the IACA's own CRL distribution point when that point is {@code …/mdoc/iaca/<id>.crl} (so the URL an
 * IACA advertises is the one this issuer serves), else its subject key identifier in lower-case hex. An IACA whose CRL
 * distribution point is {@code …/mdoc/iaca/<x>.crl} with an {@code <x>} that is not a valid id, or not its anchor id,
 * refuses startup: verifiers would get a 404 at the advertised URL.
 *
 * <p>CRLs are refreshed every {@code crl-refresh-interval}: a configured file is re-read when its modification time or
 * size changed and replaces the current CRL only when it validates and moves forward (a larger cRLNumber, a thisUpdate
 * no earlier; a broken or older file is logged and the current CRL kept, since an older list could un-revoke a DSC);
 * for an IACA whose private key the x509-file provider holds in dev mode, an empty CRL is issued at startup and
 * re-issued once half its validity has passed, numbered after the last number recorded in a {@link CrlNumberStore}.
 * Every tick, unchanged files included, logs a CRL past its nextUpdate: WARN within {@code certify.pki.stale-crl-grace}
 * (signing continues), ERROR past it (the DSC policy refuses {@code CRL_STALE}); at startup too, where a CRL past the
 * grace is logged at ERROR and the service starts, since only mDoc signing under that IACA is affected and the policy
 * already fails closed for it (decision log 2026-11-13). The gauge {@value #METRIC}{@code {anchor}} counts down to each CRL's
 * nextUpdate, negative once it has passed.
 */
@Slf4j
public class FileTrustAnchorRegistry implements TrustAnchorRegistry, AutoCloseable {

    /**
     * Seconds until the anchor's current CRL reaches its nextUpdate; negative once it has. Tagged {@code anchor}, base
     * unit seconds, so Prometheus exports it as {@code certify_pki_crl_next_update_seconds{anchor}}.
     */
    public static final String METRIC = "certify.pki.crl.next_update";

    /** Issues an empty CRL for an IACA whose key the caller holds; empty when it holds none (production). */
    @FunctionalInterface
    public interface DevCrlIssuer {
        DevCrlIssuer NONE = (iaca, number, thisUpdate, nextUpdate) -> Optional.empty();

        Optional<X509CRL> issue(X509Certificate iaca, BigInteger crlNumber, Instant thisUpdate, Instant nextUpdate);
    }

    private static final Pattern PUBLISHED_CRL = Pattern.compile(".*/mdoc/iaca/([^/]+)\\.crl$");

    private final List<Anchor> anchors;
    private final Map<String, Path> crlFiles;
    private final Map<String, CrlState> crls = new ConcurrentHashMap<>();
    private final DevCrlIssuer devCrls;
    private final CrlNumberStore crlNumbers;
    private final Duration devCrlValidity;
    private final Duration staleCrlGrace;
    private final Clock clock;
    /** The state behind each gauge, held here because Micrometer may hold it weakly (as {@code SigningKeyExpiry}). */
    private final Map<String, CrlGauge> gauges = new ConcurrentHashMap<>();
    private volatile MeterRegistry meters;
    private ScheduledExecutorService scheduler;

    /** What is current for one anchor: the CRL and, for a file, what the file looked like when it was read. */
    private record CrlState(X509CRL crl, FileTime modified, long size, boolean dev) {}

    private static final class CrlGauge {
        volatile Instant nextUpdate;
    }

    /** A registry whose dev-mode CRL numbers live in memory only (tests). */
    public FileTrustAnchorRegistry(PkiProperties properties, List<X509Certificate> providerIacas, DevCrlIssuer devCrls, Clock clock) {
        this(properties, providerIacas, devCrls, CrlNumberStore.inMemory(), clock);
    }

    /**
     * @param properties    {@code certify.pki}
     * @param providerIacas the IACAs of the x509-file provider ({@code X509FileKeyProviders.iacaCertificates}), empty when
     *                      it is not enabled
     * @param devCrls       issues dev-mode CRLs for IACAs whose key is held in the application
     * @param crlNumbers    the last cRLNumber issued per IACA in dev mode, so a restart never reuses or lowers one
     */
    public FileTrustAnchorRegistry(PkiProperties properties, List<X509Certificate> providerIacas, DevCrlIssuer devCrls,
                                   CrlNumberStore crlNumbers, Clock clock) {
        this.clock = clock;
        this.devCrls = devCrls == null ? DevCrlIssuer.NONE : devCrls;
        this.crlNumbers = crlNumbers == null ? CrlNumberStore.inMemory() : crlNumbers;
        this.devCrlValidity = properties.trustAnchors().devCrlValidity();
        this.staleCrlGrace = properties.staleCrlGrace();
        Map<String, Anchor> loaded = new LinkedHashMap<>();
        Map<String, Path> files = new LinkedHashMap<>();
        List<PkiProperties.AnchorSpec> specs = properties.trustAnchors().mdocIaca();
        for (int i = 0; i < specs.size(); i++) {
            PkiProperties.AnchorSpec spec = specs.get(i);
            String where = "certify.pki.trust-anchors.mdoc-iaca[" + i + "]";
            X509Certificate iaca = readCertificate(spec.certificate(), where);
            requireIaca(iaca, where + " (" + spec.certificate() + ")");
            String configured = spec.id() == null || spec.id().isBlank() ? null : spec.id();
            String id = anchorId(configured, iaca, where + (configured == null ? "" : " (id '" + configured + "')"));
            add(loaded, new Anchor(id, MDOC_IACA, iaca), where);
            if (spec.crl() != null) {
                files.put(id, spec.crl());
            }
        }
        for (X509Certificate iaca : providerIacas == null ? List.<X509Certificate>of() : providerIacas) {
            if (loaded.values().stream().anyMatch(anchor -> anchor.certificate().equals(iaca))) {
                continue; // the operator listed it too: the configured entry (its id, its CRL) wins
            }
            String where = "the x509-file IACA " + iaca.getSubjectX500Principal();
            requireIaca(iaca, where);
            add(loaded, new Anchor(anchorId(null, iaca, where), MDOC_IACA, iaca), where);
        }
        this.anchors = List.copyOf(loaded.values());
        this.crlFiles = Map.copyOf(files);
        for (Anchor anchor : anchors) {
            Path file = crlFiles.get(anchor.id());
            if (file != null) {
                current(anchor.id(), readCrlFile(anchor, file, true).orElseThrow());
            } else {
                issueDevCrl(anchor, BigInteger.ZERO, true).ifPresent(state -> current(anchor.id(), state));
            }
        }
        // a stale CRL does not refuse startup: the service issues other formats, and mDoc signing under that IACA fails
        // closed (CRL_STALE) on its own; the ERROR below and the gauge tell the operator (decision log 2026-11-13)
        Instant now = clock.instant();
        for (Anchor anchor : anchors) {
            logFreshness(anchor, crls.get(anchor.id()), now);
        }
        if (!anchors.isEmpty()) {
            log.info("mdoc-iaca trust anchors: {}", anchors.stream().map(anchor -> anchor.id() + " ("
                    + anchor.certificate().getSubjectX500Principal() + (crls.containsKey(anchor.id())
                    ? (crls.get(anchor.id()).dev() ? ", dev CRL" : ", CRL " + crlFiles.get(anchor.id())) : ", no CRL")
                    + ")").toList());
        }
    }

    @Override
    public List<Anchor> entries(String purpose) {
        return MDOC_IACA.equals(purpose) ? anchors : List.of();
    }

    @Override
    public Optional<X509CRL> crl(String anchorId) {
        return Optional.ofNullable(crls.get(anchorId)).map(CrlState::crl);
    }

    @Override
    public Duration staleCrlGrace() {
        return staleCrlGrace;
    }

    /**
     * Registers the gauge {@value #METRIC}{@code {anchor}} for every anchor with a CRL, now and for a CRL that appears
     * later. The value is computed on each scrape from the nextUpdate this registry holds strongly.
     */
    public void bindMetrics(MeterRegistry registry) {
        if (registry == null) {
            return;
        }
        meters = registry;
        crls.forEach((anchorId, state) -> gauge(anchorId).nextUpdate = nextUpdate(state.crl()));
    }

    /**
     * Re-reads changed CRL files, re-issues dev CRLs past half their validity and logs every CRL past its nextUpdate,
     * unchanged ones included; called by the refresh schedule.
     */
    public synchronized void refresh() {
        Instant now = clock.instant();
        for (Anchor anchor : anchors) {
            Path file = crlFiles.get(anchor.id());
            CrlState current = crls.get(anchor.id());
            if (file != null) {
                boolean changed;
                try {
                    changed = current == null || !Files.getLastModifiedTime(file).equals(current.modified())
                            || Files.size(file) != current.size();
                } catch (IOException e) {
                    log.error("CRL file {} of the IACA {} cannot be read ({}); the previous CRL stays in use", file, anchor.id(), e.getMessage());
                    changed = false;
                }
                if (changed) {
                    readCrlFile(anchor, file, false).ifPresent(candidate -> replace(anchor, file, current, candidate));
                }
            } else if (current != null && current.dev()) {
                Instant thisUpdate = current.crl().getThisUpdate().toInstant();
                Instant nextUpdate = current.crl().getNextUpdate().toInstant();
                if (!now.isBefore(thisUpdate.plus(Duration.between(thisUpdate, nextUpdate).dividedBy(2)))) {
                    issueDevCrl(anchor, crlNumber(current.crl()), false).ifPresent(state -> current(anchor.id(), state));
                }
            }
            logFreshness(anchor, crls.get(anchor.id()), now);
        }
    }

    /**
     * Runs {@link #refresh} every {@code interval}; nothing without anchors. A zero or negative interval turns the
     * refresh off, and with it the re-reading of CRL files and the dev-mode CRL renewal: that is logged, because a
     * dev CRL then goes stale after {@code dev-crl-validity} and signing stops once the grace has passed too.
     */
    public synchronized void scheduleRefresh(Duration interval) {
        if (anchors.isEmpty() || scheduler != null) {
            return;
        }
        if (interval == null || interval.isZero() || interval.isNegative()) {
            crls.forEach((anchorId, state) -> log.warn("certify.pki.trust-anchors.crl-refresh-interval is {}: the CRL of the IACA {}"
                    + " is never {} and its freshness is not logged; once its nextUpdate {} is more than {} past, mDoc"
                    + " signing under it is refused (CRL_STALE) until a restart {}", interval, anchorId,
                    state.dev() ? "re-issued (dev mode)" : "re-read from " + crlFiles.get(anchorId), nextUpdate(state.crl()),
                    staleCrlGrace, state.dev() ? "issues a new one" : "reads a new one"));
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "certify-trust-anchor-crl-refresh");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                refresh();
            } catch (RuntimeException e) {
                log.error("CRL refresh failed; the current CRLs stay in use", e);
            }
        }, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    private void current(String anchorId, CrlState state) {
        crls.put(anchorId, state);
        if (meters != null) {
            gauge(anchorId).nextUpdate = nextUpdate(state.crl());
        }
    }

    private CrlGauge gauge(String anchorId) {
        return gauges.computeIfAbsent(anchorId, id -> {
            CrlGauge state = new CrlGauge();
            Gauge.builder(METRIC, state, this::secondsToNextUpdate)
                    .tag("anchor", id)
                    .description("Seconds until the IACA CRL's nextUpdate; negative once it passed (mDoc signing under"
                            + " the IACA is refused once it is more than certify.pki.stale-crl-grace past)")
                    .baseUnit("seconds")
                    .strongReference(true)
                    .register(meters);
            return state;
        });
    }

    private double secondsToNextUpdate(CrlGauge gauge) {
        Instant nextUpdate = gauge.nextUpdate;
        return nextUpdate == null ? Double.NaN : Duration.between(clock.instant(), nextUpdate).toMillis() / 1000.0;
    }

    /**
     * A changed CRL file that validated replaces the current CRL only when it moves forward (RFC 5280 5.2.3): a larger
     * cRLNumber, and a thisUpdate no more than {@link AnnexBValidator#CLOCK_SKEW} earlier than the current one's (the
     * number orders CRLs; the skew absorbs a signer whose clock ran fast). The same CRL written again changes nothing. Anything else (a lower number,
     * the same number with other content, an earlier thisUpdate) is a rollback that could un-revoke a Document Signer:
     * it is logged at ERROR on every tick until the file is fixed, and the current CRL stays.
     */
    private void replace(Anchor anchor, Path file, CrlState current, CrlState candidate) {
        if (current == null) {
            current(anchor.id(), candidate);
            return;
        }
        BigInteger was = crlNumber(current.crl());
        BigInteger is = crlNumber(candidate.crl());
        int order = is.compareTo(was);
        if (order == 0 && Arrays.equals(encoded(current.crl()), encoded(candidate.crl()))) {
            crls.put(anchor.id(), new CrlState(current.crl(), candidate.modified(), candidate.size(), false));
            log.debug("The CRL file {} of the IACA {} was rewritten with the same CRL (cRLNumber {})", file, anchor.id(), is);
            return;
        }
        Instant wasThisUpdate = current.crl().getThisUpdate().toInstant();
        Instant isThisUpdate = candidate.crl().getThisUpdate().toInstant();
        // RFC 5280 5.2.3 orders CRLs by number; thisUpdate only guards against an old list renumbered, within the clock
        // skew AnnexBValidator allows, so a CRL signed on a slightly slow clock after one signed on a fast clock is taken
        String problem = order < 0 ? "its cRLNumber " + is + " is lower than the current " + was
                : order == 0 ? "its cRLNumber " + is + " is the current one's, but its content differs"
                : isThisUpdate.isBefore(wasThisUpdate.minus(AnnexBValidator.CLOCK_SKEW)) ? "its thisUpdate " + isThisUpdate
                        + " is more than " + AnnexBValidator.CLOCK_SKEW + " earlier than the current " + wasThisUpdate
                : null;
        if (problem != null) {
            log.error("Refused the CRL {} of the IACA {}: {}. A replacement must carry a larger cRLNumber (RFC 5280"
                    + " 5.2.3) and a thisUpdate no earlier than the current CRL's less the clock skew, since an older list"
                    + " could un-revoke a Document Signer; the current CRL (cRLNumber {}, thisUpdate {}) stays in use", file, anchor.id(),
                    problem, was, wasThisUpdate);
            return;
        }
        current(anchor.id(), candidate);
        log.info("Reloaded the CRL of the IACA {} from {} (cRLNumber {}, nextUpdate {})", anchor.id(), file, is,
                nextUpdate(candidate.crl()));
    }

    /** WARN for a CRL past its nextUpdate within the grace (signing continues), ERROR past the grace (refused). */
    private void logFreshness(Anchor anchor, CrlState state, Instant now) {
        if (state == null) {
            return;
        }
        Instant nextUpdate = nextUpdate(state.crl());
        if (nextUpdate == null || !now.isAfter(nextUpdate)) {
            return;
        }
        if (pastGrace(state.crl(), now)) {
            log.error("The CRL of the IACA {} passed its nextUpdate {} more than {} ago (certify.pki.stale-crl-grace):"
                    + " mDoc signing under it is refused (CRL_STALE) until a new CRL is {}", anchor.id(), nextUpdate,
                    staleCrlGrace, state.dev() ? "issued" : "published");
        } else {
            log.warn("The CRL of the IACA {} passed its nextUpdate {}: {} a new one before {}, when mDoc signing under"
                    + " it is refused (CRL_STALE, certify.pki.stale-crl-grace {}); until then signing continues and the"
                    + " revocations it lists still apply", anchor.id(), nextUpdate, state.dev() ? "issue" : "publish",
                    nextUpdate.plus(staleCrlGrace), staleCrlGrace);
        }
    }

    private boolean pastGrace(X509CRL crl, Instant now) {
        Instant nextUpdate = nextUpdate(crl);
        return nextUpdate != null && now.isAfter(nextUpdate.plus(staleCrlGrace));
    }

    private static Instant nextUpdate(X509CRL crl) {
        return crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant();
    }

    /**
     * An empty CRL for an IACA whose key the dev-mode provider holds. The number is one more than the last one recorded
     * for the IACA (here or in the {@link CrlNumberStore}, which survives restarts) and at least the issuing epoch
     * second, and it is recorded before the CRL is used: a restart within the same second, or after the clock was set
     * back, never reuses or lowers a number (RFC 5280 5.2.3). A number that cannot be recorded leaves the CRL unused.
     */
    private Optional<CrlState> issueDevCrl(Anchor anchor, BigInteger previous, boolean startup) {
        Instant thisUpdate = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant iacaEnd = anchor.certificate().getNotAfter().toInstant();
        Instant nextUpdate = thisUpdate.plus(devCrlValidity);
        if (nextUpdate.isAfter(iacaEnd)) {
            nextUpdate = iacaEnd;
        }
        if (!nextUpdate.isAfter(thisUpdate)) {
            return Optional.empty();
        }
        BigInteger last = previous.max(crlNumbers.last(anchor.certificate()));
        BigInteger number = BigInteger.valueOf(thisUpdate.getEpochSecond()).max(last.add(BigInteger.ONE));
        Optional<X509CRL> crl = devCrls.issue(anchor.certificate(), number, thisUpdate, nextUpdate);
        if (crl.isEmpty()) {
            return Optional.empty();
        }
        try {
            crlNumbers.record(anchor.certificate(), number);
        } catch (IOException | RuntimeException e) {
            if (startup) {
                throw new IllegalStateException("Cannot record the cRLNumber " + number + " of the dev-mode CRL of the IACA "
                        + anchor.id() + crlNumbers.location().map(file -> " in " + file + " (" + e.getMessage() + "); in"
                        + " x509-file dev mode the keystore's directory " + file.getParent() + " must be writable, since the"
                        + " last cRLNumber of each dev IACA is kept there (<keystore>.crl-numbers) so numbers keep increasing"
                        + " across restarts").orElse(": " + e.getMessage()), e);
            }
            log.error("Cannot record the cRLNumber {} of the dev-mode CRL of the IACA {} ({}); the current CRL stays in use",
                    number, anchor.id(), e.getMessage());
            return Optional.empty();
        }
        log.info("Issued the dev-mode CRL of the IACA {} (cRLNumber {}, nextUpdate {})", anchor.id(), number,
                crl.get().getNextUpdate().toInstant());
        return Optional.of(new CrlState(crl.get(), null, -1, true));
    }

    /** Reads and validates a CRL file; at startup a problem refuses to start, later it keeps the previous CRL. */
    private Optional<CrlState> readCrlFile(Anchor anchor, Path file, boolean startup) {
        String where = "the CRL " + file + " of the IACA " + anchor.id();
        try {
            FileTime modified = Files.getLastModifiedTime(file);
            long size = Files.size(file);
            byte[] bytes = Files.readAllBytes(file);
            X509CRL crl = isPem(bytes) ? Pem.readCrl(new String(bytes, StandardCharsets.US_ASCII))
                    : (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(bytes));
            List<AnnexBValidator.Violation> violations = AnnexBValidator.validateCrl(crl, anchor.certificate(), clock.instant());
            if (!violations.isEmpty()) {
                throw new IllegalStateException(where + " breaks ISO/IEC 18013-5 Annex B / RFC 5280: " + violations);
            }
            return Optional.of(new CrlState(crl, modified, size, false));
        } catch (IOException | CRLException | CertificateException | RuntimeException e) {
            if (startup) {
                throw e instanceof IllegalStateException state ? state
                        : new IllegalStateException("Cannot read " + where + ": " + e.getMessage(), e);
            }
            log.error("Cannot use {} ({}); the previous CRL stays in use", where, e.getMessage());
            return Optional.empty();
        }
    }

    private static void add(Map<String, Anchor> loaded, Anchor anchor, String where) {
        Anchor existing = loaded.get(anchor.id());
        if (existing != null) {
            throw new IllegalStateException(where + ": the anchor id '" + anchor.id() + "' is already used by "
                    + existing.certificate().getSubjectX500Principal() + "; give one of them an explicit"
                    + " certify.pki.trust-anchors.mdoc-iaca[].id");
        }
        loaded.put(anchor.id(), anchor);
    }

    private static void requireIaca(X509Certificate iaca, String where) {
        List<AnnexBValidator.Violation> violations = AnnexBValidator.validateIaca(iaca);
        if (!violations.isEmpty()) {
            throw new IllegalStateException(where + " is not an ISO/IEC 18013-5:2021 Annex B IACA: " + violations);
        }
    }

    /**
     * The anchor's id: {@code configured} when set, else the {@code <id>} of a CRL distribution point
     * {@code …/mdoc/iaca/<id>.crl} (so the advertised URL is the one served), else the subject key identifier in hex.
     * Every distribution point of that form must name a valid id and this anchor's id; otherwise the publication would
     * answer 404 where the IACA, and every DSC that copies its distribution point, sends verifiers, and startup is
     * refused naming both.
     */
    static String anchorId(String configured, X509Certificate iaca, String where) {
        List<String[]> published = publishedCrlIds(iaca);
        for (String[] point : published) {
            if (!PkiProperties.ID.matcher(point[1]).matches()) {
                throw new IllegalStateException(where + ": the IACA " + iaca.getSubjectX500Principal() + " has the CRL"
                        + " distribution point " + point[0] + ", whose '" + point[1] + "' is not a valid anchor id: an id is "
                        + PkiProperties.ID_RULE + ", so /mdoc/iaca/" + point[1] + ".crl is never served. Issue the IACA"
                        + " with a CRL distribution point https://<host>/v1/certify/mdoc/iaca/<id>.crl whose <id> follows"
                        + " that rule (certify.keyprovider.x509-file.iaca.crl-uri, certify-cli pki iaca create --crl-uri)");
            }
        }
        String id = configured != null ? configured : published.isEmpty()
                ? CertificateLinks.subjectKeyIdentifierHex(iaca).orElseThrow(() -> new IllegalStateException(where
                        + ": the IACA " + iaca.getSubjectX500Principal() + " has no subject key identifier to name it by;"
                        + " set certify.pki.trust-anchors.mdoc-iaca[].id"))
                : published.get(0)[1];
        for (String[] point : published) {
            if (!point[1].equals(id)) {
                throw new IllegalStateException(where + ": the IACA " + iaca.getSubjectX500Principal() + " advertises its"
                        + " CRL at " + point[0] + " (anchor id '" + point[1] + "'), but its anchor id is '" + id + "'"
                        + (configured != null ? " (configured)" : "") + ", so this issuer serves that CRL at /mdoc/iaca/"
                        + id + ".crl and the advertised URL would answer 404 to every verifier; "
                        + (configured != null ? "set the id to '" + point[1] + "' or leave it unset"
                        : "an IACA names one id in all its distribution points under /mdoc/iaca"));
            }
        }
        return id;
    }

    /** {@code [uri, <id>]} for every CRL distribution point whose path is {@code …/mdoc/iaca/<id>.crl}. */
    private static List<String[]> publishedCrlIds(X509Certificate iaca) {
        List<String[]> ids = new ArrayList<>();
        for (String uri : crlDistributionPoints(iaca)) {
            String path;
            try {
                path = URI.create(uri).getPath();
            } catch (IllegalArgumentException e) {
                continue;
            }
            Matcher matcher = PUBLISHED_CRL.matcher(path == null ? "" : path);
            if (matcher.matches()) {
                ids.add(new String[] {uri, matcher.group(1)});
            }
        }
        return ids;
    }

    /** The URIs of the certificate's CRL distribution points, in order. */
    static List<String> crlDistributionPoints(X509Certificate certificate) {
        byte[] value = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        List<String> uris = new ArrayList<>();
        if (value == null) {
            return uris;
        }
        try {
            for (DistributionPoint point : CRLDistPoint.getInstance(ASN1OctetString.getInstance(value).getOctets()).getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();
                if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                    Arrays.stream(GeneralNames.getInstance(name.getName()).getNames())
                            .filter(general -> general.getTagNo() == GeneralName.uniformResourceIdentifier)
                            .map(general -> general.getName().toString())
                            .forEach(uris::add);
                }
            }
        } catch (RuntimeException e) {
            return List.of(); // validateIaca already refused a malformed distribution point
        }
        return uris;
    }

    static X509Certificate readCertificate(Path path, String where) {
        try {
            byte[] bytes = Files.readAllBytes(path);
            if (isPem(bytes)) {
                List<X509Certificate> certificates = Pem.readCertificates(new String(bytes, StandardCharsets.US_ASCII));
                if (certificates.size() != 1) {
                    throw new IllegalStateException(where + ": " + path + " holds " + certificates.size()
                            + " certificates; an anchor file holds exactly the IACA certificate");
                }
                return certificates.get(0);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
        } catch (IOException | CertificateException | RuntimeException e) {
            throw e instanceof IllegalStateException state ? state
                    : new IllegalStateException(where + ": cannot read the IACA certificate " + path + ": " + e.getMessage(), e);
        }
    }

    private static boolean isPem(byte[] bytes) {
        return new String(bytes, 0, Math.min(bytes.length, 4096), StandardCharsets.US_ASCII).contains("-----BEGIN ");
    }

    private static byte[] encoded(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (CRLException e) {
            throw new IllegalStateException("Cannot encode the CRL of " + crl.getIssuerX500Principal(), e);
        }
    }

    static BigInteger crlNumber(X509CRL crl) {
        byte[] value = crl.getExtensionValue(Extension.cRLNumber.getId());
        if (value == null) {
            return BigInteger.ZERO;
        }
        return org.bouncycastle.asn1.ASN1Integer.getInstance(ASN1OctetString.getInstance(value).getOctets()).getValue();
    }
}
