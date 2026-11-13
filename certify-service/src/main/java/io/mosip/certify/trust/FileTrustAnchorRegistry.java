package io.mosip.certify.trust;

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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
 * IACA advertises is the one this issuer serves), else its subject key identifier in lower-case hex.
 *
 * <p>CRLs are refreshed every {@code crl-refresh-interval}: a configured file is re-read when its modification time or
 * size changed and replaces the current CRL only when it validates (a broken file is logged and the previous CRL kept);
 * for an IACA whose private key the x509-file provider holds in dev mode, an empty CRL is issued at startup and
 * re-issued once half its validity has passed, with a cRLNumber that never decreases (decision log 2026-11-13).
 */
@Slf4j
public class FileTrustAnchorRegistry implements TrustAnchorRegistry, AutoCloseable {

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
    private final Duration devCrlValidity;
    private final Clock clock;
    private ScheduledExecutorService scheduler;

    /** What is current for one anchor: the CRL and, for a file, what the file looked like when it was read. */
    private record CrlState(X509CRL crl, FileTime modified, long size, boolean dev) {}

    /**
     * @param properties   {@code certify.pki}
     * @param providerIacas the IACAs of the x509-file provider ({@code X509FileKeyProviders.iacaCertificates}), empty when
     *                     it is not enabled
     * @param devCrls      issues dev-mode CRLs for IACAs whose key is held in the application
     */
    public FileTrustAnchorRegistry(PkiProperties properties, List<X509Certificate> providerIacas, DevCrlIssuer devCrls, Clock clock) {
        this.clock = clock;
        this.devCrls = devCrls == null ? DevCrlIssuer.NONE : devCrls;
        this.devCrlValidity = properties.trustAnchors().devCrlValidity();
        Map<String, Anchor> loaded = new LinkedHashMap<>();
        Map<String, Path> files = new LinkedHashMap<>();
        List<PkiProperties.AnchorSpec> specs = properties.trustAnchors().mdocIaca();
        for (int i = 0; i < specs.size(); i++) {
            PkiProperties.AnchorSpec spec = specs.get(i);
            String where = "certify.pki.trust-anchors.mdoc-iaca[" + i + "]";
            X509Certificate iaca = readCertificate(spec.certificate(), where);
            requireIaca(iaca, where + " (" + spec.certificate() + ")");
            String id = spec.id() == null || spec.id().isBlank() ? derivedId(iaca) : spec.id();
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
            add(loaded, new Anchor(derivedId(iaca), MDOC_IACA, iaca), where);
        }
        this.anchors = List.copyOf(loaded.values());
        this.crlFiles = Map.copyOf(files);
        for (Anchor anchor : anchors) {
            Path file = crlFiles.get(anchor.id());
            if (file != null) {
                crls.put(anchor.id(), readCrlFile(anchor, file, true).orElseThrow());
            } else {
                issueDevCrl(anchor, BigInteger.ZERO).ifPresent(state -> crls.put(anchor.id(), state));
            }
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

    /** Re-reads changed CRL files and re-issues dev CRLs past half their validity; called by the refresh schedule. */
    public synchronized void refresh() {
        Instant now = clock.instant();
        for (Anchor anchor : anchors) {
            Path file = crlFiles.get(anchor.id());
            CrlState current = crls.get(anchor.id());
            if (file != null) {
                try {
                    if (current != null && Files.getLastModifiedTime(file).equals(current.modified()) && Files.size(file) == current.size()) {
                        continue;
                    }
                } catch (IOException e) {
                    log.error("CRL file {} of the IACA {} cannot be read ({}); the previous CRL stays in use", file, anchor.id(), e.getMessage());
                    continue;
                }
                readCrlFile(anchor, file, false).ifPresent(state -> {
                    crls.put(anchor.id(), state);
                    log.info("Reloaded the CRL of the IACA {} from {} (cRLNumber {}, nextUpdate {})", anchor.id(), file,
                            crlNumber(state.crl()), state.crl().getNextUpdate().toInstant());
                });
            } else if (current != null && current.dev()) {
                Instant thisUpdate = current.crl().getThisUpdate().toInstant();
                Instant nextUpdate = current.crl().getNextUpdate().toInstant();
                if (!now.isBefore(thisUpdate.plus(Duration.between(thisUpdate, nextUpdate).dividedBy(2)))) {
                    issueDevCrl(anchor, crlNumber(current.crl())).ifPresent(state -> crls.put(anchor.id(), state));
                }
            }
            CrlState state = crls.get(anchor.id());
            if (state != null && state.crl().getNextUpdate() != null && now.isAfter(state.crl().getNextUpdate().toInstant())) {
                log.warn("The CRL of the IACA {} passed its nextUpdate {}: publish a new one (revocations it lists still apply)",
                        anchor.id(), state.crl().getNextUpdate().toInstant());
            }
        }
    }

    /** Runs {@link #refresh} every {@code interval}; nothing for a zero or negative interval or without anchors. */
    public synchronized void scheduleRefresh(Duration interval) {
        if (interval == null || interval.isZero() || interval.isNegative() || anchors.isEmpty() || scheduler != null) {
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

    private Optional<CrlState> issueDevCrl(Anchor anchor, BigInteger previous) {
        // CRL numbers must increase (RFC 5280 5.2.3) across restarts too: the issuing second, or one more than the last
        Instant thisUpdate = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        BigInteger number = BigInteger.valueOf(thisUpdate.getEpochSecond()).max(previous.add(BigInteger.ONE));
        Instant iacaEnd = anchor.certificate().getNotAfter().toInstant();
        Instant nextUpdate = thisUpdate.plus(devCrlValidity);
        if (nextUpdate.isAfter(iacaEnd)) {
            nextUpdate = iacaEnd;
        }
        if (!nextUpdate.isAfter(thisUpdate)) {
            return Optional.empty();
        }
        Optional<X509CRL> crl = devCrls.issue(anchor.certificate(), number, thisUpdate, nextUpdate);
        crl.ifPresent(issued -> log.info("Issued the dev-mode CRL of the IACA {} (cRLNumber {}, nextUpdate {})",
                anchor.id(), number, issued.getNextUpdate().toInstant()));
        return crl.map(issued -> new CrlState(issued, null, -1, true));
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
        } catch (IOException | java.security.cert.CRLException | CertificateException | RuntimeException e) {
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
     * The id of an anchor without a configured one: the {@code <id>} of a CRL distribution point
     * {@code …/mdoc/iaca/<id>.crl}, so the advertised URL is the one served, else the subject key identifier in hex.
     */
    static String derivedId(X509Certificate iaca) {
        for (String uri : crlDistributionPoints(iaca)) {
            String path;
            try {
                path = URI.create(uri).getPath();
            } catch (IllegalArgumentException e) {
                continue;
            }
            Matcher matcher = PUBLISHED_CRL.matcher(path == null ? "" : path);
            if (matcher.matches() && PkiProperties.ID.matcher(matcher.group(1)).matches()) {
                return matcher.group(1);
            }
        }
        return CertificateLinks.subjectKeyIdentifierHex(iaca)
                .orElseThrow(() -> new IllegalStateException("The IACA " + iaca.getSubjectX500Principal()
                        + " has no subject key identifier to name it by; set certify.pki.trust-anchors.mdoc-iaca[].id"));
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

    static BigInteger crlNumber(X509CRL crl) {
        byte[] value = crl.getExtensionValue(Extension.cRLNumber.getId());
        if (value == null) {
            return BigInteger.ZERO;
        }
        return org.bouncycastle.asn1.ASN1Integer.getInstance(ASN1OctetString.getInstance(value).getOctets()).getValue();
    }
}
