package io.mosip.certify.trust;

import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.TrustAnchorRegistry;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Publishes the IACA certificates mDoc verifiers anchor to, and their CRLs (docs/design/20-mdl-issuer.md M-08, decision
 * D15: a plain list plus downloads; a signed VICAL later). Off unless {@code certify.pki.publication.enabled}; public
 * and read-only, under its own security chain ({@link IacaPublicationSecurityConfiguration}).
 *
 * <ul>
 *     <li>{@code GET /mdoc/iaca}: {@code [{id, subject, country, sha256, notBefore, notAfter, pem, der, crl}]}, the
 *     downloads as references relative to this list's URL ({@code iaca/<id>.pem}), {@code crl} null when the anchor
 *     publishes none;</li>
 *     <li>{@code GET /mdoc/iaca/<id>.pem} ({@code application/x-pem-file}), {@code .der} ({@code application/pkix-cert}),
 *     {@code .crl} (the CRL as DER, {@code application/pkix-crl}; 404 when the anchor has none).</li>
 * </ul>
 * {@code https://<host>/v1/certify/mdoc/iaca/<id>.crl} is the CRL distribution point to write into an IACA; the id is
 * the one {@link FileTrustAnchorRegistry} gives the anchor.
 */
@RestController
@RequestMapping("/mdoc/iaca")
@ConditionalOnProperty(prefix = "certify.pki.publication", name = "enabled", havingValue = "true")
public class IacaPublicationController {

    static final MediaType PEM = MediaType.parseMediaType("application/x-pem-file");
    static final MediaType CERTIFICATE = MediaType.parseMediaType("application/pkix-cert");
    static final MediaType CRL = MediaType.parseMediaType("application/pkix-crl");
    /** Certificates do not change under an id; the list may gain an anchor at the next restart. */
    static final Duration CERTIFICATE_MAX_AGE = Duration.ofHours(1);
    static final Duration LIST_MAX_AGE = Duration.ofMinutes(5);
    /** A CRL is cached until its nextUpdate, never longer than this, so a re-issued one reaches clients within it. */
    static final Duration CRL_MAX_AGE = Duration.ofHours(1);

    private final TrustAnchorRegistry registry;

    public IacaPublicationController(TrustAnchorRegistry registry) {
        this.registry = registry;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> list() {
        List<Map<String, Object>> body = registry.entries(TrustAnchorRegistry.MDOC_IACA).stream().map(this::describe).toList();
        return ResponseEntity.ok().cacheControl(maxAge(LIST_MAX_AGE)).body(body);
    }

    @GetMapping("/{file:.+}")
    public ResponseEntity<byte[]> download(@PathVariable("file") String file) {
        int dot = file.lastIndexOf('.');
        if (dot <= 0) {
            return ResponseEntity.notFound().build();
        }
        String id = file.substring(0, dot);
        Optional<TrustAnchorRegistry.Anchor> anchor = registry.anchor(TrustAnchorRegistry.MDOC_IACA, id);
        if (anchor.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        X509Certificate certificate = anchor.get().certificate();
        return switch (file.substring(dot + 1)) {
            case "pem" -> ResponseEntity.ok().contentType(PEM).cacheControl(maxAge(CERTIFICATE_MAX_AGE))
                    .body(Pem.writeCertificate(certificate).getBytes(StandardCharsets.US_ASCII));
            case "der" -> ResponseEntity.ok().contentType(CERTIFICATE).cacheControl(maxAge(CERTIFICATE_MAX_AGE))
                    .body(der(certificate));
            case "crl" -> registry.crl(id)
                    .map(crl -> ResponseEntity.ok().contentType(CRL).cacheControl(crlCache(crl, Instant.now())).body(der(crl)))
                    .orElseGet(() -> ResponseEntity.notFound().build());
            default -> ResponseEntity.notFound().build();
        };
    }

    private Map<String, Object> describe(TrustAnchorRegistry.Anchor anchor) {
        X509Certificate certificate = anchor.certificate();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", anchor.id());
        entry.put("subject", certificate.getSubjectX500Principal().getName());
        entry.put("country", country(certificate));
        entry.put("sha256", sha256(der(certificate)));
        entry.put("notBefore", certificate.getNotBefore().toInstant().toString());
        entry.put("notAfter", certificate.getNotAfter().toInstant().toString());
        entry.put("pem", "iaca/" + anchor.id() + ".pem");
        entry.put("der", "iaca/" + anchor.id() + ".der");
        entry.put("crl", registry.crl(anchor.id()).isPresent() ? "iaca/" + anchor.id() + ".crl" : null);
        return entry;
    }

    /** Until nextUpdate, at most {@link #CRL_MAX_AGE}; a CRL past its nextUpdate is served uncached. */
    static CacheControl crlCache(X509CRL crl, Instant now) {
        if (crl.getNextUpdate() == null) {
            return CacheControl.noCache();
        }
        Duration left = Duration.between(now, crl.getNextUpdate().toInstant());
        if (left.isNegative() || left.isZero()) {
            return CacheControl.noCache();
        }
        return maxAge(left.compareTo(CRL_MAX_AGE) < 0 ? left : CRL_MAX_AGE);
    }

    private static CacheControl maxAge(Duration duration) {
        return CacheControl.maxAge(duration.toSeconds(), TimeUnit.SECONDS).cachePublic();
    }

    private static String country(X509Certificate certificate) {
        X500Name name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        return name.getRDNs(BCStyle.C).length == 0 ? null
                : IETFUtils.valueToString(name.getRDNs(BCStyle.C)[0].getFirst().getValue());
    }

    private static String sha256(byte[] der) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] der(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Cannot encode the IACA " + certificate.getSubjectX500Principal(), e);
        }
    }

    private static byte[] der(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (CRLException e) {
            throw new IllegalStateException("Cannot encode the CRL of " + crl.getIssuerX500Principal(), e);
        }
    }
}
