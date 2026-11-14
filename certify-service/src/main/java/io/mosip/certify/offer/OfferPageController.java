package io.mosip.certify.offer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code /offer} and {@code /offer/} answer the bundled page itself (static resources have no directory index, and a
 * forward under a servlet path other than {@code /} does not resolve). {@code /offer/demo-subjects} answers the example
 * subjects {@code certify.offer-page.demo-subjects} configures, which the page offers in place of a typed record id
 * (F-15).
 *
 * <p>The subjects come from the properties and from nothing else: the endpoint reads no data source and no holder
 * file, so it cannot enumerate a deployment's subjects, and an operator who configures none gets
 * {@code {"subjects":[]}}. The page is the only client (same origin, under the page's own security chain).
 * {@code no-store}, because a deployment's list is a restart away from changing and the page must not show a stale
 * one.</p>
 *
 * <p>P5-03a adds the demo wallet: {@code /offer/wallet} and {@code /offer/wallet/config}, both only with
 * {@code certify.offer-page.wallet.enabled} (D-P5-03-6, D-P5-03-11). Every page answer carries the security headers of
 * the plan's section 4.13; the offer page's Content-Security-Policy hashes its inline script, computed here from the
 * bytes served, so the header can never drift from the page.</p>
 *
 * <p>{@code @EnableConfigurationProperties} here rather than only on {@link OfferPageSecurityConfiguration}: that chain
 * is absent under the {@code test} profile, and the controller needs the properties on any profile the page is on.</p>
 */
@RestController
@EnableConfigurationProperties(OfferPageProperties.class)
@ConditionalOnProperty(prefix = OfferPageProperties.PREFIX, name = "enabled", havingValue = "true")
public class OfferPageController {

    private static final ClassPathResource PAGE = new ClassPathResource("static/offer/index.html");
    private static final ClassPathResource WALLET_PAGE = new ClassPathResource("static/offer/wallet.html");
    /** The inline scripts a page may carry: a tag with no attributes at all. */
    private static final Pattern INLINE_SCRIPT = Pattern.compile("<script>([\\s\\S]*?)</script>");
    /** The hosts whose page may reach a local stack over plain HTTP (the CI and development stacks). */
    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private static final String CSP_TEMPLATE = "default-src 'none'; script-src %s; style-src 'self' 'unsafe-inline';"
            + " img-src 'self' blob: data:; connect-src %s; frame-ancestors 'none'; base-uri 'none';"
            + " form-action 'none'; object-src 'none'";
    private static final String CONNECT_SRC = "'self' https:";
    private static final String CONNECT_SRC_LOCAL = "'self' https: http://localhost:* http://127.0.0.1:* http://[::1]:*";
    private static final String REFERRER_POLICY = "no-referrer";

    private final OfferPageProperties properties;
    private final byte[] page;
    private final String pageScriptSources;
    private final byte[] walletPage;

    public OfferPageController(OfferPageProperties properties) {
        this.properties = properties;
        try {
            this.page = PAGE.getContentAsByteArray();
            this.walletPage = WALLET_PAGE.getContentAsByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("the offer page resources cannot be read", e);
        }
        // the hash of the inline script, over the bytes served: a page edit changes it with the page
        this.pageScriptSources = "'self'" + inlineScriptHashes(new String(page, StandardCharsets.UTF_8));
    }

    /**
     * The offer page. Its file name, {@code /offer/index.html}, is mapped here too (P5-03a review round 3): as an
     * ordinary classpath resource it was served by the static resource handler without the headers of plan 4.13, so the
     * same bytes reached a browser with no Content-Security-Policy. Every spelling now answers the same page with the
     * same headers.
     */
    @GetMapping(value = {"/offer", "/offer/", "/offer/index.html"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> page(HttpServletRequest request) {
        // the issuance page never needs the camera, and it is served with the same origin-wide rules as the wallet
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .header("Content-Security-Policy", csp(pageScriptSources, request))
                .header("Permissions-Policy", "camera=()")
                .header("Referrer-Policy", REFERRER_POLICY)
                .body(page);
    }

    /** The demo wallet (P5-03a); 404 unless {@code certify.offer-page.wallet.enabled}. */
    @GetMapping(value = "/offer/wallet", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> walletPage(HttpServletRequest request) {
        if (!properties.walletEnabled()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .cacheControl(CacheControl.noStore())
                .header("Content-Security-Policy", csp("'self'", request))
                .header("Permissions-Policy", "camera=(self)")
                .header("Referrer-Policy", REFERRER_POLICY)
                .body(walletPage);
    }

    /**
     * The wallet page's file name. {@code static/offer/wallet.html} is an ordinary classpath resource, so without this
     * mapping the static resource handler would serve it here - with the wallet switched off and without the headers
     * above. The page has one address, {@code /offer/wallet}; this spelling answers 404 whatever the switch says. (The
     * offer page's {@code /offer/index.html} answers the page with its headers, see {@link #page}: links to it predate
     * the wallet.)
     */
    @GetMapping("/offer/wallet.html")
    public ResponseEntity<Void> walletPageFile() {
        return ResponseEntity.notFound().build();
    }

    /**
     * What the wallet page needs from this deployment: the relay's host allow-list (P5-03f; empty until it exists). The
     * page links the wallet only when this answers 200, so with the wallet off the offer page shows no link.
     */
    @GetMapping(value = "/offer/wallet/config", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> walletConfig() {
        if (!properties.walletEnabled()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of("relay", Map.of("hosts", List.of())));
    }

    @GetMapping(value = "/offer/demo-subjects", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<DemoSubjectsResponse> demoSubjects() {
        List<DemoSubjectsResponse.Subject> subjects = properties.demoSubjects().stream()
                .map(subject -> new DemoSubjectsResponse.Subject(subject.id(), subject.labelOrId(),
                        subject.credentialConfigurationIds()))
                .toList();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new DemoSubjectsResponse(subjects));
    }

    private static String csp(String scriptSources, HttpServletRequest request) {
        String connect = request != null && LOCAL_HOSTS.contains(request.getServerName()) ? CONNECT_SRC_LOCAL : CONNECT_SRC;
        return String.format(CSP_TEMPLATE, scriptSources, connect);
    }

    /** `'sha256-…'` per inline script, base64 of the SHA-256 of the script's text (CSP 3, section 6.7.3.1). */
    static String inlineScriptHashes(String html) {
        // The browser hashes the script's text as its parser produced it, and the HTML parser turns CRLF and a lone CR
        // into LF before the tokenizer sees the newline (HTML standard, 13.2.3.1). A page read from a checkout with
        // another line ending therefore has to be hashed over LF too, or every script would be blocked.
        String normalised = html.replace("\r\n", "\n").replace('\r', '\n');
        StringBuilder hashes = new StringBuilder();
        Matcher matcher = INLINE_SCRIPT.matcher(normalised);
        while (matcher.find()) {
            hashes.append(" 'sha256-").append(sha256Base64(matcher.group(1))).append('\'');
        }
        return hashes.toString();
    }

    private static String sha256Base64(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every JRE", e);
        }
    }
}
