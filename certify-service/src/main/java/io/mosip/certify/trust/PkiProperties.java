package io.mosip.certify.trust;

import io.mosip.certify.signing.TrustAnchorRegistry;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * {@code certify.pki.*} (docs/design/14-configuration.md, 20-mdl-issuer.md M-06 and M-08): the IACA trust anchors mDoc
 * Document Signers are checked against, and their publication. New settings, so no aliases. Nothing here is set by
 * default: without an anchor the DSC policy's trust-anchor rules do not apply and nothing is published.
 *
 * @param trustAnchors  the anchors and how their CRLs are refreshed
 * @param publication   {@code GET /mdoc/iaca} and the per-anchor downloads
 * @param staleCrlGrace how long an anchor's CRL may be past its {@code nextUpdate} before mDoc signing under that
 *                      anchor is refused with {@code CRL_STALE} (and startup refused); within it signing continues with
 *                      a WARN and the CRL's revocations still apply. {@code PT24H} by default, {@code PT0S} refuses as
 *                      soon as {@code nextUpdate} has passed (decision log 2026-11-13, refining D16)
 */
@ConfigurationProperties(prefix = "certify.pki")
public record PkiProperties(@DefaultValue TrustAnchors trustAnchors, @DefaultValue Publication publication,
                            @DefaultValue("PT24H") Duration staleCrlGrace) {

    /** An anchor id: what {@code /mdoc/iaca/<id>.crl} and the other downloads are named by. */
    static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");

    /** {@link #ID} in words, for the messages that refuse an id. */
    static final String ID_RULE = "lower-case letters, digits, '.', '_' and '-', starting with a letter or digit, at most"
            + " 64 characters (" + ID.pattern() + ")";

    @ConstructorBinding
    public PkiProperties {
        trustAnchors = trustAnchors == null ? new TrustAnchors(List.of(), Duration.ofMinutes(5), Duration.ofDays(7)) : trustAnchors;
        publication = publication == null ? new Publication(false) : publication;
        staleCrlGrace = staleCrlGrace == null ? TrustAnchorRegistry.DEFAULT_STALE_CRL_GRACE : staleCrlGrace;
        if (staleCrlGrace.isNegative()) {
            throw new IllegalArgumentException("certify.pki.stale-crl-grace must be zero or positive, was " + staleCrlGrace);
        }
    }

    /** The shape before {@code stale-crl-grace}: the default grace. */
    public PkiProperties(TrustAnchors trustAnchors, Publication publication) {
        this(trustAnchors, publication, null);
    }

    /**
     * @param mdocIaca             the operator's IACA certificates (purpose {@code mdoc-iaca}); the x509-file provider's
     *                             IACAs are added to them when that provider is enabled
     * @param crlRefreshInterval   how often configured CRL files are re-read when they changed, a dev-mode CRL is
     *                             re-issued once half its validity has passed, and every CRL's freshness is logged;
     *                             zero or negative turns the refresh off, and with it the dev-mode CRL renewal: a dev
     *                             CRL then goes stale after {@code dev-crl-validity} (signing is still refused past the
     *                             grace, which is judged when signing, not by the refresh)
     * @param devCrlValidity       nextUpdate - thisUpdate of the empty CRL dev mode issues for an IACA whose key it holds
     */
    public record TrustAnchors(@DefaultValue List<AnchorSpec> mdocIaca,
                               @DefaultValue("PT5M") Duration crlRefreshInterval,
                               @DefaultValue("P7D") Duration devCrlValidity) {
        public TrustAnchors {
            mdocIaca = mdocIaca == null ? List.of() : List.copyOf(mdocIaca);
            if (devCrlValidity == null || devCrlValidity.compareTo(Duration.ofHours(1)) < 0) {
                throw new IllegalArgumentException("certify.pki.trust-anchors.dev-crl-validity must be at least PT1H, was "
                        + devCrlValidity);
            }
        }
    }

    /**
     * One IACA an operator trusts.
     *
     * @param id          optional; the URL-safe name of its downloads ({@code [a-z0-9][a-z0-9._-]{0,63}}). Unset, it is
     *                    the {@code <id>} of the IACA's own CRL distribution point when that is
     *                    {@code …/mdoc/iaca/<id>.crl}, else the IACA's subject key identifier in lower-case hex
     * @param certificate the IACA certificate, PEM or DER
     * @param crl         optional; the CRL the IACA signed, PEM or DER, re-read when the file changes
     */
    public record AnchorSpec(String id, Path certificate, Path crl) {
        public AnchorSpec {
            if (id != null && !id.isBlank() && !ID.matcher(id).matches()) {
                throw new IllegalArgumentException("certify.pki.trust-anchors.mdoc-iaca[].id '" + id + "' must be "
                        + ID_RULE + ": it names the /mdoc/iaca/<id>.pem, .der and .crl downloads");
            }
            if (certificate == null) {
                throw new IllegalArgumentException("certify.pki.trust-anchors.mdoc-iaca[].certificate is required");
            }
        }
    }

    /** @param enabled serve {@code GET /mdoc/iaca} and {@code /mdoc/iaca/<id>.pem|.der|.crl} (M-08); off by default */
    public record Publication(@DefaultValue("false") boolean enabled) {}
}
