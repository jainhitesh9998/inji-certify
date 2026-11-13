package io.mosip.certify.format.mdoc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * MSO settings (docs/design/14-configuration.md). The 1.0.0-beta.1 keys {@code mosip.certify.mdoc.digest-algorithm}
 * and {@code mosip.certify.mdoc.validity-period-years} (certify-service {@code MDocConfig}) are aliases (CLAUDE.md
 * rule 9): {@link #withLegacyFallback} applies them when the {@code certify.format.mdoc.*} key is not set, so an
 * existing deployment keeps its digest algorithm and validity on the refactored formatter without a change.
 *
 * @param digestAlgorithm      the MSO digest algorithm, one of {@code SHA-256}, {@code SHA-384}, {@code SHA-512}
 *                             (ISO/IEC 18013-5 9.1.2.4); the same algorithm computes and declares the digests;
 *                             precedence {@code certify.format.mdoc.digest-algorithm} &gt;
 *                             {@code mosip.certify.mdoc.digest-algorithm} &gt; {@code SHA-256}
 * @param msoVersion           {@code version} of the MSO (9.1.2.4); ISO/IEC 18013-5 defines only {@code "1.0"}
 * @param msoValidity          how long the MSO claims the document is valid, capped at the DSC {@code notAfter} and an
 *                             mDL's {@code expiry_date} (docs/design/20-mdl-issuer.md D7); at least one minute, because
 *                             {@code tdate} carries whole seconds only and a shorter span could encode a
 *                             {@code validUntil} equal to {@code signed}; when unset {@link #validity()} applies P90D
 * @param validityPeriodYears  the pre-D7 setting ({@code certify.format.mdoc.validity-period-years}); only a
 *                             fallback. Precedence: {@code certify.format.mdoc.mso-validity} &gt;
 *                             {@code certify.format.mdoc.validity-period-years} &gt;
 *                             {@code mosip.certify.mdoc.validity-period-years} &gt; P90D
 */
@ConfigurationProperties(prefix = "certify.format.mdoc")
public record MdocProperties(String digestAlgorithm, @DefaultValue("1.0") String msoVersion,
                             Duration msoValidity, Integer validityPeriodYears) {

    static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";
    private static final Duration DEFAULT_VALIDITY = Duration.ofDays(90);
    /** The shortest {@code mso-validity} accepted: whole-second {@code tdate}s must leave {@code validUntil} after {@code signed}. */
    static final Duration MINIMUM_VALIDITY = Duration.ofMinutes(1);

    public MdocProperties {
        if (msoVersion == null || !"1.0".equals(msoVersion)) {
            throw new IllegalArgumentException("certify.format.mdoc.mso-version must be \"1.0\" (ISO/IEC 18013-5 9.1.2.4), was "
                    + msoVersion);
        }
        if (msoValidity != null && msoValidity.compareTo(MINIMUM_VALIDITY) < 0) {
            throw new IllegalArgumentException("certify.format.mdoc.mso-validity must be at least " + MINIMUM_VALIDITY
                    + " (ISO/IEC 18013-5 9.1.2.4 tdates carry whole seconds; validUntil must be after signed), was " + msoValidity);
        }
        if (validityPeriodYears != null && validityPeriodYears <= 0) {
            throw new IllegalArgumentException("certify.format.mdoc.validity-period-years must be positive, was " + validityPeriodYears);
        }
    }

    /** The configured digest algorithm, {@code SHA-256} when neither key nor alias sets one. */
    @Override
    public String digestAlgorithm() {
        return digestAlgorithm == null ? DEFAULT_DIGEST_ALGORITHM : digestAlgorithm;
    }

    /** Whether a digest algorithm was set, as opposed to the {@code SHA-256} default. */
    boolean digestAlgorithmConfigured() {
        return digestAlgorithm != null;
    }

    /**
     * These properties with the 1.0.0-beta.1 {@code mosip.certify.mdoc.*} aliases applied where the
     * {@code certify.format.mdoc.*} key is unset (CLAUDE.md rule 9).
     *
     * @param legacyValidityPeriodYears {@code mosip.certify.mdoc.validity-period-years}, or null when unset
     * @param legacyDigestAlgorithm     {@code mosip.certify.mdoc.digest-algorithm}, or null when unset
     */
    public MdocProperties withLegacyFallback(Integer legacyValidityPeriodYears, String legacyDigestAlgorithm) {
        if (legacyValidityPeriodYears != null && legacyValidityPeriodYears <= 0) {
            throw new IllegalArgumentException("mosip.certify.mdoc.validity-period-years must be positive, was "
                    + legacyValidityPeriodYears);
        }
        String digest = digestAlgorithm != null ? digestAlgorithm : legacyDigestAlgorithm;
        Integer years = msoValidity == null && validityPeriodYears == null ? legacyValidityPeriodYears : validityPeriodYears;
        return new MdocProperties(digest, msoVersion, msoValidity, years);
    }

    /**
     * The validity span to apply: an explicitly configured {@code mso-validity} first, then the deprecated
     * {@code validity-period-years}, then the P90D default (D7).
     */
    public Duration validity() {
        if (msoValidity != null) {
            return msoValidity;
        }
        if (validityPeriodYears != null) {
            return Duration.ofDays(365L * validityPeriodYears);
        }
        return DEFAULT_VALIDITY;
    }
}
