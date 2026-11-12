package io.mosip.certify.format.mdoc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * MSO settings (docs/design/14-configuration.md). The defaults are the values {@code mosip.certify.mdoc.*} carried
 * in certify-service; those keys keep working there for the legacy path.
 *
 * @param digestAlgorithm      the MSO digest algorithm, one of {@code SHA-256}, {@code SHA-384}, {@code SHA-512}
 *                             (ISO/IEC 18013-5 9.1.2.4); the same algorithm computes and declares the digests
 * @param msoVersion           {@code version} of the MSO (9.1.2.4); ISO/IEC 18013-5 defines only {@code "1.0"}
 * @param msoValidity          how long the MSO claims the document is valid, capped at the DSC {@code notAfter} and an
 *                             mDL's {@code expiry_date} (docs/design/20-mdl-issuer.md D7); at least one minute, because
 *                             {@code tdate} carries whole seconds only and a shorter span could encode a
 *                             {@code validUntil} equal to {@code signed}; when unset {@link #validity()} applies P90D
 * @param validityPeriodYears  the pre-D7 setting ({@code certify.format.mdoc.validity-period-years}); kept as an
 *                             alias so an existing deployment needs no change. It is only a fallback: an explicitly
 *                             configured {@code mso-validity} wins over it
 */
@ConfigurationProperties(prefix = "certify.format.mdoc")
public record MdocProperties(@DefaultValue("SHA-256") String digestAlgorithm, @DefaultValue("1.0") String msoVersion,
                             Duration msoValidity, Integer validityPeriodYears) {

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
