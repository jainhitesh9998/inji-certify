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
 * @param msoVersion           {@code version} of the MSO (9.1.2.4)
 * @param msoValidity          how long the MSO claims the document is valid, capped at the DSC {@code notAfter}
 *                             (docs/design/20-mdl-issuer.md D7)
 * @param validityPeriodYears  the pre-D7 setting ({@code certify.format.mdoc.validity-period-years}); kept as an
 *                             alias so an existing deployment needs no change, ignored when {@code mso-validity} is set
 */
@ConfigurationProperties(prefix = "certify.format.mdoc")
public record MdocProperties(@DefaultValue("SHA-256") String digestAlgorithm, @DefaultValue("1.0") String msoVersion,
                             @DefaultValue("P90D") Duration msoValidity, Integer validityPeriodYears) {

    /** The validity span to apply: {@code mso-validity}, or the legacy {@code validity-period-years} when that is set. */
    public Duration validity() {
        return validityPeriodYears == null ? (msoValidity == null ? Duration.ofDays(90) : msoValidity)
                : Duration.ofDays(365L * validityPeriodYears);
    }
}
