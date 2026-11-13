package io.mosip.certify.signing;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * {@code certify.signing.key-expiry.*} (docs/design/14-configuration.md): the signing-key expiry report of M-05
 * ({@link SigningKeyExpiry}). New settings, so no aliases.
 *
 * @param warnDays          a current key expiring within this many days is logged at WARN
 * @param reconcileInterval delay between two reconciliations of the gauges with the providers, counted from the end of
 *                          the previous one; the first runs once the application is ready. Zero or negative turns the
 *                          periodic run off (the report at startup still runs)
 */
@ConfigurationProperties(prefix = "certify.signing.key-expiry")
public record SigningKeyExpiryProperties(@DefaultValue("30") int warnDays,
                                         @DefaultValue("PT1H") Duration reconcileInterval) {

    public static final SigningKeyExpiryProperties DEFAULTS = new SigningKeyExpiryProperties(30, Duration.ofHours(1));
}
