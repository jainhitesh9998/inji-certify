package io.mosip.certify.keyprovider.keymanager;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Settings of the keymanager provider itself (docs/design/14-configuration.md). Keymanager's own
 * {@code mosip.kernel.keymanager.*} keys are untouched.
 *
 * @param certificateCacheTtl how long certificates read from keymanager are reused before re-reading; a key
 *                            rotated in keymanager becomes the signing key within this time
 */
@ConfigurationProperties(prefix = "certify.keyprovider.keymanager")
public record KeymanagerProviderProperties(@DefaultValue("PT60S") Duration certificateCacheTtl) {}
