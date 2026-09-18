package io.mosip.certify.format.mdoc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * MSO settings (docs/design/14-configuration.md). The defaults are the values {@code mosip.certify.mdoc.*} carried
 * in certify-service; those keys keep working there for the legacy path.
 */
@ConfigurationProperties(prefix = "certify.format.mdoc")
public record MdocProperties(@DefaultValue("SHA-256") String digestAlgorithm, @DefaultValue("1.0") String msoVersion,
                             @DefaultValue("2") int validityPeriodYears) {}
