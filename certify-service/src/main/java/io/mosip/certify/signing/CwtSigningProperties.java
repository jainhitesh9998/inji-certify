package io.mosip.certify.signing;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Validity of the claim-169 CWTs Certify signs (docs/design/14-configuration.md). The defaults are the ones
 * keymanager applied (`mosip.kernel.keymanager.signature.cwt.exp` 180 days, `nbf` 0 days); no Certify deployment
 * configured those keys, so they get no alias.
 *
 * @param expDays days from signing until {@code exp}
 * @param nbfDays days from signing until {@code nbf}
 */
@ConfigurationProperties(prefix = "certify.signing.cwt")
public record CwtSigningProperties(@DefaultValue("180") int expDays, @DefaultValue("0") int nbfDays) {}
