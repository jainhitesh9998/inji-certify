package io.mosip.certify.oid4vci;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the OpenID4VCI 1.0 adapter (docs/design/14-configuration.md). {@code compat-core.enabled} routes the
 * compatibility path {@code POST /issuance/credential} through the new core instead of the legacy issuance service;
 * off until the v1 goldens prove both modes on CI, then the default flips and the legacy service is removed.
 */
@ConfigurationProperties(prefix = "certify.protocol.oid4vci-v1")
public record Oid4vciV1Properties(@DefaultValue CompatCore compatCore, @DefaultValue Notification notification) {

    public static final String COMPAT_CORE_PREFIX = "certify.protocol.oid4vci-v1.compat-core";

    public record CompatCore(@DefaultValue("false") boolean enabled) {}

    /**
     * How long an issuance transaction stays open for the wallet's notification ({@code retention}) and how often
     * expired rows are purged ({@code purge-interval}, read by the housekeeping schedule).
     */
    public record Notification(@DefaultValue("P1D") java.time.Duration retention,
                               @DefaultValue("PT1H") java.time.Duration purgeInterval) {}
}
