package io.mosip.certify.oid4vci;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the OpenID4VCI 1.0 adapter (docs/design/14-configuration.md). {@code compat-core.enabled} routes the
 * compatibility path {@code POST /issuance/credential} through the new core instead of the legacy issuance service;
 * off until the v1 goldens prove both modes on CI, then the default flips and the legacy service is removed.
 */
@ConfigurationProperties(prefix = "certify.protocol.oid4vci-v1")
public record Oid4vciV1Properties(@DefaultValue CompatCore compatCore, @DefaultValue Notification notification,
                                  @DefaultValue Nonce nonce, @DefaultValue Batch batch) {

    public static final String COMPAT_CORE_PREFIX = "certify.protocol.oid4vci-v1.compat-core";

    public record CompatCore(@DefaultValue("false") boolean enabled) {}

    /**
     * How long an issuance transaction stays open for the wallet's notification ({@code retention}) and how often
     * expired rows are purged ({@code purge-interval}, read by the housekeeping schedule).
     */
    public record Notification(@DefaultValue("P1D") java.time.Duration retention,
                               @DefaultValue("PT1H") java.time.Duration purgeInterval) {}

    /** {@code single-use}: a c_nonce from the nonce endpoint is consumed by the credential request it authorised. */
    public record Nonce(@DefaultValue("true") boolean singleUse) {}

    /**
     * {@code size}: the largest {@code proofs} array a credential request may carry (one credential per proof),
     * advertised as {@code batch_credential_issuance.batch_size} when above 1.
     */
    public record Batch(@DefaultValue("10") int size) {}
}
