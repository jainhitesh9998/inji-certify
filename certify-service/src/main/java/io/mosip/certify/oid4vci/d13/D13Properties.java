package io.mosip.certify.oid4vci.d13;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the draft-13 compatibility adapter (docs/design/14-configuration.md): on by default, the versioned
 * {@code /issuance/vd11/credential} and {@code /issuance/vd12/credential} paths on by default.
 */
@ConfigurationProperties(prefix = "certify.protocol.oid4vci-d13")
public record D13Properties(@DefaultValue("true") boolean enabled, @DefaultValue VersionedPaths versionedPaths) {

    public static final String PREFIX = "certify.protocol.oid4vci-d13";

    public record VersionedPaths(@DefaultValue("true") boolean enabled) {}
}
