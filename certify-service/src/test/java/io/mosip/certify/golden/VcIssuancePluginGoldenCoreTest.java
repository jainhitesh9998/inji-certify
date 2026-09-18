package io.mosip.certify.golden;

import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.oid4vci.compat.CoreBackedVCIssuanceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link VcIssuancePluginGoldenTest} with the compatibility path served by the core: the plugin is reached through {@code LegacyExternalIssuer}. */
@TestPropertySource(properties = "certify.protocol.oid4vci-v1.compat-core.enabled=true")
class VcIssuancePluginGoldenCoreTest extends VcIssuancePluginGoldenTest {

    @Autowired VCIssuanceService vcIssuanceService;

    @Test
    void compatibilityPathIsServedByTheCore() {
        assertTrue(vcIssuanceService instanceof CoreBackedVCIssuanceService, vcIssuanceService.getClass().getName());
    }
}
