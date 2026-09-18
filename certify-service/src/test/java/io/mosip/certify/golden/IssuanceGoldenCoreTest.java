package io.mosip.certify.golden;

import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.oid4vci.compat.CoreBackedVCIssuanceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every v1 golden of {@link IssuanceGoldenTest}, with the compatibility path {@code POST /issuance/credential} served
 * by the new core ({@code certify.protocol.oid4vci-v1.compat-core.enabled=true}): the same request must produce the
 * same normalised bytes on every signing path, including status, QR and the legacy suites.
 */
@TestPropertySource(properties = "certify.protocol.oid4vci-v1.compat-core.enabled=true")
class IssuanceGoldenCoreTest extends IssuanceGoldenTest {

    @Autowired VCIssuanceService vcIssuanceService;

    @Test
    void compatibilityPathIsServedByTheCore() {
        assertTrue(vcIssuanceService instanceof CoreBackedVCIssuanceService, "the controller's service must be the core-backed one: " + vcIssuanceService.getClass());
    }
}
