package io.mosip.certify.golden;

import org.springframework.test.context.TestPropertySource;

/** {@link StatusListPostgresTest} with the compatibility path served by the new core: same list, same entries, same ledger rows. */
@TestPropertySource(properties = "certify.protocol.oid4vci-v1.compat-core.enabled=true")
class StatusListPostgresCoreTest extends StatusListPostgresTest {
}
