package io.mosip.certify.format.sdjwt;

import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SdJwtHeaderPolicyTest {

    static IssuanceContext context(ProtocolVersion protocol, Map<String, Object> params) {
        return new IssuanceContext(TenantContext.DEFAULT, null, List.of(), protocol, "c", Instant.EPOCH, params);
    }

    @Test
    void typFollowsTheDraft13RequestOnlyForVcSdJwt() {
        assertEquals("dc+sd-jwt", SdJwtFormatter.headerPolicy(null).typ());
        assertEquals("dc+sd-jwt", SdJwtFormatter.headerPolicy(context(ProtocolVersion.OID4VCI_1_0, Map.of(SdJwtFormatter.PARAM_REQUESTED_FORMAT, "vc+sd-jwt"))).typ());
        assertEquals("dc+sd-jwt", SdJwtFormatter.headerPolicy(context(ProtocolVersion.OID4VCI_D13, Map.of(SdJwtFormatter.PARAM_REQUESTED_FORMAT, "dc+sd-jwt"))).typ());
        assertEquals("vc+sd-jwt", SdJwtFormatter.headerPolicy(context(ProtocolVersion.OID4VCI_D13, Map.of(SdJwtFormatter.PARAM_REQUESTED_FORMAT, "vc+sd-jwt"))).typ());
    }
}
