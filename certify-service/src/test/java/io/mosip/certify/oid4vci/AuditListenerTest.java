package io.mosip.certify.oid4vci;

import io.mosip.certify.api.dto.AuditDTO;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditListenerTest {

    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, new Authorization("bearer", Map.of(), "hash-1"), List.of(),
            ProtocolVersion.OID4VCI_1_0, "c", Instant.EPOCH, Map.of());

    @Test
    void issuedWritesProofValidationThenIssuanceSuccess() {
        AuditPlugin plugin = mock(AuditPlugin.class);
        new AuditListener(plugin).onIssued(new IssuanceListener.IssuanceEvent(CONTEXT, null, null, List.of(), "txn"));
        InOrder order = inOrder(plugin);
        ArgumentCaptor<AuditDTO> audit = ArgumentCaptor.forClass(AuditDTO.class);
        order.verify(plugin).logAudit(eq(Action.PROOF_VALIDATION), eq(ActionStatus.SUCCESS), audit.capture(), isNull());
        order.verify(plugin).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
        assertEquals("hash-1", audit.getValue().getTransactionId());
        assertEquals("accessTokenHash", audit.getValue().getIdType());
    }

    @Test
    void proofFailuresAuditAsProofValidationOtherFailuresAsIssuance() {
        AuditPlugin plugin = mock(AuditPlugin.class);
        AuditListener listener = new AuditListener(plugin);
        IssuanceException nonce = new IssuanceException(IssuanceException.INVALID_NONCE, "c_nonce is invalid or expired");
        listener.onFailed(new IssuanceListener.IssuanceFailure(CONTEXT, null, IssuanceException.INVALID_NONCE, nonce));
        verify(plugin).logAudit(eq(Action.PROOF_VALIDATION), eq(ActionStatus.ERROR), any(), eq(nonce));
        IssuanceException failed = new IssuanceException(IssuanceException.ISSUANCE_FAILED, "boom");
        listener.onFailed(new IssuanceListener.IssuanceFailure(CONTEXT, null, IssuanceException.ISSUANCE_FAILED, failed));
        verify(plugin).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.ERROR), any(), eq(failed));
        listener.onFailed(new IssuanceListener.IssuanceFailure(null, null, null, null));
        verify(plugin).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.ERROR), any(), isNull());
    }
}
