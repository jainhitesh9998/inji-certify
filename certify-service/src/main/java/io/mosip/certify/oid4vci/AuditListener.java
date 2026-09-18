package io.mosip.certify.oid4vci;

import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * The audit entries the legacy issuance services wrote per request, keyed by the access token hash:
 * {@code PROOF_VALIDATION} success once every proof passed (error when a proof or its nonce failed) and
 * {@code VC_ISSUANCE} success or error. {@code NONCE_VALIDATION}, which the legacy services wrote per proof with the
 * nonce value, has no core hook yet and is not written on the core path.
 */
@Component
public class AuditListener implements IssuanceListener {

    static final String ID_TYPE = "accessTokenHash";
    static final Set<String> PROOF_FAILURES = Set.of(IssuanceException.INVALID_PROOF, IssuanceException.INVALID_NONCE);

    private final AuditPlugin auditPlugin;

    public AuditListener(AuditPlugin auditPlugin) {
        this.auditPlugin = auditPlugin;
    }

    @Override
    public void onIssued(IssuanceEvent event) {
        String tokenHash = tokenHash(event.context());
        auditPlugin.logAudit(Action.PROOF_VALIDATION, ActionStatus.SUCCESS, AuditHelper.buildAuditDto(tokenHash, ID_TYPE), null);
        auditPlugin.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS, AuditHelper.buildAuditDto(tokenHash, ID_TYPE), null);
    }

    @Override
    public void onFailed(IssuanceFailure failure) {
        Throwable cause = failure.cause() instanceof Throwable t ? t : null;
        Action action = failure.errorCode() != null && PROOF_FAILURES.contains(failure.errorCode()) ? Action.PROOF_VALIDATION : Action.VC_ISSUANCE;
        auditPlugin.logAudit(action, ActionStatus.ERROR, AuditHelper.buildAuditDto(tokenHash(failure.context()), ID_TYPE), cause);
    }

    private static String tokenHash(IssuanceContext context) {
        return context == null || context.authorization() == null ? null : context.authorization().tokenHash();
    }
}
