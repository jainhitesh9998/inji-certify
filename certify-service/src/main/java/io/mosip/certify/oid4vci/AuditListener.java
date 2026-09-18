package io.mosip.certify.oid4vci;

import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.spi.IssuanceListener;
import org.springframework.stereotype.Component;

/** The audit entries the legacy issuance wrote per request: {@code VC_ISSUANCE} success or error, keyed by the access token hash. */
@Component
public class AuditListener implements IssuanceListener {

    static final String ID_TYPE = "accessTokenHash";

    private final AuditPlugin auditPlugin;

    public AuditListener(AuditPlugin auditPlugin) {
        this.auditPlugin = auditPlugin;
    }

    @Override
    public void onIssued(IssuanceEvent event) {
        auditPlugin.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS, AuditHelper.buildAuditDto(tokenHash(event.context()), ID_TYPE), null);
    }

    @Override
    public void onFailed(IssuanceFailure failure) {
        auditPlugin.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR, AuditHelper.buildAuditDto(tokenHash(failure.context()), ID_TYPE),
                failure.cause() instanceof Throwable t ? t : null);
    }

    private static String tokenHash(io.mosip.certify.spi.IssuanceContext context) {
        return context == null || context.authorization() == null ? null : context.authorization().tokenHash();
    }
}
