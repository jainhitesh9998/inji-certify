package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.services.CredentialLedgerServiceImpl;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.utils.LedgerUtils;
import org.json.JSONObject;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * The ledger entry the legacy issuance writes per issued {@code ldp_vc} ({@code mosip.certify.issuer.ledger-enabled}):
 * credential id, issuer DID, credential type, the status entry and the indexed attributes taken from the data the
 * plugin returned (kept by {@link DataProviderPluginDataSource} in the claim set's provenance).
 */
@Component
public class LedgerListener implements IssuanceListener {

    private final CredentialLedgerServiceImpl ledger;
    private final LedgerUtils ledgerUtils;
    private final boolean enabled;

    public LedgerListener(CredentialLedgerServiceImpl ledger, LedgerUtils ledgerUtils, Environment environment) {
        this.ledger = ledger;
        this.ledgerUtils = ledgerUtils;
        this.enabled = environment.getProperty("mosip.certify.issuer.ledger-enabled", Boolean.class, true);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onIssued(IssuanceEvent event) {
        if (!enabled) {
            return;
        }
        for (IssuedCredential credential : event.credentials()) {
            if (!"ldp_vc".equals(credential.format()) || !(credential.credential() instanceof Map<?, ?> map)) {
                continue;
            }
            Map<String, Object> document = (Map<String, Object>) map;
            Object data = event.claims() == null ? null : event.claims().provenance().get(DataProviderPluginDataSource.PROVENANCE_DATA);
            JSONObject source = new JSONObject(data instanceof Map<?, ?> m ? (Map<String, Object>) m : document);
            Map<String, Object> indexedAttributes = ledgerUtils.extractIndexedAttributes(source);
            CredentialStatusDetail statusDetail = ledgerUtils.extractCredentialStatusDetails(new JSONObject(document));
            Object credentialType = event.configuration().formatConfig() == null ? null : event.configuration().formatConfig().raw().get("credentialType");
            ledger.storeLedgerEntry(credential.credentialId(), event.configuration().signing().issuerDid(),
                    credentialType == null ? null : credentialType.toString(), statusDetail, indexedAttributes,
                    LocalDateTime.ofInstant(event.context().now(), ZoneOffset.UTC));
        }
    }
}
