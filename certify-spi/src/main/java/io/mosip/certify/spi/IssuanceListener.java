package io.mosip.certify.spi;

import java.util.List;

/** Side effects of issuance (ledger, audit, QR/claim-169, notifications) as plugins, in registration order. */
public interface IssuanceListener {

    default UnsignedCredential beforeSign(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        return credential;
    }

    default void onIssued(IssuanceEvent event) {}

    default void onFailed(IssuanceFailure failure) {}

    record IssuanceEvent(IssuanceContext context, CredentialConfiguration configuration, ClaimSet claims,
                         List<IssuedCredential> credentials, String transactionId) {}

    record IssuanceFailure(IssuanceContext context, CredentialConfiguration configuration, String errorCode, Throwable cause) {}
}
