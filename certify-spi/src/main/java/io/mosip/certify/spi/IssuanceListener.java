package io.mosip.certify.spi;

import java.util.List;

/** Side effects of issuance (ledger, audit, QR/claim-169, notifications) as plugins, in registration order. */
public interface IssuanceListener {

    /**
     * Called before a template renders, for templated configurations only: the returned claim set is what the
     * template engine sees (extra model parameters, derived values); the default returns the claims unchanged.
     */
    default ClaimSet beforeRender(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        return claims;
    }

    default UnsignedCredential beforeSign(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        return credential;
    }

    default void onIssued(IssuanceEvent event) {}

    default void onFailed(IssuanceFailure failure) {}

    record IssuanceEvent(IssuanceContext context, CredentialConfiguration configuration, ClaimSet claims,
                         List<IssuedCredential> credentials, String transactionId) {}

    record IssuanceFailure(IssuanceContext context, CredentialConfiguration configuration, String errorCode, Throwable cause) {}
}
