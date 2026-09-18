package io.mosip.certify.issuance;

/** The one operation every protocol adapter and the CLI call. */
public interface IssuanceService {

    IssuanceResult issue(IssuanceCommand command);

    /**
     * Renders and builds a credential for the configuration without attaching status, running the pre-sign listeners
     * or signing: the dry run behind the configuration API's preview.
     */
    default io.mosip.certify.spi.UnsignedCredential preview(io.mosip.certify.spi.CredentialConfiguration configuration, io.mosip.certify.spi.ClaimSet claims,
                                                            io.mosip.certify.spi.IssuanceContext context, io.mosip.certify.spi.HolderBinding holder) {
        throw new UnsupportedOperationException("preview is not supported by " + getClass().getName());
    }
}
