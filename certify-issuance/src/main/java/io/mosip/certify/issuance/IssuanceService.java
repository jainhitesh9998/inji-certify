package io.mosip.certify.issuance;

/** The one operation every protocol adapter and the CLI call. */
public interface IssuanceService {

    IssuanceResult issue(IssuanceCommand command);
}
