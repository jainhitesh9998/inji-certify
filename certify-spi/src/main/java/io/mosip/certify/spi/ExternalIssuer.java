package io.mosip.certify.spi;

/**
 * Produces a complete, signed credential outside Certify (successor of {@code VCIssuancePlugin});
 * the core still validates proofs, applies listeners and returns the result through the adapter.
 */
public interface ExternalIssuer {

    String id();

    IssuedCredential issue(IssuanceContext context, CredentialConfiguration configuration, HolderBinding holder) throws DataSourceException;
}
