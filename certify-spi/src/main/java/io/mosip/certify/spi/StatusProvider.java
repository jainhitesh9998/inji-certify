package io.mosip.certify.spi;

/** Attaches a status entry to a credential before signing and applies later status updates. */
public interface StatusProvider {

    /** {@code BitstringStatusList}, {@code TokenStatusList}, ... */
    String mechanism();

    boolean supports(String format);

    UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context);

    void update(StatusUpdate update);

    record StatusUpdate(String credentialId, String purpose, boolean value, String reason) {}
}
