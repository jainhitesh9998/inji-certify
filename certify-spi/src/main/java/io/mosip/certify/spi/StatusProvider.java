package io.mosip.certify.spi;

/** Attaches a status entry to a credential before signing and applies later status updates. */
public interface StatusProvider {

    /** {@code BitstringStatusList}, {@code TokenStatusList}, ... */
    String mechanism();

    boolean supports(String format);

    UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context);

    void update(StatusUpdate update);

    record StatusUpdate(String credentialId, String purpose, boolean value, String reason) {}

    /**
     * As {@link #attach(UnsignedCredential, CredentialConfiguration, IssuanceContext)}, told what the credential will be
     * signed with and how its format wants its status list carried (M-11e).
     *
     * <p>A status list of {@code mso_mdoc} must be signed by the Document Signer that signs the mDLs indexed in it — the
     * token's {@code x5chain} then equals the mDL's IssuerAuth {@code x5chain}, which is what Credo and Paradym require
     * — and ISO/IEC 18013-5 second edition 12.3.6.3 makes it a CWT rather than a JWT. So a provider that makes that
     * choice needs to know, before it allocates an index, which key will sign the credential and which status-list token
     * format the credential's own format asks for. Resolving the key before the status step also means an unusable
     * signing key fails without consuming an index.
     *
     * <p>The default method delegates to {@link #attach(UnsignedCredential, CredentialConfiguration, IssuanceContext)}:
     * every provider written before M-11e keeps working unchanged, and one that has nothing format-specific to do is
     * never forced to look at the binding.
     *
     * @param binding the signing context this credential will be signed with, and {@link
     *                CredentialFormatter#statusListTokenFormat()}
     */
    default UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration,
                                     IssuanceContext context, StatusBinding binding) {
        return attach(credential, configuration, context);
    }

    /**
     * What a status entry is attached for (M-11e).
     *
     * @param signing               the resolved signing context the credential itself is signed with: the Document
     *                              Signer of an {@code mso_mdoc}, whose certificate a status list for it must be
     *                              signed by and pinned to
     * @param statusListTokenFormat how this credential's format carries a status list, from the formatter:
     *                              {@code jwt} (a Token Status List JWT, the default) or {@code cwt} (a CWT Status List
     *                              Token, {@code mso_mdoc}; ISO/IEC 18013-5 second edition 12.3.6.3). A token format is
     *                              not a credential format: only a formatter module decides that its credentials want
     *                              CWT.
     */
    record StatusBinding(SigningContext signing, String statusListTokenFormat) {}
}
