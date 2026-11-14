package io.mosip.certify.spi;

import java.util.Objects;

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
     * never forced to look at the binding. A binding is required: a caller that has one passes it, and a caller that
     * has nothing to bind calls the three-argument method, so the default method refuses {@code null} rather than
     * binding silently to nothing.
     *
     * @param binding the signing context this credential will be signed with, and {@link
     *                CredentialFormatter#statusListTokenFormat()}; never {@code null}
     */
    default UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration,
                                     IssuanceContext context, StatusBinding binding) {
        Objects.requireNonNull(binding, "binding: an attach that is told what the credential is signed with"
                + " cannot be called with no binding; implement the three-argument attach instead");
        return attach(credential, configuration, context);
    }

    /**
     * Gives back the status entry {@link #attach} took for a credential that was never issued (M-11e, owner decision
     * D-M11e-1). The core calls it when anything after the attachment fails — a listener, the format's own signing
     * policy, the signature — so a failed request does not retire an index no wallet can ever reference.
     *
     * <p>{@code credential} is the credential exactly as {@link #attach} returned it, so a provider reads its own entry
     * out of it; a provider whose attachment is not an index (or taken from a pool it must not hand back) leaves this
     * default in place and nothing is released. Releasing is best effort: the core logs a provider's failure and answers
     * the request with the failure that made it give the index back.
     */
    default void release(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
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
