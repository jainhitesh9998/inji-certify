package io.mosip.certify.status;

/**
 * A CWT status list whose pinned signer certificate is past its {@code notAfter}, so the list is retired rather than
 * signed again (docs/design/wp/M-11-status-list-under-iaca.md section 4.3; owner decision D-M11-7). Every mDL that
 * indexed this list has expired by then — an mDL never outlives its Document Signer — so retrying cannot help and
 * re-signing with a newer signer would break Credo's rule that a list's chain equals the mDL's issuance chain.
 *
 * <p>Extends {@link IllegalStateException} because it is decided where the other signer refusals are, but the service
 * tells it apart from them: no re-sign is attempted, the list is served as stored while its {@code exp} holds and
 * answered {@code 410 Gone} afterwards.
 */
public class StatusListRetiredException extends IllegalStateException {

    public StatusListRetiredException(String message) {
        super(message);
    }

    public StatusListRetiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
