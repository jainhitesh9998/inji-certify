package io.mosip.certify.status;

/**
 * A CWT status list whose signer certificate has expired and whose own {@code exp} has passed: it is retired
 * (docs/design/wp/M-11-status-list-under-iaca.md section 4.3; owner decision D-M11-7), so the endpoint answers
 * {@code 410 Gone} without {@code Retry-After} — asking again cannot help, because every mDL that indexed the list has
 * expired too and the list is never signed by another certificate (Credo accepts an mDL's list only when the list's
 * validated chain equals the mDL's issuance chain).
 *
 * <p>Deliberately not a {@link TokenStatusListUnavailableException}: that one is the 503 the endpoint answers when a
 * list could be served later.
 */
public class TokenStatusListGoneException extends IllegalStateException {

    public TokenStatusListGoneException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenStatusListGoneException(String message) {
        super(message);
    }
}
