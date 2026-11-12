package io.mosip.certify.issuance;

/** The core refused or failed a command; {@code errorCode} is protocol-agnostic and adapters map it to their wire errors. */
public class IssuanceException extends RuntimeException {

    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
    /**
     * OpenID4VCI 1.0 section 8.3.1.2: the request is well formed but the issuer will not issue this credential to this
     * subject (no data for it, say). Distinct from {@link #INVALID_CREDENTIAL_REQUEST}, which names a malformed request,
     * and from {@link #ISSUANCE_FAILED}, which the adapters answer with a 500. Draft 13 has no such code, so the
     * draft-13 adapter maps it to {@code invalid_credential_request}.
     */
    public static final String CREDENTIAL_REQUEST_DENIED = "credential_request_denied";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String UNSUPPORTED_CREDENTIAL_FORMAT = "unsupported_credential_format";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String INVALID_PROOF = "invalid_proof";
    public static final String INVALID_NONCE = "invalid_nonce";
    public static final String NOT_AUTHENTICATED = "invalid_token";
    public static final String ISSUANCE_FAILED = "credential_issuance_failed";

    private final String errorCode;

    public IssuanceException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public IssuanceException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() { return errorCode; }
}
