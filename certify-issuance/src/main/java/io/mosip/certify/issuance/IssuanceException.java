package io.mosip.certify.issuance;

/** The core refused or failed a command; {@code errorCode} is protocol-agnostic and adapters map it to their wire errors. */
public class IssuanceException extends RuntimeException {

    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
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
