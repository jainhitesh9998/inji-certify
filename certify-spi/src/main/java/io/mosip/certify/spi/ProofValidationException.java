package io.mosip.certify.spi;

/** A proof was rejected; {@code errorCode} is the protocol error ({@code invalid_proof}, {@code invalid_nonce}). */
public class ProofValidationException extends Exception {
    private final String errorCode;

    public ProofValidationException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() { return errorCode; }
}
