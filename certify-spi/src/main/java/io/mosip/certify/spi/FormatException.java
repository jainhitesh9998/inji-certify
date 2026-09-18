package io.mosip.certify.spi;

/** A configuration or document violates the format's rules; {@code errorCode} names the rule. */
public class FormatException extends RuntimeException {
    private final String errorCode;

    public FormatException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public FormatException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() { return errorCode; }
}
