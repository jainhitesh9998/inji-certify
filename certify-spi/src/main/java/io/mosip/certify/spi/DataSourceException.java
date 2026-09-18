package io.mosip.certify.spi;

/** A data source or external issuer could not produce data; {@code errorCode} maps to the protocol error. */
public class DataSourceException extends Exception {
    private final String errorCode;

    public DataSourceException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public DataSourceException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() { return errorCode; }
}
