package io.mosip.certify.as;

/** An OAuth error answered by the authorization server endpoints as {@code {error, error_description}} with an HTTP status. */
public class AsException extends RuntimeException {

    private final int status;
    private final String error;

    public AsException(int status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }
}
