package io.mosip.certify.signing;

/** Any failure inside the signing library or a key provider. */
public class SigningException extends RuntimeException {
    public SigningException(String message) { super(message); }
    public SigningException(String message, Throwable cause) { super(message, cause); }
}
