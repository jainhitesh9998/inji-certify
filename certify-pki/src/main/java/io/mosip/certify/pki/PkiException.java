package io.mosip.certify.pki;

/**
 * A certificate-profile operation failed: a builder was given invalid input, a certificate or CSR cannot be parsed,
 * or a signing key does not fit the ISO/IEC 18013-5:2021 Annex B profile. The message starts with a stable rule
 * identifier where one applies, so callers can map a failure to a named refusal.
 */
public class PkiException extends RuntimeException {

    public PkiException(String message) {
        super(message);
    }

    public PkiException(String message, Throwable cause) {
        super(message, cause);
    }
}
