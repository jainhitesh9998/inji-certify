package io.mosip.certify.cli;

/**
 * An invocation the CLI cannot act on: a missing or conflicting option, a value that does not parse, two options that
 * name the same file, a missing password. Commands exit {@code 1} for it, as picocli does for its own parameter errors;
 * a refusal of a well-formed request (an Annex B violation, an existing alias, a CRL number that does not increase)
 * exits {@code 2}.
 */
final class UsageException extends RuntimeException {

    UsageException(String message) {
        super(message);
    }
}
