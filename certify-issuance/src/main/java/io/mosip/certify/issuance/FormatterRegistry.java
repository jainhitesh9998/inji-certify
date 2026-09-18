package io.mosip.certify.issuance;

import io.mosip.certify.spi.CredentialFormatter;

import java.util.List;
import java.util.Optional;

/** Finds the formatter for a format id or one of its aliases; the only place a format string is matched. */
public class FormatterRegistry {

    private final List<CredentialFormatter> formatters;

    public FormatterRegistry(List<CredentialFormatter> formatters) {
        this.formatters = List.copyOf(formatters);
    }

    public Optional<CredentialFormatter> forFormat(String format) {
        return formatters.stream().filter(f -> f.handles(format)).findFirst();
    }

    public CredentialFormatter require(String format) {
        return forFormat(format).orElseThrow(() -> new IssuanceException(IssuanceException.UNSUPPORTED_CREDENTIAL_FORMAT,
                "No formatter for format " + format));
    }

    public List<CredentialFormatter> all() {
        return formatters;
    }
}
