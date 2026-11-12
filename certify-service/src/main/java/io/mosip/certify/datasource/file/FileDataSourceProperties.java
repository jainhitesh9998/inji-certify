package io.mosip.certify.datasource.file;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * {@code certify.datasource.file.*} (docs/design/14-configuration.md, docs/design/20-mdl-issuer.md M-10): JSON files as
 * credential data sources. Every entry under {@code sources} registers one {@link FileCredentialDataSource} whose
 * {@link io.mosip.certify.spi.CredentialDataSource#id()} is the entry's key, so a credential configuration selects it
 * with {@code dataSourceId}. With no entry the feature is off and no data source is registered.
 *
 * <p>{@code path} is validated here, so a missing value fails startup instead of the first request; the file's
 * existence, JSON shape, size and binary-field paths are validated by the data source itself when it is built, because
 * only it knows the record and field a bad value belongs to.</p>
 */
@Validated
@ConfigurationProperties(prefix = FileDataSourceProperties.PREFIX)
public record FileDataSourceProperties(@DefaultValue Map<String, @Valid Source> sources) {

    public static final String PREFIX = "certify.datasource.file";
    /** The authorization claim whose value selects the record, when a source names none. */
    public static final String DEFAULT_KEY_CLAIM = "sub";

    public FileDataSourceProperties {
        sources = sources == null ? Map.of() : Map.copyOf(sources);
    }

    /**
     * One configured file.
     *
     * @param path         the JSON file: a single object whose keys are the values of {@code keyClaim}, each value
     *                     holding one subject's fields; a relative path is resolved against the working directory
     * @param keyClaim     the authorization claim (default {@code sub}) whose value is looked up in the file
     * @param binaryFields record fields whose value is a file path relative to the JSON file's directory; the bytes are
     *                     read once at startup and served as base64url without padding (an mDoc {@code bstr})
     */
    public record Source(@NotNull Path path, @DefaultValue(DEFAULT_KEY_CLAIM) String keyClaim,
                         @DefaultValue List<String> binaryFields) {

        public Source {
            binaryFields = binaryFields == null ? List.of() : List.copyOf(binaryFields);
        }
    }
}
