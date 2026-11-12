package io.mosip.certify.datasource.file;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * {@code certify.datasource.file.*} (docs/design/14-configuration.md, docs/design/20-mdl-issuer.md M-10): JSON files as
 * credential data sources. Every entry under {@code sources} registers one {@link FileCredentialDataSource} whose
 * {@link io.mosip.certify.spi.CredentialDataSource#id()} is the entry's key, so a credential configuration selects it
 * with {@code dataSourceId}. With no entry the feature is off and no data source is registered.
 */
@ConfigurationProperties(prefix = FileDataSourceProperties.PREFIX)
public record FileDataSourceProperties(@DefaultValue Map<String, Source> sources) {

    public static final String PREFIX = "certify.datasource.file";
    /** The authorization claim whose value selects the record, when a source names none. */
    public static final String DEFAULT_KEY_CLAIM = "sub";

    public FileDataSourceProperties {
        sources = sources == null ? Map.of() : Map.copyOf(sources);
    }

    public boolean enabled() {
        return !sources.isEmpty();
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
    public record Source(Path path, @DefaultValue(DEFAULT_KEY_CLAIM) String keyClaim,
                         @DefaultValue List<String> binaryFields) {

        public Source {
            binaryFields = binaryFields == null ? List.of() : List.copyOf(binaryFields);
        }
    }
}
