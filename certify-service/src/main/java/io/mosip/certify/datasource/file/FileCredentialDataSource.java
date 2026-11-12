package io.mosip.certify.datasource.file;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.IssuanceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CredentialDataSource} backed by one JSON file (docs/design/20-mdl-issuer.md M-10, decision D10).
 *
 * <p>The file holds a single JSON object whose keys are the values of {@code key-claim}; each value is that subject's
 * record and is returned, unchanged, as the template data map. The claim the request arrives with (the validated access
 * token claims) selects the record, so the file is read once at startup, validated there, and never touched per
 * request.</p>
 *
 * <p>Fields named in {@code binary-fields} hold a file path relative to the JSON file's directory; the file's bytes are
 * read at startup and the field is served as base64url without padding, the shape an mDoc {@code bstr} element (e.g.
 * {@code portrait}) takes from a Velocity template. Absolute paths and paths escaping the JSON directory with {@code ..}
 * are refused when the data source is built, as are missing files and malformed JSON, so a bad deployment fails at
 * startup with the file named instead of at the first credential request.</p>
 */
public final class FileCredentialDataSource implements CredentialDataSource {

    /** Provenance key naming the data source the claims came from, as {@code DataProviderPluginDataSource} does. */
    public static final String PROVENANCE_SOURCE = "source";
    /**
     * The core's code for "this credential request cannot be served for this subject" (OpenID4VCI
     * {@code invalid_credential_request}). The core maps a data source failure to an {@code IssuanceException} with the
     * same code, and every adapter answers it with 400; it must never be {@code credential_issuance_failed}, which the
     * adapters turn into a 500.
     */
    public static final String ERROR_NO_DATA = IssuanceException.INVALID_CREDENTIAL_REQUEST;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger log = LoggerFactory.getLogger(FileCredentialDataSource.class);
    private static final TypeReference<LinkedHashMap<String, Object>> RECORD = new TypeReference<>() {};

    private final String id;
    private final String keyClaim;
    private final Path file;
    private final Map<String, Map<String, Object>> records;

    /**
     * Loads and validates the file. Throws {@link IllegalStateException} with the source id, file and field in the
     * message when the file is missing, is not JSON, or a binary field's path is absolute, escapes the JSON file's
     * directory or names a missing file.
     */
    public FileCredentialDataSource(String id, FileDataSourceProperties.Source source) {
        if (id == null || id.isBlank()) {
            throw new IllegalStateException(FileDataSourceProperties.PREFIX + ".sources.<id>: every source needs an id");
        }
        Objects.requireNonNull(source, "source");
        if (source.path() == null) {
            throw new IllegalStateException("Data source '" + id + "': " + FileDataSourceProperties.PREFIX + ".sources." + id + ".path is required");
        }
        this.id = id;
        this.keyClaim = source.keyClaim() == null || source.keyClaim().isBlank()
                ? FileDataSourceProperties.DEFAULT_KEY_CLAIM : source.keyClaim();
        this.file = source.path().toAbsolutePath().normalize();
        this.records = load(source.binaryFields());
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public ClaimSet fetch(IssuanceContext context, CredentialConfiguration configuration) throws DataSourceException {
        Object subject = context.authorization().claims().get(keyClaim);
        if (subject == null || String.valueOf(subject).isBlank()) {
            throw new DataSourceException(ERROR_NO_DATA,
                    "No data in data source '" + id + "': the access token carries no '" + keyClaim + "' claim");
        }
        Map<String, Object> record = records.get(String.valueOf(subject));
        if (record == null) {
            throw new DataSourceException(ERROR_NO_DATA, "No data in data source '" + id + "' for '" + keyClaim + "'");
        }
        return new ClaimSet(new LinkedHashMap<>(record), Map.of(PROVENANCE_SOURCE, id));
    }

    /** The claim the record is looked up by. */
    public String keyClaim() {
        return keyClaim;
    }

    /** The file this source serves, for startup logs and diagnostics. */
    public Path file() {
        return file;
    }

    private Map<String, Map<String, Object>> load(List<String> binaryFields) {
        if (!Files.isRegularFile(file)) {
            throw new IllegalStateException("Data source '" + id + "': " + file + " does not exist or is not a file");
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(file.toFile());
        } catch (IOException e) {
            throw new IllegalStateException("Data source '" + id + "': " + file + " is not readable JSON: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new IllegalStateException("Data source '" + id + "': " + file
                    + " must hold one JSON object whose keys are the '" + keyClaim + "' values");
        }
        Path directory = file.getParent();
        Map<String, Map<String, Object>> loaded = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> entries = root.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            String key = entry.getKey();
            JsonNode value = entry.getValue();
            if (!value.isObject()) {
                throw new IllegalStateException("Data source '" + id + "': record '" + key + "' in " + file + " is not a JSON object");
            }
            LinkedHashMap<String, Object> record = MAPPER.convertValue(value, RECORD);
            record.values().removeIf(Objects::isNull);
            for (String field : binaryFields) {
                JsonNode node = value.get(field);
                if (node == null || node.isNull()) {
                    continue;
                }
                if (!node.isTextual()) {
                    throw new IllegalStateException("Data source '" + id + "': field '" + field + "' of record '" + key
                            + "' in " + file + " must name a file");
                }
                record.put(field, base64url(directory, node.asText(), key, field));
            }
            loaded.put(key, Collections.unmodifiableMap(record));
        }
        log.info("Data source '{}' loaded {} record(s) from {}", id, loaded.size(), file);
        return Collections.unmodifiableMap(loaded);
    }

    /** Reads a binary field's file and returns its bytes as base64url without padding. */
    private String base64url(Path directory, String value, String key, String field) {
        String what = "Data source '" + id + "': field '" + field + "' of record '" + key + "'";
        Path relative;
        try {
            relative = Path.of(value);
        } catch (InvalidPathException e) {
            throw new IllegalStateException(what + " is not a path: '" + value + "'", e);
        }
        if (relative.isAbsolute()) {
            throw new IllegalStateException(what + " must be relative to " + directory + ", not absolute: '" + value + "'");
        }
        Path resolved = directory.resolve(relative).normalize();
        if (!resolved.startsWith(directory)) {
            throw new IllegalStateException(what + " escapes " + directory + ": '" + value + "'");
        }
        if (!Files.isRegularFile(resolved)) {
            throw new IllegalStateException(what + " names a missing file: '" + resolved + "'");
        }
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(Files.readAllBytes(resolved));
        } catch (IOException e) {
            throw new IllegalStateException(what + " cannot be read: '" + resolved + "': " + e.getMessage(), e);
        }
    }
}
