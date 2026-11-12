package io.mosip.certify.datasource.file;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.oid4vci.DataProviderPluginDataSource;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.IssuanceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
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
 * request. The record is deeply immutable: a template (or a listener) cannot modify the nested lists and maps a later
 * request for the same subject would see.</p>
 *
 * <p>Fields named in {@code binary-fields} hold a file path relative to the JSON file's directory; the file's bytes are
 * read at startup and the field is served as base64url without padding, the shape an mDoc {@code bstr} element (e.g.
 * {@code portrait}) takes from a Velocity template. Absolute paths and paths escaping the JSON directory are refused
 * when the data source is built, as are missing files and malformed JSON, so a bad deployment fails at startup with the
 * file named instead of at the first credential request. Escapes are checked after resolving symlinks, so a link that
 * points outside the directory is refused while a Kubernetes ConfigMap's layout (files linked into {@code ..data/}
 * in the same directory) is accepted.</p>
 *
 * <p><b>The directory is trusted.</b> Containment is checked before the read: the path is resolved, compared with the
 * JSON file's directory and only then read. Those are two steps, so a writer that can replace a link or a file between
 * the check and the read can still make the read follow a path that was not checked, and a hard link is a name rather
 * than a path, so a file outside the directory reached through one passes the check. Both are out of scope: this source
 * assumes the directory is writable only by the deployment that configures it (a mounted ConfigMap or a data volume),
 * and closing the gap needs a descriptor-relative open ({@code openat} with {@code O_NOFOLLOW}), which Java's file API
 * does not expose portably.</p>
 *
 * <p><b>Trust.</b> The record is selected by a claim of the token the authorization server issued; this source trusts
 * that issuer's {@code sub} to name the holder. It therefore does not authenticate anyone itself: with a synthetic
 * demo deployment (D12) anyone who can mint an offer for a demo holder receives that holder's credential, which is
 * acceptable only because the data is synthetic. With real data the pre-authorized offer endpoint must not be public,
 * or the authorization server must authenticate the holder (see {@code config/mdl/README.md}).</p>
 *
 * <p>Size bounds: a JSON file above 5 MiB, a binary file above 1 MiB and more than 50 MiB read in total for one source
 * are refused while reading, with the source, record, field and file named.</p>
 */
public final class FileCredentialDataSource implements CredentialDataSource {

    /** Provenance key naming the data source the claims came from, as {@code DataProviderPluginDataSource} does. */
    public static final String PROVENANCE_SOURCE = "source";
    /**
     * The core's code for "this credential request cannot be served for this subject" (OpenID4VCI 1.0 section 8.3.1.2
     * {@code credential_request_denied}). The core maps a data source failure to an {@code IssuanceException} with the
     * same code; the {@code /oid4vci} adapter answers 400, the draft-13 adapter answers its
     * {@code invalid_credential_request}, and the compatibility surface answers 400 too. It must never be
     * {@code credential_issuance_failed}, which the adapters turn into a 500.
     */
    public static final String ERROR_NO_DATA = IssuanceException.CREDENTIAL_REQUEST_DENIED;

    /** A JSON file larger than this is refused (5 MiB). */
    static final long MAX_JSON_BYTES = 5L * 1024 * 1024;
    /** A binary field's file larger than this is refused (1 MiB); a portrait is a few kilobytes. */
    static final long MAX_BINARY_BYTES = 1024L * 1024;
    /** The most one source may read across its JSON file and all binary files (50 MiB). */
    static final long MAX_TOTAL_BYTES = 50L * 1024 * 1024;

    /**
     * Strict on purpose: a repeated record key would keep the last value, so which subject's data is served would depend
     * on where in the file the duplicate sits, and a second document after the first object is a deployment mistake
     * rather than data to ignore. Both are refused at startup with the file named.
     */
    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    private static final Logger log = LoggerFactory.getLogger(FileCredentialDataSource.class);
    private static final TypeReference<LinkedHashMap<String, Object>> RECORD = new TypeReference<>() {};

    private final String id;
    private final String keyClaim;
    private final Path file;
    private final Map<String, Map<String, Object>> records;

    /**
     * Loads and validates the file. Throws {@link IllegalStateException} with the source id, file and field in the
     * message when the file is missing, is not JSON, is too large, or a binary field's path is absolute, escapes the
     * JSON file's directory (after symlinks are resolved) or names a missing or oversized file.
     */
    public FileCredentialDataSource(String id, FileDataSourceProperties.Source source) {
        if (id == null || id.isBlank()) {
            throw new IllegalStateException(FileDataSourceProperties.PREFIX + ".sources.<id>: every source needs an id");
        }
        if (DataProviderPluginDataSource.ID.equals(id)) {
            throw new IllegalStateException("Data source id '" + id + "' is reserved for the data-provider plugin; choose "
                    + "another id under " + FileDataSourceProperties.PREFIX + ".sources");
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
        // the record is deeply unmodifiable and ClaimSet copies the top level, so no copy of the record is needed here
        return new ClaimSet(record, Map.of(PROVENANCE_SOURCE, id));
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
        Path directory = file.getParent();
        Path realDirectory = realPath(directory, "Data source '" + id + "': directory of " + file);
        Path realFile = realPath(file, "Data source '" + id + "': " + file);
        if (!realFile.startsWith(realDirectory)) {
            throw new IllegalStateException("Data source '" + id + "': " + file + " resolves to '" + realFile
                    + "', outside '" + realDirectory + "'");
        }
        byte[] json = readBounded(realFile, MAX_JSON_BYTES, "Data source '" + id + "': file '" + realFile + "'");
        long[] read = {json.length};
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IllegalStateException("Data source '" + id + "': " + file + " is not readable JSON: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new IllegalStateException("Data source '" + id + "': " + file
                    + " must hold one JSON object whose keys are the '" + keyClaim + "' values");
        }
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
                record.put(field, base64url(directory, realDirectory, node.asText(), key, field, read));
            }
            LinkedHashMap<String, Object> immutable = new LinkedHashMap<>();
            record.forEach((name, fieldValue) -> immutable.put(name, immutable(fieldValue)));
            loaded.put(key, Collections.unmodifiableMap(immutable));
        }
        log.info("Data source '{}' loaded {} record(s) from {}", id, loaded.size(), file);
        return Collections.unmodifiableMap(loaded);
    }

    /** Reads a binary field's file and returns its bytes as base64url without padding. */
    private String base64url(Path directory, Path realDirectory, String value, String key, String field, long[] read) {
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
            throw new IllegalStateException(what + " names a missing or non-regular file: '" + resolved + "'");
        }
        // a symlink is followed before it is trusted: a ConfigMap links into ..data/ inside the directory, an attacker
        // would link outside it, where a file's bytes are none of this source's business
        Path real = realPath(resolved, what);
        if (!real.startsWith(realDirectory)) {
            throw new IllegalStateException(what + " resolves to '" + real + "', outside '" + realDirectory + "'");
        }
        byte[] bytes = readBounded(real, MAX_BINARY_BYTES, what + " file '" + real + "'");
        read[0] += bytes.length;
        if (read[0] > MAX_TOTAL_BYTES) {
            throw new IllegalStateException("Data source '" + id + "' reads more than " + MAX_TOTAL_BYTES
                    + " bytes in total; refused at " + what + " file '" + real + "'");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Path realPath(Path path, String what) {
        try {
            return path.toRealPath();
        } catch (IOException e) {
            throw new IllegalStateException(what + " cannot be resolved: '" + path + "': " + e.getMessage(), e);
        }
    }

    /**
     * Reads at most {@code max} bytes; a larger file is refused at the limit, before the rest of it is read, so an
     * oversized file cannot exhaust memory on its way to being rejected.
     */
    private static byte[] readBounded(Path path, long max, String what) {
        try (InputStream in = Files.newInputStream(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            long count = 0;
            int n;
            while ((n = in.read(buffer)) != -1) {
                count += n;
                if (count > max) {
                    throw new IllegalStateException(what + " is larger than " + max + " bytes");
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(what + " cannot be read: '" + path + "': " + e.getMessage(), e);
        }
    }

    /** Recursively unmodifiable: lists become unmodifiable lists, maps unmodifiable maps, scalars stay as they are. */
    private static Object immutable(Object value) {
        if (value instanceof Map<?, ?> map) {
            LinkedHashMap<String, Object> copy = new LinkedHashMap<>();
            map.forEach((name, nested) -> copy.put(String.valueOf(name), immutable(nested)));
            return Collections.unmodifiableMap(copy);
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            list.forEach(element -> copy.add(immutable(element)));
            return Collections.unmodifiableList(copy);
        }
        return value;
    }
}
