package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Golden files: recorded JSON documents that later refactors must reproduce byte for byte after
 * normalisation of the fields that legitimately change per run (dates, ids, nonces, signatures).
 * A missing golden is recorded on first run (like a frozen ArchUnit store); {@code -Dgoldens.record=true}
 * re-records everything. Files live under src/test/resources/goldens and are committed.
 */
public final class Goldens {

    static final Set<String> VOLATILE_KEYS = Set.of(
            "id", "issuanceDate", "expirationDate", "validFrom", "validUntil", "created", "proofValue", "jws",
            "iat", "exp", "nbf", "jti", "c_nonce", "nonce", "_sd", "sd_alg", "cnf", "signature", "x5c", "x5t#S256", "kid",
            "pre-authorized_code", "access_token", "credential_offer_uri",
            // published key material regenerates with the test keystore on every run
            "publicKeyMultibase", "publicKeyJwk", "publicKeyPem", "x", "y", "n", "e",
            "qr", "statusListIndex", "statusListCredential");

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    private Goldens() {}

    public static JsonNode normalize(JsonNode node) {
        JsonNode copy = node.deepCopy();
        normalizeInPlace(copy);
        return sorted(copy);
    }

    private static void normalizeInPlace(JsonNode node) {
        if (node instanceof ObjectNode object) {
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (VOLATILE_KEYS.contains(field.getKey())) {
                    object.set(field.getKey(), MAPPER.getNodeFactory().textNode("<" + field.getKey() + ">"));
                } else {
                    normalizeInPlace(field.getValue());
                }
            }
            if (object.has("credentialSubject") && object.get("credentialSubject").isObject()) {
                // holder binding differs per run (fresh holder key)
                ((ObjectNode) object.get("credentialSubject")).put("id", "<holder>");
            }
            if (object.has("verificationMethod") && object.get("verificationMethod").isTextual()) {
                // the fragment is the signing key id, which is generated per run
                String vm = object.get("verificationMethod").asText();
                int hash = vm.indexOf('#');
                object.put("verificationMethod", hash > 0 ? vm.substring(0, hash) + "#<kid>" : vm);
            }
        } else if (node instanceof ArrayNode array) {
            array.forEach(Goldens::normalizeInPlace);
            sortObjectArray(array);
        }
    }

    /**
     * Arrays of objects are compared order-insensitively: develop builds several of them from HashMaps
     * (for example credential_metadata.claims), so their order is not stable between JVM runs.
     * Arrays of scalars keep their order because it is part of the wire contract (type, @context).
     */
    private static void sortObjectArray(ArrayNode array) {
        if (array.isEmpty() || !array.get(0).isObject()) {
            return;
        }
        java.util.List<JsonNode> items = new java.util.ArrayList<>();
        array.forEach(items::add);
        items.sort(java.util.Comparator.comparing(JsonNode::toString));
        array.removeAll();
        items.forEach(array::add);
    }

    private static JsonNode sorted(JsonNode node) {
        try {
            return MAPPER.readTree(MAPPER.writeValueAsString(MAPPER.treeToValue(node, Object.class)));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Compares (or records) the normalized document against {@code src/test/resources/goldens/<name>.json}. */
    public static void assertGolden(String name, JsonNode actual) throws IOException {
        JsonNode normalized = normalize(actual);
        Path file = goldenPath(name);
        boolean record = Boolean.getBoolean("goldens.record") || !Files.exists(file);
        if (record) {
            Files.createDirectories(file.getParent());
            Files.writeString(file, MAPPER.writeValueAsString(normalized) + "\n", StandardCharsets.UTF_8);
            System.out.println("[goldens] recorded " + file);
            return;
        }
        JsonNode expected = MAPPER.readTree(Files.readString(file, StandardCharsets.UTF_8));
        assertEquals(MAPPER.writeValueAsString(expected), MAPPER.writeValueAsString(normalized),
                "golden " + name + " differs; re-record with -Dgoldens.record=true only if the change is intended");
    }

    static Path goldenPath(String name) {
        Path dir = Paths.get("").toAbsolutePath();
        Path resources = dir.resolve("src/test/resources/goldens");
        if (!Files.isDirectory(resources)) {
            resources = dir.resolve("certify-service/src/test/resources/goldens");
        }
        return resources.resolve(name + ".json");
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
