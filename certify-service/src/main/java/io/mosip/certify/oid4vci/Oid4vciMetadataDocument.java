package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * The finishing pass of the {@code /oid4vci} Credential Issuer Metadata document (OpenID4VCI 1.0 section 12.2.4).
 * The document reuses DTOs that the compatibility surface serialises with explicit nulls ({@code "logo": null},
 * {@code "background_image": null}, ...) and with claims in hash-map order; the compatibility documents keep those bytes
 * (the {@code legacy-develop} and {@code legacy-0.14.0} goldens), this surface does not:
 * <ul>
 *     <li>a member whose value is null is omitted: every member the specification defines here is optional and is
 *     either absent or of its type (an object for {@code logo} and {@code background_image}, a string for colours);</li>
 *     <li>{@code credential_metadata.claims} follows the configuration's display order (12.2.4: "the order in which
 *     claims are displayed"): listed claims first, in the listed order, the others after them ordered by path.</li>
 * </ul>
 */
final class Oid4vciMetadataDocument {

    private Oid4vciMetadataDocument() {}

    /**
     * Returns a finished copy of the document.
     *
     * @param claimOrder per credential configuration id, the claim names in display order (an absent id keeps the claims
     *                   ordered by path)
     */
    static JsonNode finish(JsonNode document, Map<String, List<String>> claimOrder) {
        JsonNode copy = document.deepCopy();
        dropNulls(copy);
        JsonNode supported = copy.get("credential_configurations_supported");
        if (supported instanceof ObjectNode configurations) {
            configurations.fields().forEachRemaining(configuration -> {
                JsonNode claims = configuration.getValue().path("credential_metadata").get("claims");
                if (claims instanceof ArrayNode array) {
                    order(array, claimOrder.getOrDefault(configuration.getKey(), List.of()));
                }
            });
        }
        return copy;
    }

    private static void dropNulls(JsonNode node) {
        if (node instanceof ObjectNode object) {
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                JsonNode value = fields.next().getValue();
                if (value == null || value.isNull()) {
                    fields.remove();
                } else {
                    dropNulls(value);
                }
            }
        } else if (node instanceof ArrayNode array) {
            array.forEach(Oid4vciMetadataDocument::dropNulls);
        }
    }

    private static void order(ArrayNode claims, List<String> displayOrder) {
        List<String> order = names(displayOrder);
        List<JsonNode> items = new ArrayList<>();
        claims.forEach(items::add);
        items.sort(Comparator.comparingInt((JsonNode claim) -> position(claim, order)).thenComparing(Oid4vciMetadataDocument::path));
        claims.removeAll();
        items.forEach(claims::add);
    }

    /** Where a claim sits in the display order: its last path element (an mDoc element, a claim name), else its first. */
    private static int position(JsonNode claim, List<String> order) {
        JsonNode path = claim.get("path");
        if (path instanceof ArrayNode segments && !segments.isEmpty()) {
            int last = order.indexOf(segments.get(segments.size() - 1).asText());
            if (last >= 0) {
                return last;
            }
            int first = order.indexOf(segments.get(0).asText());
            if (first >= 0) {
                return first;
            }
        }
        return Integer.MAX_VALUE;
    }

    private static String path(JsonNode claim) {
        return claim.path("path").toString();
    }

    /**
     * The order's names, one per element. A {@code TEXT[]} column read through H2 arrives as one bracketed element
     * ({@code "[fullName, dateOfBirth]"}); claim names carry neither brackets nor commas, so such an element is split.
     */
    static List<String> names(List<String> displayOrder) {
        List<String> names = new ArrayList<>();
        if (displayOrder == null) {
            return names;
        }
        for (String element : displayOrder) {
            if (element == null) {
                continue;
            }
            String text = element.trim();
            if (text.startsWith("[") && text.endsWith("]")) {
                for (String name : text.substring(1, text.length() - 1).split(",")) {
                    if (!name.isBlank()) {
                        names.add(name.trim());
                    }
                }
            } else if (!text.isEmpty()) {
                names.add(text);
            }
        }
        return names;
    }
}
