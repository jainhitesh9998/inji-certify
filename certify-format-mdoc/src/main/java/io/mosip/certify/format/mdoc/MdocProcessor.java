/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.format.mdoc;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;

import java.io.ByteArrayOutputStream;


import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.certify.spi.FormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Utility class for mDoc (Mobile Document) specific operations.
 * Provides helper methods for mDoc structure creation and manipulation.
 *
 * <p>The wire rules of ISO/IEC 18013-5 that this class owns: {@code tdate} is tag 0 around a 20-character RFC 3339
 * string without fractional seconds (9.1.2.4); an IssuerSignedItem is digested over its tag-24 encoding with the
 * algorithm the MSO declares (9.1.2.5); {@code digestID} is a random distinct {@code uint} per namespace, drawn from a
 * range much larger than the element count, so a disclosed identifier reveals nothing about the order or the number of
 * elements (9.1.2.5); element values are encoded by the {@link MdocElementTypes} table rather than by guessing (7.2.1),
 * and the {@code YYYY-MM-DD} heuristic applies only to element values in namespaces that have no type table at all;
 * element identifiers, namespace names and {@code docType} are always {@code tstr}. An integer beyond {@code long} in
 * an untyped value stays an integer (uint/nint up to 64 bits, bignum beyond).
 */
public class MdocProcessor {

    private static final Logger log = LoggerFactory.getLogger(MdocProcessor.class);
    /** The digest algorithms 18013-5 9.1.2.4 allows the MSO to declare. */
    private static final Map<String, String> DIGEST_ALGORITHMS = Map.of(
            "SHA256", "SHA-256", "SHA-256", "SHA-256",
            "SHA384", "SHA-384", "SHA-384", "SHA-384",
            "SHA512", "SHA-512", "SHA-512", "SHA-512");
    private static final DateTimeFormatter TDATE = DateTimeFormatter.ofPattern(MdocConstants.TDATE_PATTERN)
            .withResolverStyle(ResolverStyle.STRICT).withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter FULL_DATE = DateTimeFormatter.ofPattern(MdocConstants.FULL_DATE_PATTERN)
            .withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter TDATE_INPUT = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssXXX")
            .withResolverStyle(ResolverStyle.STRICT);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final java.util.concurrent.atomic.AtomicBoolean DIGEST_ID_WARNING = new java.util.concurrent.atomic.AtomicBoolean();

    private final ObjectMapper objectMapper;
    private final MdocProperties mDocConfig;

    public MdocProcessor(ObjectMapper objectMapper, MdocProperties properties) {
        this.objectMapper = objectMapper;
        this.mDocConfig = properties;
    }

    /**
     * Process templated JSON to create final mDoc structure: validityInfo from the request clock, element values typed
     * by the namespace's table, and {@code digestID}s drawn as random distinct uints in {@code 0..2^31-1} per namespace
     * (not a permutation of {@code 0..n-1}, so an identifier reveals nothing about the element count or order).
     */
    public Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams,
                                                    MdocElementTypes elementTypes, Instant now) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            JsonNode validityInfo = templateNode.get(MdocConstants.VALIDITY_INFO);
            if (validityInfo != null && !validityInfo.isNull()) {
                // the values are finalised again at signing time; here they only have to be present and well-formed
                finalMDoc.put(MdocConstants.VALIDITY_INFO, objectMapper.convertValue(validityInfo, Map.class));
            }

            if (templateParams.containsKey(MdocConstants.DID_URL)) {
                finalMDoc.put("_issuer", templateParams.get(MdocConstants.DID_URL));
            }
            String docType = Objects.requireNonNull(templateNode.get(MdocConstants.DOCTYPE), "Missing docType").asText();
            finalMDoc.put("_docType", docType);
            if (templateParams.containsKey(MdocConstants._HOLDER_ID)) {
                finalMDoc.put(MdocConstants._HOLDER_ID, templateParams.get(MdocConstants._HOLDER_ID));
            }

            // Process namespaces
            Map<String, Object> nameSpaces = new HashMap<>();
            Map<String, Map<String, Object>> elementValues = new HashMap<>();

            if (templateNode.has(MdocConstants.NAMESPACES)) {
                JsonNode nameSpacesNode = templateNode.get(MdocConstants.NAMESPACES);
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                    List<Map<String, Object>> processedItems = processNamespaceItems(namespaceName, namespaceItems, elementTypes);
                    nameSpaces.put(namespaceName, processedItems);
                    Map<String, Object> values = new LinkedHashMap<>();
                    for (Map<String, Object> item : processedItems) {
                        values.put((String) item.get(MdocConstants.ELEMENT_IDENTIFIER), item.get(MdocConstants.ELEMENT_VALUE));
                    }
                    elementValues.put(namespaceName, values);
                });
            }
            finalMDoc.put(MdocConstants.NAMESPACES, nameSpaces);
            finalMDoc.put(MdocProcessor.ELEMENT_VALUES, elementValues);

            return finalMDoc;

        } catch (FormatException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error processing templated JSON: {}", e.getMessage(), e);
            throw new FormatException(MdocConstants.ERROR_TEMPLATE, "Error processing templated JSON: " + e.getMessage());
        }
    }

    /** Internal key of the processed document: namespace to element identifier to typed value, for the validator. */
    static final String ELEMENT_VALUES = "_elementValues";

    /**
     * Process items within a namespace: type the value, then give each element a random distinct {@code digestID} from
     * {@code 0..2^31-1}. A {@code digestID} the template carries is ignored (18013-5 9.1.2.5: identifiers must not
     * reveal information) and the first such template is reported once.
     */
    private List<Map<String, Object>> processNamespaceItems(String namespaceName, JsonNode namespaceItems, MdocElementTypes elementTypes) {
        List<Map<String, Object>> processedItems = new ArrayList<>();
        Set<String> identifiers = new HashSet<>();
        boolean templateCarriedIds = false;

        for (JsonNode item : namespaceItems) {
            Map<String, Object> itemMap = new HashMap<>();
            if (item.has(MdocConstants.DIGEST_ID)) {
                templateCarriedIds = true;
            }
            String identifier = item.get(MdocConstants.ELEMENT_IDENTIFIER).asText();
            if (!identifiers.add(identifier)) {
                throw dataModelError(identifier, "appears twice in namespace " + namespaceName
                        + "; elementIdentifier must be unique within a namespace (ISO/IEC 18013-5 7.2.1)");
            }
            ConvertedValue converted = convertValue(namespaceName, identifier, item.get(MdocConstants.ELEMENT_VALUE), elementTypes);
            itemMap.put(MdocConstants.ELEMENT_IDENTIFIER, identifier);
            itemMap.put(MdocConstants.ELEMENT_VALUE, converted.logical());
            if (converted.wire() != null) {
                itemMap.put(MdocConstants.WIRE_VALUE, converted.wire());
            }
            processedItems.add(itemMap);
        }
        if (templateCarriedIds && DIGEST_ID_WARNING.compareAndSet(false, true)) {
            log.warn("Template namespace {} carries digestID values; they are ignored and replaced by random distinct uints "
                    + "so the identifiers reveal nothing (ISO/IEC 18013-5 9.1.2.5)", namespaceName);
        }
        for (Map<String, Object> processedItem : processedItems) {
            processedItem.put(MdocConstants.DIGEST_ID, distinctDigestId(processedItems));
        }
        return processedItems;
    }

    /** A random {@code digestID} not yet used in this namespace (18013-5 9.1.2.5). */
    private static int distinctDigestId(List<Map<String, Object>> items) {
        Set<Integer> used = new HashSet<>();
        for (Map<String, Object> item : items) {
            Object id = item.get(MdocConstants.DIGEST_ID);
            if (id instanceof Integer value) {
                used.add(value);
            }
        }
        int candidate;
        do {
            candidate = RANDOM.nextInt() & Integer.MAX_VALUE; // 0..2^31-1, non-negative by construction
        } while (used.contains(candidate));
        return candidate;
    }

    /** A value in both shapes: the Java value the validator and a preview see, and its exact CBOR encoding when typed. */
    private record ConvertedValue(Object logical, DataItem wire) {}

    /** Encodes one element value in the type its namespace's table declares (7.2.1 Table 5). */
    private ConvertedValue convertValue(String namespaceName, String identifier, JsonNode value, MdocElementTypes elementTypes) {
        Optional<MdocElementTypes.Type> type = elementTypes == null ? Optional.empty() : elementTypes.type(namespaceName, identifier);
        if (type.isEmpty()) {
            Object logical = plain(value);
            // Only a namespace without any type table keeps the pre-M-03 heuristic, and only inside the element's value:
            // the element identifier, the namespace name and the docType are structural text and never become dates. In a
            // namespace that has a table an unlisted (new) identifier is written exactly as the template gives it.
            boolean heuristic = elementTypes == null || !elementTypes.hasTable(namespaceName);
            return new ConvertedValue(logical, heuristic ? heuristicItem(logical) : convertToDataItem(logical));
        }
        if (value == null || value.isNull()) {
            throw dataModelError(identifier, "has no value; the signed document must carry one");
        }
        return switch (type.get()) {
            case TSTR -> {
                String text = text(identifier, value);
                yield new ConvertedValue(text, new UnicodeString(text));
            }
            case UINT -> {
                long number = unsigned(identifier, value);
                yield new ConvertedValue(number, new UnsignedInteger(number));
            }
            case BOOL -> {
                boolean flag = bool(identifier, value);
                yield new ConvertedValue(flag, flag ? SimpleValue.TRUE : SimpleValue.FALSE);
            }
            case BSTR -> {
                byte[] bytes = bytes(identifier, value);
                yield new ConvertedValue(bytes, new ByteString(bytes));
            }
            case FULL_DATE -> {
                String date = fullDate(identifier, text(identifier, value));
                yield new ConvertedValue(date, taggedItem(MdocConstants.CBOR_TAG_FULL_DATE, date));
            }
            case TDATE -> {
                String dateTime = tdate(identifier, text(identifier, value));
                yield new ConvertedValue(dateTime, taggedItem(MdocConstants.CBOR_TAG_TDATE, dateTime));
            }
            case FULL_DATE_OR_TDATE -> {
                String date = text(identifier, value);
                if (isFullDate(date)) {
                    yield new ConvertedValue(fullDate(identifier, date), taggedItem(MdocConstants.CBOR_TAG_FULL_DATE, date));
                }
                String dateTime = tdate(identifier, date);
                yield new ConvertedValue(dateTime, taggedItem(MdocConstants.CBOR_TAG_TDATE, dateTime));
            }
            case DRIVING_PRIVILEGES -> new ConvertedValue(drivingPrivileges(identifier, value), encodedDrivingPrivileges(identifier, value));
            case ARRAY -> {
                if (!value.isArray()) {
                    throw dataModelError(identifier, "must be an array, was " + value.getNodeType().toString().toLowerCase(Locale.ROOT));
                }
                Object list = plain(value);
                yield new ConvertedValue(list, convertToDataItem(list)); // typed: its strings stay text, never dates
            }
        };
    }

    private Object plain(JsonNode value) {
        if (value == null || value.isNull()) {
            return null;
        }
        return value.isTextual() ? value.asText() : objectMapper.convertValue(value, Object.class);
    }

    private static String text(String identifier, JsonNode value) {
        if (!value.isTextual()) {
            throw dataModelError(identifier, "must be a text string (tstr), was " + value.getNodeType().toString().toLowerCase(Locale.ROOT));
        }
        return value.asText();
    }

    private static long unsigned(String identifier, JsonNode value) {
        java.math.BigInteger number;
        if (value.isIntegralNumber()) {
            number = value.bigIntegerValue();
        } else if (value.isTextual() && value.asText().trim().matches("\\d+")) {
            try {
                number = new java.math.BigInteger(value.asText().trim());
            } catch (NumberFormatException e) {
                throw dataModelError(identifier, "must be an unsigned integer (uint), was " + value);
            }
        } else {
            throw dataModelError(identifier, "must be an unsigned integer (uint), was " + value);
        }
        if (number.signum() < 0) {
            throw dataModelError(identifier, "must be an unsigned integer (uint), was " + number);
        }
        if (number.bitLength() > 63) {
            throw dataModelError(identifier, "overflows the unsigned integer (uint) this issuer can encode, was " + number);
        }
        return number.longValue();
    }

    private static boolean bool(String identifier, JsonNode value) {
        if (value.isBoolean()) {
            return value.asBoolean();
        }
        if (value.isTextual() && ("true".equalsIgnoreCase(value.asText()) || "false".equalsIgnoreCase(value.asText()))) {
            return Boolean.parseBoolean(value.asText());
        }
        throw dataModelError(identifier, "must be a boolean (bool), was " + value);
    }

    private static byte[] bytes(String identifier, JsonNode value) {
        if (!value.isTextual()) {
            throw dataModelError(identifier, "must be a base64 or base64url string that decodes to a byte string (bstr), was "
                    + value.getNodeType().toString().toLowerCase(Locale.ROOT));
        }
        String encoded = value.asText().trim();
        if (encoded.isEmpty()) {
            throw dataModelError(identifier, "is an empty byte string; a portrait or template cannot be empty");
        }
        try {
            return Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException notStandard) {
            try {
                String url = encoded.replace('-', '+').replace('_', '/');
                return Base64.getDecoder().decode(url + "=".repeat((4 - url.length() % 4) % 4));
            } catch (IllegalArgumentException e) {
                throw dataModelError(identifier, "is not base64 or base64url: " + e.getMessage());
            }
        }
    }

    /** A {@code full-date}; parsed with {@link ResolverStyle#STRICT} so {@code 2023-02-31} is refused (7.2.1). */
    private static String fullDate(String identifier, String value) {
        if (!value.matches("\\d{4}-\\d{2}-\\d{2}")) {
            throw dataModelError(identifier, "must be a full-date (YYYY-MM-DD), was " + value);
        }
        try {
            LocalDate.parse(value, FULL_DATE);
        } catch (DateTimeParseException e) {
            throw dataModelError(identifier, "must be a real full-date (YYYY-MM-DD), was " + value);
        }
        return value;
    }

    private static boolean isFullDate(String value) {
        if (!value.matches("\\d{4}-\\d{2}-\\d{2}")) {
            return false;
        }
        try {
            LocalDate.parse(value, FULL_DATE);
            return true;
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /** RFC 3339 without fractional seconds, as {@code tdate} requires (18013-5 9.1.2.4); parsed strictly. */
    private static String tdate(String identifier, String value) {
        try {
            return TDATE.format(TDATE_INPUT.parse(value, Instant::from));
        } catch (DateTimeParseException e) {
            throw dataModelError(identifier, "must be a real RFC 3339 date-time such as 2024-01-31T10:15:30Z, was " + value);
        }
    }

    /** {@code full-date} only, for the dates inside {@code driving_privileges} (7.2.1 Table 5). */
    private static DataItem encodedFullDate(String identifier, String value) {
        return taggedItem(MdocConstants.CBOR_TAG_FULL_DATE, fullDate(identifier, value));
    }

    private static final Set<String> PRIVILEGE_KEYS = Set.of("vehicle_category_code", "issue_date", "expiry_date", "codes");
    private static final Set<String> CODE_KEYS = Set.of("code", "sign", "value");

    /** {@code driving_privileges}: an array of {vehicle_category_code, issue_date, expiry_date, codes[]} maps. */
    private List<Object> drivingPrivileges(String identifier, JsonNode value) {
        List<Object> privileges = new ArrayList<>();
        for (JsonNode privilege : privileges(identifier, value)) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("vehicle_category_code", text(identifier, privilege.get("vehicle_category_code")));
            for (String date : new String[] {"issue_date", "expiry_date"}) {
                JsonNode node = privilege.get(date);
                if (node != null && !node.isNull()) {
                    map.put(date, fullDate(identifier + "." + date, text(identifier + "." + date, node)));
                }
            }
            JsonNode codes = privilege.get("codes");
            if (codes != null && !codes.isNull()) {
                List<Object> codeList = new ArrayList<>();
                for (JsonNode code : codes) {
                    Map<String, Object> codeMap = new LinkedHashMap<>();
                    codeMap.put("code", text(identifier + ".codes.code", code.get("code")));
                    for (String optional : new String[] {"sign", "value"}) {
                        JsonNode node = code.get(optional);
                        if (node != null && !node.isNull()) {
                            codeMap.put(optional, text(identifier + ".codes." + optional, node));
                        }
                    }
                    codeList.add(codeMap);
                }
                map.put("codes", codeList);
            }
            privileges.add(map);
        }
        return privileges;
    }

    /** The CBOR form of {@code driving_privileges}: the dates are full-date even where Table 5 allows a tdate. */
    private static DataItem encodedDrivingPrivileges(String identifier, JsonNode value) {
        Array array = new Array();
        for (JsonNode privilege : privileges(identifier, value)) {
            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            map.put(new UnicodeString("vehicle_category_code"), new UnicodeString(text(identifier, privilege.get("vehicle_category_code"))));
            for (String date : new String[] {"issue_date", "expiry_date"}) {
                JsonNode node = privilege.get(date);
                if (node != null && !node.isNull()) {
                    map.put(new UnicodeString(date), encodedFullDate(identifier + "." + date, text(identifier + "." + date, node)));
                }
            }
            JsonNode codes = privilege.get("codes");
            if (codes != null && !codes.isNull()) {
                Array codeArray = new Array();
                for (JsonNode code : codes) {
                    co.nstant.in.cbor.model.Map codeMap = new co.nstant.in.cbor.model.Map();
                    codeMap.put(new UnicodeString("code"), new UnicodeString(text(identifier + ".codes.code", code.get("code"))));
                    for (String optional : new String[] {"sign", "value"}) {
                        JsonNode node = code.get(optional);
                        if (node != null && !node.isNull()) {
                            codeMap.put(new UnicodeString(optional), new UnicodeString(text(identifier + ".codes." + optional, node)));
                        }
                    }
                    codeArray.add(codeMap);
                }
                map.put(new UnicodeString("codes"), codeArray);
            }
            array.add(map);
        }
        return array;
    }

    /** Validates the shape of every driving privilege, refusing empty {@code codes} and unknown keys (Table 5, CDDL). */
    private static List<JsonNode> privileges(String identifier, JsonNode value) {
        if (!value.isArray() || value.isEmpty()) {
            throw dataModelError(identifier, "must be a non-empty array of driving privileges, was " + value);
        }
        List<JsonNode> privileges = new ArrayList<>();
        for (JsonNode privilege : value) {
            if (!privilege.isObject()) {
                throw dataModelError(identifier, "must contain driving privilege maps, found " + privilege);
            }
            privilege.fieldNames().forEachRemaining(key -> {
                if (!PRIVILEGE_KEYS.contains(key)) {
                    throw dataModelError(identifier, "has an unknown driving privilege key '" + key + "' (expected one of "
                            + PRIVILEGE_KEYS + ")");
                }
            });
            JsonNode category = privilege.get("vehicle_category_code");
            if (category == null || !category.isTextual() || category.asText().isBlank()) {
                throw dataModelError(identifier, "carries a driving privilege without a vehicle_category_code (tstr)");
            }
            JsonNode codes = privilege.get("codes");
            if (codes != null && !codes.isNull()) {
                if (!codes.isArray() || codes.isEmpty()) {
                    throw dataModelError(identifier + ".codes", "must carry at least one code (CDDL [+ Code]), was " + codes);
                }
                for (JsonNode code : codes) {
                    if (!code.isObject() || code.get("code") == null || !code.get("code").isTextual()) {
                        throw dataModelError(identifier + ".codes", "must contain maps with a code (tstr)");
                    }
                    code.fieldNames().forEachRemaining(key -> {
                        if (!CODE_KEYS.contains(key)) {
                            throw dataModelError(identifier + ".codes", "has an unknown code key '" + key + "' (expected one of "
                                    + CODE_KEYS + ")");
                        }
                    });
                }
            }
            privileges.add(privilege);
        }
        return privileges;
    }

    private static FormatException dataModelError(String identifier, String problem) {
        return new FormatException(MdocConstants.ERROR_DATA_MODEL, identifier + " " + problem);
    }

    /**
     * Adds random salts to each data element
     */
    public static Map<String, Object> addRandomSalts(Map<String, Object> mDocJson) {
        Map<String, Object> nameSpaces = (Map<String, Object>) mDocJson.get(MdocConstants.NAMESPACES);
        Map<String, Object> saltedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : nameSpaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<Map<String, Object>> saltedElements = new ArrayList<>();

            for (Map<String, Object> element : elements) {
                // Generate 24-byte random salt
                byte[] randomSalt = new byte[24];
                RANDOM.nextBytes(randomSalt);

                // Clone element with random salt as hex string
                Map<String, Object> saltedElement = new HashMap<>(element);
                saltedElement.put("random", randomSalt);

                saltedElements.add(saltedElement);
            }

            saltedNamespaces.put(namespaceName, saltedElements);
        }

        return saltedNamespaces;
    }

    /**
     * Calculates the digests of the salted elements and the encoded IssuerSignedItems the IssuerSigned carries. The digest
     * algorithm must be the one the MSO declares (18013-5 9.1.2.5); {@code namespaceDigests} receives
     * {@code namespace -> digestID -> digest}. The items are returned as their CBOR bytes, so the unsigned credential
     * stays JSON-serialisable (a preview returns it); {@link #taggedNamespaces} wraps them for the wire.
     */
    public static Map<String, List<byte[]>> calculateDigests
    (Map<String, Object> saltedNamespaces, Map<String, Map<Integer, byte[]>> namespaceDigests, String digestAlgorithm) throws Exception {

        Map<String, List<byte[]>> encodedNamespaces = new HashMap<>();
        String algorithm = digestAlgorithmName(digestAlgorithm);

        for (Map.Entry<String, Object> namespaceEntry : saltedNamespaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<byte[]> encodedElements = new ArrayList<>();
            Map<Integer, byte[]> digestMap = new HashMap<>();

            for (Map<String, Object> element : elements) {
                // 1) Encode element (IssuerSignedItem) to CBOR with its pre-built value (typed, or the untyped heuristic)
                Map<String, Object> wireElement = new LinkedHashMap<>(element);
                Object typed = wireElement.remove(MdocConstants.WIRE_VALUE);
                if (typed != null) {
                    wireElement.put(MdocConstants.ELEMENT_VALUE, typed);
                }
                ByteArrayOutputStream innerBaos = new ByteArrayOutputStream();
                new CborEncoder(innerBaos).encode(convertToDataItem(preprocessForCBOR(wireElement)));
                byte[] elementCbor = innerBaos.toByteArray();
                encodedElements.add(elementCbor);

                // 2) Calculate the digest over the Tag(24) encoded bytes
                ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
                new CborEncoder(outerBaos).encode(tag24(elementCbor));
                byte[] taggedCbor = outerBaos.toByteArray();
                byte[] digest = MessageDigest.getInstance(algorithm).digest(taggedCbor);
                digestMap.put((Integer) element.get(MdocConstants.DIGEST_ID), digest);
            }

            encodedNamespaces.put(namespaceName, encodedElements);
            namespaceDigests.put(namespaceName, digestMap);
        }

        return encodedNamespaces;
    }

    /** {@code #6.24(bstr .cbor IssuerSignedItem)}: the tag-24 items the IssuerSigned carries (9.1.2.5). */
    public static Map<String, Object> taggedNamespaces(Map<String, List<byte[]>> encodedNamespaces) {
        Map<String, Object> tagged = new HashMap<>();
        encodedNamespaces.forEach((namespaceName, items) -> {
            List<Object> taggedItems = new ArrayList<>(items.size());
            for (byte[] item : items) {
                taggedItems.add(tag24(item));
            }
            tagged.put(namespaceName, taggedItems);
        });
        return tagged;
    }

    private static ByteString tag24(byte[] innerCbor) {
        ByteString tagged = new ByteString(innerCbor);
        tagged.setTag(24);
        return tagged;
    }

    /** The canonical MSO name of a digest algorithm, refusing anything 18013-5 9.1.2.4 does not allow. */
    public static String digestAlgorithmName(String configured) {
        String canonical = configured == null ? null : DIGEST_ALGORITHMS.get(configured.trim().toUpperCase(Locale.ROOT));
        if (canonical == null) {
            throw new FormatException(MdocConstants.ERROR_TEMPLATE,
                    "digestAlgorithm " + configured + " is not one of SHA-256, SHA-384, SHA-512 (ISO/IEC 18013-5 9.1.2.4)");
        }
        return canonical;
    }

    public static byte[] encodeToCBOR(Object obj) throws Exception {
        try {
            Object preprocessedData = preprocessForCBOR(obj);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);
            encoder.encode(convertToDataItem(preprocessedData));
            return baos.toByteArray();
        } catch (Exception e) {
            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
        }
    }

    public static byte[] encodeToTaggedCBOR(Object obj) throws Exception {
        try {
            byte[] innerCborBytes = encodeToCBOR(obj);

            // Format: #6.24(bstr .cbor convertToDataItem(preprocessedData))
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);
            ByteString taggedCbor = new ByteString(innerCborBytes);
            taggedCbor.setTag(24);
            encoder.encode(taggedCbor);

            return baos.toByteArray();
        } catch (Exception e) {
            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
        }
    }

    /**
     * Preprocesses objects for CBOR encoding (handles dates, byte arrays, etc.)
     */
    private static Object preprocessForCBOR(Object obj) {
        if (obj == null) {
            return null;
        }

        // Handle byte arrays directly - don't convert to hex
        if (obj instanceof byte[]) {
            return obj;
        }

        if (obj instanceof Map) {
            Map<Object, Object> map = (Map<Object, Object>) obj;
            if (map.containsKey(MdocConstants.__CBOR_TAG)) {
                return obj; // already typed by the element table: a tag around its value
            }
            Map<Object, Object> processedMap = new HashMap<>();

            for (Map.Entry<Object, Object> entry : map.entrySet()) {
                Object processedKey = preprocessForCBOR(entry.getKey());
                Object processedValue = preprocessForCBOR(entry.getValue());
                processedMap.put(processedKey, processedValue);
            }
            return processedMap;
        }

        if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> processedList = new ArrayList<>();
            for (Object item : list) {
                processedList.add(preprocessForCBOR(item));
            }
            return processedList;
        }

        return obj; // Return as-is for primitives
    }

    private static DataItem convertToDataItem(Object obj) {
        if (obj instanceof DataItem di) {
            return di;
        }
        if (obj == null) {
            return SimpleValue.NULL;
        }
        if (obj instanceof String) {
            return new UnicodeString((String) obj);
        }
        if (obj instanceof Integer) {
            int value = (Integer) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof Long) {
            long value = (Long) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof java.math.BigInteger big) {
            return integerItem(big);
        }
        if (obj instanceof Boolean) {
            return (Boolean) obj ? SimpleValue.TRUE : SimpleValue.FALSE;
        }
        if (obj instanceof Double) {
            return new DoublePrecisionFloat((Double) obj);
        }
        if (obj instanceof Float) {
            return new SinglePrecisionFloat((Float) obj);
        }
        if (obj instanceof byte[]) {
            return new ByteString((byte[]) obj);
        }
        if (obj instanceof java.util.Map && ((java.util.Map<?, ?>) obj).containsKey(MdocConstants.__CBOR_TAG)) {
            java.util.Map<?, ?> taggedMap = (java.util.Map<?, ?>) obj;
            int tag = (Integer) taggedMap.get(MdocConstants.__CBOR_TAG);
            Object value = taggedMap.get(MdocConstants.__CBOR_VALUE);
            DataItem dataItem = convertToDataItem(value);
            dataItem.setTag(tag);  // This correctly sets the tag
            return dataItem;
        }
        if (obj instanceof java.util.Map) {
            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            for (Object entry : ((java.util.Map<?, ?>) obj).entrySet()) {
                java.util.Map.Entry<?, ?> mapEntry = (java.util.Map.Entry<?, ?>) entry;
                DataItem keyItem = convertToDataItem(mapEntry.getKey());
                DataItem valueItem = convertToDataItem(mapEntry.getValue());
                map.put(keyItem, valueItem);
            }
            return map;
        }
        if (obj instanceof List) {
            Array array = new Array();
            for (Object item : (List<?>) obj) {
                array.add(convertToDataItem(item));
            }
            return array;
        }
        // For any other type, convert to string
        return new UnicodeString(obj.toString());
    }


    private static final java.math.BigInteger UINT64_MAX = java.math.BigInteger.ONE.shiftLeft(64).subtract(java.math.BigInteger.ONE);
    private static final java.math.BigInteger NINT64_MIN = java.math.BigInteger.ONE.shiftLeft(64).negate();

    /**
     * An integer beyond {@code long}: a CBOR uint or nint while it fits the 64-bit argument (RFC 8949 3.1, major types 0
     * and 1 reach {@code 2^64-1} and {@code -2^64}), a bignum beyond that (tag 2 or 3 around the unsigned big-endian
     * magnitude, without leading zeros; RFC 8949 3.4.3). Never text: a number must stay a number on the wire.
     */
    static DataItem integerItem(java.math.BigInteger value) {
        if (value.signum() >= 0) {
            if (value.compareTo(UINT64_MAX) <= 0) {
                return new UnsignedInteger(value);
            }
            ByteString bignum = new ByteString(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(value));
            bignum.setTag(2);
            return bignum;
        }
        if (value.compareTo(NINT64_MIN) >= 0) {
            return new NegativeInteger(value);
        }
        ByteString bignum = new ByteString(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(
                java.math.BigInteger.ONE.negate().subtract(value))); // tag 3 carries -1 - n
        bignum.setTag(3);
        return bignum;
    }

    /**
     * The pre-M-03 date heuristic, for the value of an element in a namespace without a type table: a {@code YYYY-MM-DD}
     * string anywhere inside the value becomes {@code #6.1004}. Map keys stay text, and nothing outside an element value
     * (identifiers, namespace names, docType) ever reaches this method.
     */
    private static DataItem heuristicItem(Object value) {
        if (value instanceof String text) {
            return isDateOnlyString(text) ? taggedItem(MdocConstants.CBOR_TAG_FULL_DATE, text) : new UnicodeString(text);
        }
        if (value instanceof Map<?, ?> map && !map.containsKey(MdocConstants.__CBOR_TAG)) {
            co.nstant.in.cbor.model.Map out = new co.nstant.in.cbor.model.Map();
            map.forEach((key, entry) -> out.put(convertToDataItem(key), heuristicItem(entry)));
            return out;
        }
        if (value instanceof List<?> list) {
            Array out = new Array();
            list.forEach(entry -> out.add(heuristicItem(entry)));
            return out;
        }
        return convertToDataItem(value);
    }

    /**
     * Checks if a string represents a date-only value (YYYY-MM-DD)
     */
    private static boolean isDateOnlyString(String str) {
        try {
            LocalDate.parse(str, DateTimeFormatter.ISO_LOCAL_DATE);
            return str.matches("\\d{4}-\\d{2}-\\d{2}");
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /** A pre-built tagged text item: {@code #6.<tag>(tstr)} with no heuristic applied later. */
    private static DataItem taggedItem(int tag, String value) {
        UnicodeString item = new UnicodeString(value);
        item.setTag(tag);
        return item;
    }

    /** A JSON-friendly tagged text value ({@code __cbor_tag}/{@code __cbor_value}) for maps that stay serialisable. */
    private static Map<String, Object> taggedMap(int tag, String value) {
        Map<String, Object> taggedValue = new LinkedHashMap<>();
        taggedValue.put(MdocConstants.__CBOR_TAG, tag);
        taggedValue.put(MdocConstants.__CBOR_VALUE, value);
        return taggedValue;
    }

    /**
     * The MSO's {@code validityInfo} (18013-5 9.1.2.4) without a document expiry: see
     * {@link #validityInfo(Instant, Duration, Instant, Instant)}.
     */
    public static Map<String, Object> validityInfo(Instant signedAt, Duration validity, Instant notAfter) {
        return validityInfo(signedAt, validity, notAfter, null);
    }

    /**
     * The MSO's {@code validityInfo} (18013-5 9.1.2.4): {@code signed} and {@code validFrom} are the instant of signing
     * truncated to seconds; {@code validUntil} is that instant plus the configured validity, capped at the document
     * signer certificate's {@code notAfter} (the credential never outlives the key that signed it) and at the document's
     * own expiry (an mDL's {@code expiry_date}), then truncated to seconds. The comparison with {@code signed} is made on
     * the truncated values, i.e. on what the MSO will say: a {@code validUntil} that encodes equal to {@code signed} is
     * refused, with the code of the bound that made it so.
     */
    public static Map<String, Object> validityInfo(Instant signedAt, Duration validity, Instant notAfter, Instant documentExpiry) {
        Instant signed = (signedAt == null ? Instant.now() : signedAt).truncatedTo(ChronoUnit.SECONDS);
        Instant until = signed.plus(validity == null ? Duration.ofDays(90) : validity);
        String bound = "validity";
        if (notAfter != null && notAfter.isBefore(until)) {
            until = notAfter;
            bound = "certificate";
        }
        if (documentExpiry != null && documentExpiry.isBefore(until)) {
            until = documentExpiry;
            bound = "expiry";
        }
        until = until.truncatedTo(ChronoUnit.SECONDS); // tdate carries whole seconds: compare what will be encoded
        if (!until.isAfter(signed)) {
            throw switch (bound) {
                // 9.1.2.4/9.3.3: a document whose validity ends before it is signed can never be valid. This is a
                // certificate fault, refused here before the generic chain check so the operator sees the DSC.
                case "certificate" -> new FormatException(MdocConstants.ERROR_CHAIN, "the document signer certificate expires at "
                        + notAfter + ", which leaves no whole second after the signing instant " + signed
                        + "; the MSO validUntil would not be after signed (ISO/IEC 18013-5 9.1.2.4)");
                case "expiry" -> new FormatException(MdocConstants.ERROR_DATA_MODEL, "the document expires at " + documentExpiry
                        + ", not after the signing instant " + signed + "; an expired document is not issued");
                default -> new FormatException(MdocConstants.ERROR_SIGNING, "the MSO validity " + validity
                        + " leaves validUntil equal to signed once truncated to whole seconds (ISO/IEC 18013-5 9.1.2.4)");
            };
        }
        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put(MdocConstants.VALID_FROM, taggedMap(MdocConstants.CBOR_TAG_TDATE, TDATE.format(signed)));
        validityInfo.put(MdocConstants.VALID_UNTIL, taggedMap(MdocConstants.CBOR_TAG_TDATE, TDATE.format(until)));
        validityInfo.put(MdocConstants.SIGNED, taggedMap(MdocConstants.CBOR_TAG_TDATE, TDATE.format(signed)));
        return validityInfo;
    }

    /**
     * Creates the Mobile Security Object (MSO) structure
     */
    public Map<String, Object> createMobileSecurityObject
    (Map<String, Object> mDocJson, Map<String, Map<Integer, byte[]>> namespaceDigests, Map<Object, Object> deviceKey) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", mDocConfig.msoVersion());
        mso.put("digestAlgorithm", digestAlgorithmName(mDocConfig.digestAlgorithm()));

        // Create valueDigests structure
        Map<String, Object> nameSpacesDigests = new HashMap<>();
        nameSpacesDigests.putAll(namespaceDigests);

        mso.put("valueDigests", nameSpacesDigests);
        mso.put(MdocConstants.DOCTYPE, mDocJson.get("_docType"));

        Map<String, Object> validityInfo = mDocJson.containsKey(MdocConstants.VALIDITY_INFO)
                ? (Map<String, Object>) mDocJson.get(MdocConstants.VALIDITY_INFO)
                : validityInfo(Instant.now(), mDocConfig.validity(), null);
        mso.put(MdocConstants.VALIDITY_INFO, validityInfo);

        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", deviceKey);
        mso.put("deviceKeyInfo", deviceKeyInfo);

        return mso;
    }

    /**
     * Creates the final IssuerSigned structure combining namespaces and issuerAuth
     */

    public static Map<String, Object> createIssuerSignedStructure(Map<String, Object> processedNamespaces, byte[] signedMSO) throws IOException {
        try {
            var di = new CborDecoder(new java.io.ByteArrayInputStream(signedMSO)).decode();
            if (di.isEmpty()) {
                throw new IOException("Failed to decode COSE_Sign1: empty result");
            }
            DataItem cose = di.get(0);
            Map<String, Object> out = new HashMap<>();
            out.put(MdocConstants.NAMESPACES, processedNamespaces);
            out.put("issuerAuth", cose);
            return out;
        } catch (CborException e) {
            throw new IOException("Failed to decode COSE_Sign1", e);
        }
    }
}
