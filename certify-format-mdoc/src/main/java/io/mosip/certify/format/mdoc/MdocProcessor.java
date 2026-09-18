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
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
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
 */
public class MdocProcessor {

    private static final Logger log = LoggerFactory.getLogger(MdocProcessor.class);
    private final ObjectMapper objectMapper;
    private final MdocProperties mDocConfig;

    public MdocProcessor(ObjectMapper objectMapper, MdocProperties properties) {
        this.objectMapper = objectMapper;
        this.mDocConfig = properties;
    }

    /**
     * Process templated JSON to create final mDoc structure
     */
    public Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            JsonNode validityInfo = Objects.requireNonNull(
                    templateNode.get(MdocConstants.VALIDITY_INFO),
                    "Missing validity info"
            );

            Map<String, Object> validity = objectMapper.convertValue(validityInfo, Map.class);

            String validFromValue = Objects.requireNonNull(
                    (String) validity.get(MdocConstants.VALID_FROM),
                    "Missing validFrom"
            );
            String signedValue = Objects.requireNonNull(
                    (String) validity.get(MdocConstants.SIGNED),
                    "Missing signed"
            );
            String validUntilValue = Objects.requireNonNull(
                    (String) validity.get(MdocConstants.VALID_UNTIL),
                    "Missing validUntil"
            );

            ZonedDateTime currentTime = ZonedDateTime.now(ZoneOffset.UTC);
            String formattedCurrentTime = currentTime.format(DateTimeFormatter.ofPattern(MdocConstants.UTC_DATETIME_PATTERN));

            if ("${_validFrom}".equals(validFromValue)) {
                validity.put(MdocConstants.VALID_FROM, createCBORTaggedDateTime(formattedCurrentTime));
            }
            if ("${_signed}".equals(signedValue)) {
                validity.put(MdocConstants.SIGNED, createCBORTaggedDateTime(formattedCurrentTime));
            }
            if ("${_validUntil}".equals(validUntilValue)) {
                String futureTime = currentTime.plusYears(mDocConfig.validityPeriodYears())
                        .format(DateTimeFormatter.ofPattern(MdocConstants.UTC_DATETIME_PATTERN));
                validity.put(MdocConstants.VALID_UNTIL, createCBORTaggedDateTime(futureTime));
            }

            finalMDoc.put(MdocConstants.VALIDITY_INFO, validity);

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

            if (templateNode.has(MdocConstants.NAMESPACES)) {
                JsonNode nameSpacesNode = templateNode.get(MdocConstants.NAMESPACES);
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                    List<Map<String, Object>> processedItems = processNamespaceItems(namespaceItems);
                    nameSpaces.put(namespaceName, processedItems);
                });
            }
            finalMDoc.put(MdocConstants.NAMESPACES, nameSpaces);

            return finalMDoc;

        } catch (Exception e) {
            log.error("Error processing templated JSON: {}", e.getMessage(), e);
            throw new FormatException(MdocConstants.ERROR_TEMPLATE, "Error processing templated JSON: " + e.getMessage());
        }
    }

    /**
     * Process items within a namespace
     */
    private List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems) {
        List<Map<String, Object>> processedItems = new ArrayList<>();

        // First, add all items from template
        for (JsonNode item : namespaceItems) {
            Map<String, Object> itemMap = new HashMap<>();
            itemMap.put(MdocConstants.DIGEST_ID, item.get(MdocConstants.DIGEST_ID).asInt());
            itemMap.put(MdocConstants.ELEMENT_IDENTIFIER, item.get(MdocConstants.ELEMENT_IDENTIFIER).asText());

            // Handle elementValue which could be string or complex object
            JsonNode elementValue = item.get(MdocConstants.ELEMENT_VALUE);
            if (elementValue.isTextual()) {
                itemMap.put(MdocConstants.ELEMENT_VALUE, elementValue.asText());
            } else {
                // Convert complex objects (like driving_privileges)
                Object value = objectMapper.convertValue(elementValue, Object.class);
                itemMap.put(MdocConstants.ELEMENT_VALUE, value);
            }

            processedItems.add(itemMap);
        }

        return processedItems;
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

            SecureRandom sr = new SecureRandom();
            for (Map<String, Object> element : elements) {
                // Generate 24-byte random salt
                byte[] randomSalt = new byte[24];
                sr.nextBytes(randomSalt);

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
     * Calculates SHA-256 digests for salted elements
     */
    public static Map<String, Object> calculateDigests
    (Map<String, Object> saltedNamespaces, Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> taggedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : saltedNamespaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<Object> taggedElements = new ArrayList<>();
            Map<Integer, byte[]> digestMap = new HashMap<>();

            for (Map<String, Object> element : elements) {
                // 1) Encode element (IssuerSignedItem) to CBOR
                ByteArrayOutputStream innerBaos = new ByteArrayOutputStream();
                new CborEncoder(innerBaos).encode(convertToDataItem(preprocessForCBOR(element)));
                byte[] elementCbor = innerBaos.toByteArray();

                // 2) Build Tag(24) DataItem for final structure
                ByteString tag24Value = new ByteString(elementCbor);
                tag24Value.setTag(24);
                taggedElements.add(tag24Value);

                // 3) Calculate digest over Tag(24) encoded bytes
                ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
                new CborEncoder(outerBaos).encode(tag24Value);
                byte[] taggedCbor = outerBaos.toByteArray();
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(taggedCbor);
                digestMap.put((Integer) element.get(MdocConstants.DIGEST_ID), digest);
            }

            taggedNamespaces.put(namespaceName, taggedElements);
            namespaceDigests.put(namespaceName, digestMap);
        }

        return taggedNamespaces;
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

        if (obj instanceof String) {
            String str = (String) obj;
            if (isDateOnlyString(str)) {
                return createCBORTaggedDate(str);
            }
            return str;
        }

        if (obj instanceof Map) {
            Map<Object, Object> map = (Map<Object, Object>) obj;
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

    /**
     * Creates a CBOR tagged date (tag 1004) for date-only strings
     */
    private static Map<String, Object> createCBORTaggedDate(String dateStr) {
        Map<String, Object> taggedDate = new HashMap<>();
        taggedDate.put(MdocConstants.__CBOR_TAG, 1004);
        taggedDate.put(MdocConstants.__CBOR_VALUE, dateStr);
        return taggedDate;
    }

    /**
     * Creates a CBOR tagged datetime (tag 0) for datetime strings (RFC 3339 format)
     * RFC 8610: tdate = #6.0(tstr) where tstr = #3
     * This wraps full datetime timestamps in Tag 0 as per mso_mdoc specification
     */
    private static Map<String, Object> createCBORTaggedDateTime(String dateTimeStr) {
        Map<String, Object> taggedDate = new HashMap<>();
        taggedDate.put(MdocConstants.__CBOR_TAG, 0);
        taggedDate.put(MdocConstants.__CBOR_VALUE, dateTimeStr);
        return taggedDate;
    }

    /**
     * Creates the Mobile Security Object (MSO) structure
     */
    public Map<String, Object> createMobileSecurityObject
    (Map<String, Object> mDocJson, Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", mDocConfig.msoVersion());
        mso.put("digestAlgorithm", mDocConfig.digestAlgorithm());

        // Create valueDigests structure
        Map<String, Object> nameSpacesDigests = new HashMap<>();
        nameSpacesDigests.putAll(namespaceDigests);

        mso.put("valueDigests", nameSpacesDigests);
        mso.put(MdocConstants.DOCTYPE, mDocJson.get("_docType"));

        // Create validity info with current timestamp
        Map<String, Object> validityInfo = new HashMap<>();

        if (mDocJson.containsKey(MdocConstants.VALIDITY_INFO)) {
            Map<String, Object> originalValidity = (Map<String, Object>) mDocJson.get(MdocConstants.VALIDITY_INFO);
            validityInfo.put(MdocConstants.VALID_FROM, originalValidity.get(MdocConstants.VALID_FROM));
            validityInfo.put(MdocConstants.VALID_UNTIL, originalValidity.get(MdocConstants.VALID_UNTIL));
            validityInfo.put(MdocConstants.SIGNED, originalValidity.get(MdocConstants.SIGNED));
        }
        mso.put(MdocConstants.VALIDITY_INFO, validityInfo);

        // Add device key info (placeholder - should be from wallet's PoP)
        Map<String, Object> deviceKeyInfo = createDeviceKeyInfo(mDocJson.get(MdocConstants._HOLDER_ID));
        mso.put("deviceKeyInfo", deviceKeyInfo);

        return mso;
    }

    /**
     * Creates device key info structure (placeholder implementation)
     */
    private static Map<String, Object> createDeviceKeyInfo(Object deviceInfo) throws Exception {
        if (deviceInfo == null) {
            throw new IllegalArgumentException("Device info (holder ID) is required for mDoc credential");
        }
        String deviceKeyEncoded = deviceInfo.toString();
        if (deviceKeyEncoded.startsWith(MdocConstants.DID_JWK_PREFIX)) {
            deviceKeyEncoded = deviceKeyEncoded.substring(MdocConstants.DID_JWK_PREFIX.length());
            deviceKeyEncoded = deviceKeyEncoded.replace("#0","");
        }

        byte[] decodedBytes = Base64.getUrlDecoder().decode(deviceKeyEncoded);
        String decodedJson = new String(decodedBytes);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> jwk = mapper.readValue(decodedJson, Map.class);

        Map<Object, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);  // kty: EC2
        coseKey.put(3, -7); // alg: ES256 (ECDSA with SHA-256)

        if (jwk.containsKey("kid")) {
            // Pass through the key ID if it exists in the source JWK
            coseKey.put(2, ((String) jwk.get("kid")).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }


        // Map curve
        String crv = (String) jwk.get("crv");
        switch (crv) {
            case "P-256" -> coseKey.put(-1, 1);
            case "P-384" -> coseKey.put(-1, 2);
            case "P-521" -> coseKey.put(-1, 3);
            case null, default -> throw new IllegalArgumentException("Unsupported curve for EC2 key type: " + crv);
        }

        coseKey.put(-2, Base64.getUrlDecoder().decode((String) jwk.get("x")));
        if (jwk.containsKey("y")) {
            coseKey.put(-3, Base64.getUrlDecoder().decode((String) jwk.get("y")));
        }

        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", coseKey);
        return deviceKeyInfo;
    }


    /**
     * Converts hex string to byte array
     */
    private static byte[] hexStringToByteArray(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4) + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
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