package io.mosip.certify.format.mdoc;

import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.FormatException;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The element types of the mDL data model, ISO/IEC 18013-5 7.2.1 Table 5: which tags, integer widths and byte strings
 * an element's value needs. The table for namespace {@code org.iso.18013.5.1} is built in; a configuration may add or
 * override entries with {@code formatConfig.elementTypes} ({@code {<namespace>: {<element>: <type>}}}, decision D6).
 *
 * <p>Namespaces without a table keep the old date heuristic: an untyped namespace's {@code YYYY-MM-DD} string is still
 * encoded as {@code #6.1004}, which is what every pre-M-03 configuration relied on.
 */
public final class MdocElementTypes {

    /** The CBOR types of Table 5. */
    public enum Type {
        TSTR, UINT, BOOL, BSTR, FULL_DATE, TDATE, DRIVING_PRIVILEGES;

        static Optional<Type> parse(String value) {
            if (value == null) {
                return Optional.empty();
            }
            String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(" ", "_");
            if ("ARRAY".equals(normalized) || "DRIVINGPRIVILEGES".equals(normalized)) {
                return Optional.of(DRIVING_PRIVILEGES);
            }
            for (Type type : values()) {
                if (type.name().equals(normalized)) {
                    return Optional.of(type);
                }
            }
            return Optional.empty();
        }
    }

    static final String MDL_NAMESPACE = "org.iso.18013.5.1";

    /** The mandatory elements of Table 5: a {@code org.iso.18013.5.1.mDL} without one of them is not an mDL. */
    static final Set<String> MDL_MANDATORY = Set.of("family_name", "given_name", "birth_date", "issue_date", "expiry_date",
            "issuing_country", "issuing_authority", "document_number", "portrait", "driving_privileges", "un_distinguishing_sign");

    private static final Map<String, Type> MDL = mdlTable();

    private static final MdocElementTypes NONE = new MdocElementTypes(Map.of());

    private final Map<String, Map<String, Type>> tables;

    private MdocElementTypes(Map<String, Map<String, Type>> tables) {
        this.tables = tables;
    }

    /** No type table at all: every namespace takes the pre-M-03 heuristic. */
    public static MdocElementTypes none() {
        return NONE;
    }

    /** The built-in table plus the configuration's override (none when the configuration carries none). */
    public static MdocElementTypes forConfig(FormatConfig configuration) {
        Object raw = configuration == null || configuration.raw() == null ? null : configuration.raw().get(MdocConstants.ELEMENT_TYPES);
        return raw == null ? NONE : of(raw);
    }

    /** The built-in table plus {@code elementTypes}, a {@code {namespace: {element: type}}} map. */
    public static MdocElementTypes of(Object elementTypes) {
        if (!(elementTypes instanceof Map<?, ?> byNamespace)) {
            throw new FormatException(MdocConstants.ERROR_TEMPLATE,
                    MdocConstants.ELEMENT_TYPES + " must be a map of namespace to element to type, was " + elementTypes);
        }
        Map<String, Map<String, Type>> tables = new LinkedHashMap<>();
        for (Map.Entry<?, ?> namespace : byNamespace.entrySet()) {
            if (!(namespace.getValue() instanceof Map<?, ?> elements)) {
                throw new FormatException(MdocConstants.ERROR_TEMPLATE,
                        MdocConstants.ELEMENT_TYPES + "." + namespace.getKey() + " must map element identifiers to types");
            }
            Map<String, Type> byElement = new LinkedHashMap<>();
            for (Map.Entry<?, ?> element : elements.entrySet()) {
                Type type = Type.parse(element.getValue() == null ? null : String.valueOf(element.getValue()))
                        .orElseThrow(() -> new FormatException(MdocConstants.ERROR_TEMPLATE,
                                MdocConstants.ELEMENT_TYPES + "." + namespace.getKey() + "." + element.getKey() + " is not a known type: "
                                        + element.getValue() + " (expected one of tstr, uint, bool, bstr, full-date, tdate, driving_privileges)"));
                byElement.put(String.valueOf(element.getKey()), type);
            }
            tables.put(String.valueOf(namespace.getKey()), byElement);
        }
        return new MdocElementTypes(tables);
    }

    /** The type an element's value is encoded as, from the configuration's override or the built-in mDL table. */
    public Optional<Type> type(String namespace, String element) {
        Map<String, Type> override = tables.get(namespace);
        if (override != null && override.containsKey(element)) {
            return Optional.of(override.get(element));
        }
        if (MDL_NAMESPACE.equals(namespace) && MDL.containsKey(element)) {
            return Optional.of(MDL.get(element));
        }
        return Optional.empty();
    }

    /** Whether this element lives in the built-in mDL namespace (the validator's subject). */
    public static boolean isMdlNamespace(String namespace) {
        return MDL_NAMESPACE.equals(namespace);
    }

    private static Map<String, Type> mdlTable() {
        Map<String, Type> table = new LinkedHashMap<>();
        // 7.2.1 Table 5, mandatory
        table.put("family_name", Type.TSTR);
        table.put("given_name", Type.TSTR);
        table.put("birth_date", Type.FULL_DATE);
        table.put("issue_date", Type.FULL_DATE);
        table.put("expiry_date", Type.FULL_DATE);
        table.put("issuing_country", Type.TSTR);
        table.put("issuing_authority", Type.TSTR);
        table.put("document_number", Type.TSTR);
        table.put("portrait", Type.BSTR);
        table.put("driving_privileges", Type.DRIVING_PRIVILEGES);
        table.put("un_distinguishing_sign", Type.TSTR);
        // 7.2.1 Table 5, optional
        table.put("administrative_number", Type.TSTR);
        table.put("sex", Type.UINT);
        table.put("height", Type.UINT);
        table.put("weight", Type.UINT);
        table.put("eye_colour", Type.TSTR);
        table.put("hair_colour", Type.TSTR);
        table.put("birth_place", Type.TSTR);
        table.put("resident_address", Type.TSTR);
        table.put("portrait_capture_date", Type.TDATE);
        table.put("age_in_years", Type.UINT);
        table.put("age_birth_year", Type.UINT);
        for (String age : new String[] {"13", "16", "18", "21", "25", "60", "62", "65", "68", "70"}) {
            table.put("age_over_" + age, Type.BOOL);
        }
        table.put("issuing_jurisdiction", Type.TSTR);
        table.put("nationality", Type.TSTR);
        table.put("resident_city", Type.TSTR);
        table.put("resident_state", Type.TSTR);
        table.put("resident_postal_code", Type.TSTR);
        table.put("resident_country", Type.TSTR);
        table.put("family_name_national_character", Type.TSTR);
        table.put("given_name_national_character", Type.TSTR);
        table.put("signature_usual_mark", Type.BSTR);
        // biometric templates travel as bstr (18013-5 7.2.3)
        for (String kind : new String[] {"face", "finger", "iris", "signature", "retina"}) {
            table.put("biometric_template_" + kind, Type.BSTR);
        }
        return Map.copyOf(table);
    }
}
