package io.mosip.certify.format.mdoc;

import io.mosip.certify.spi.FormatException;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.MemoryCacheImageInputStream;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * ISO/IEC 18013-5 7.2.1: what an {@code org.iso.18013.5.1.mDL} must contain. A document that does not is refused before it
 * is signed, with a message that names the element and the clause, so an operator sees which template value is wrong
 * rather than a verifier refusing the credential later (CLAUDE.md non-negotiable 2).
 *
 * <p>The checks are: every mandatory element of Table 5 is present; {@code portrait} is a JPEG that really decodes
 * (this issuer accepts JPEG portraits only, a compliant subset of Table 5's JPEG or JPEG 2000; decision log
 * 2026-11-13); {@code issuing_country} is an ISO 3166-1 alpha-2 code in upper case; {@code un_distinguishing_sign} is
 * 1-3 upper-case Latin letters (the UN distinguishing sign, e.g. {@code IND}); {@code issuing_jurisdiction}, when
 * present, is an ISO 3166-2 subdivision of {@code issuing_country}; {@code expiry_date} lies after the issuance instant.
 * At signing time the country is compared with the subject {@code C} of the document signer certificate: a document
 * whose issuer is not the country the DSC belongs to is not validly signed (7.2.1, Annex B).
 */
final class MdocDataModelValidator {

    static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = MdocElementTypes.MDL_NAMESPACE;

    /** JPEG: SOI marker {@code FF D8} followed by the first marker's {@code FF}. */
    private static final byte[] JPEG_SOI = {(byte) 0xff, (byte) 0xd8, (byte) 0xff};
    /** JPEG: EOI marker {@code FF D9}, the last two bytes of a complete file. */
    private static final byte[] JPEG_EOI = {(byte) 0xff, (byte) 0xd9};
    /** The largest portrait accepted, in bytes: a portrait is a face image, not a document scan. */
    static final int PORTRAIT_MAX_BYTES = 1024 * 1024;
    /** The largest portrait accepted, in pixels (4096 x 4096), checked from the header before anything is decoded. */
    static final long PORTRAIT_MAX_PIXELS = 4096L * 4096L;
    /** ISO 3166-2 subdivision code: the alpha-2 country, a hyphen, and one to three alphanumerics. */
    private static final java.util.regex.Pattern SUBDIVISION = java.util.regex.Pattern.compile("([A-Z]{2})-[A-Z0-9]{1,3}");
    /** The UN distinguishing sign of the issuing state (1949/1968 conventions): one to three upper-case Latin letters. */
    private static final java.util.regex.Pattern UN_SIGN = java.util.regex.Pattern.compile("[A-Z]{1,3}");
    private static final DateTimeFormatter FULL_DATE = DateTimeFormatter.ofPattern(MdocConstants.FULL_DATE_PATTERN)
            .withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter TDATE = DateTimeFormatter.ofPattern(MdocConstants.TDATE_PATTERN)
            .withResolverStyle(ResolverStyle.STRICT);

    private static final Set<String> COUNTRIES = Set.of(Locale.getISOCountries());
    /** ISO/IEC 5218: 0 not known, 1 male, 2 female, 9 not applicable. */
    private static final Set<Long> SEX_CODES = Set.of(0L, 1L, 2L, 9L);

    /** Validates the element values of a document; {@code elements} is namespace to element identifier to typed value. */
    void validate(String docType, Map<String, Map<String, Object>> elements) {
        validate(docType, elements, null);
    }

    /**
     * Validates the element values of a document issued at {@code now} (when known): as {@link #validate(String, Map)}, and
     * an mDL whose {@code expiry_date} is not after the issuance instant is refused, since it would be expired on arrival.
     */
    void validate(String docType, Map<String, Map<String, Object>> elements, Instant now) {
        if (!MDL_DOCTYPE.equals(docType)) {
            return; // other document types carry their own data model
        }
        Map<String, Object> mdl = elements == null ? null : elements.get(NAMESPACE);
        if (mdl == null || mdl.isEmpty()) {
            throw invalid("an " + MDL_DOCTYPE + " carries no " + NAMESPACE + " namespace with the elements of Table 5");
        }
        List<String> missing = new ArrayList<>();
        for (String mandatory : MdocElementTypes.MDL_MANDATORY) {
            if (!mdl.containsKey(mandatory)) {
                missing.add(mandatory);
            }
        }
        if (!missing.isEmpty()) {
            missing.sort(null);
            throw invalid("the mDL is missing the mandatory element(s) " + String.join(", ", missing)
                    + " (ISO/IEC 18013-5 7.2.1 Table 5)");
        }
        typeCheck(mdl);
        requireByteString(mdl, "portrait");
        portraitIsAJpeg((byte[]) mdl.get("portrait"));
        unDistinguishingSign(mdl.get("un_distinguishing_sign"));
        String issuingCountry = country("issuing_country", mdl.get("issuing_country"));
        if (mdl.containsKey("issuing_jurisdiction")) {
            jurisdiction(mdl.get("issuing_jurisdiction"), issuingCountry);
        }
        Instant expiry = dateInstant("expiry_date", mdl.get("expiry_date"));
        if (now != null && !expiry.isAfter(now.truncatedTo(java.time.temporal.ChronoUnit.SECONDS))) {
            throw invalid("expiry_date " + mdl.get("expiry_date") + " is not after the issuance instant " + now
                    + "; an mDL that is already expired is not issued (ISO/IEC 18013-5 7.2.1)");
        }
        if (mdl.containsKey("nationality")) {
            country("nationality", mdl.get("nationality"));
        }
        if (mdl.containsKey("resident_country")) {
            country("resident_country", mdl.get("resident_country"));
        }
        if (mdl.get("sex") instanceof Number sex && !SEX_CODES.contains(sex.longValue())) {
            throw invalid("sex is " + sex + "; ISO/IEC 5218 allows only 0 (not known), 1 (male), 2 (female) or 9 (not applicable)");
        }
    }

    /** Every Table 5 element that is present carries a value of the type the table declares (7.2.1). */
    private static void typeCheck(Map<String, Object> mdl) {
        for (Map.Entry<String, Object> element : mdl.entrySet()) {
            Optional<MdocElementTypes.Type> type = MdocElementTypes.builtInType(NAMESPACE, element.getKey());
            if (type.isEmpty()) {
                continue;
            }
            Object value = element.getValue();
            boolean matches = switch (type.get()) {
                case TSTR -> value instanceof String;
                case UINT -> value instanceof Number number && number.longValue() >= 0;
                case BOOL -> value instanceof Boolean;
                case BSTR -> value instanceof byte[];
                case FULL_DATE -> value instanceof String text && isFullDate(text);
                case TDATE -> value instanceof String text && isTdate(text);
                case FULL_DATE_OR_TDATE -> value instanceof String text && (isFullDate(text) || isTdate(text));
                case DRIVING_PRIVILEGES, ARRAY -> value instanceof List<?>;
            };
            if (!matches) {
                throw invalid(element.getKey() + " must be a " + type.get().name().toLowerCase(Locale.ROOT).replace('_', '-')
                        + " (ISO/IEC 18013-5 7.2.1 Table 5), was " + typeName(value));
            }
        }
    }

    private static boolean isFullDate(String value) {
        try {
            LocalDate.parse(value, FULL_DATE);
            return value.matches("\\d{4}-\\d{2}-\\d{2}");
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    private static boolean isTdate(String value) {
        try {
            TDATE.parse(value);
            return value.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /**
     * The instant an mDL expires, from its {@code expiry_date} (a {@code full-date} counts from 00:00:00Z of that day,
     * so the MSO never claims a validity into the day the document expires), or {@code null} when the document is not
     * an mDL or carries no expiry. The MSO {@code validUntil} is capped at it (D7).
     */
    static Instant documentExpiry(String docType, Map<String, Map<String, Object>> elements) {
        if (!MDL_DOCTYPE.equals(docType) || elements == null || elements.get(NAMESPACE) == null
                || elements.get(NAMESPACE).get("expiry_date") == null) {
            return null;
        }
        return dateInstant("expiry_date", elements.get(NAMESPACE).get("expiry_date"));
    }

    private static Instant dateInstant(String element, Object value) {
        if (value instanceof String text && isFullDate(text)) {
            return LocalDate.parse(text, FULL_DATE).atStartOfDay(ZoneOffset.UTC).toInstant();
        }
        if (value instanceof String text && isTdate(text)) {
            return Instant.parse(text);
        }
        throw invalid(element + " must be a full-date or a tdate (ISO/IEC 18013-5 7.2.1 Table 5), was " + typeName(value));
    }

    /**
     * The DSC's subject {@code C} must be the document's {@code issuing_country}: a DSC issued to another country cannot
     * sign this mDL (7.2.1, Annex B B.1.2). Called from the signing step, where the certificate is known.
     */
    void validateAgainstCertificate(String docType, Map<String, Map<String, Object>> elements, X509Certificate leaf) {
        if (!MDL_DOCTYPE.equals(docType) || leaf == null || elements == null) {
            return;
        }
        Map<String, Object> mdl = elements.get(NAMESPACE);
        if (mdl == null) {
            return;
        }
        String issuingCountry = country("issuing_country", mdl.get("issuing_country"));
        String certificateCountry = subjectCountry(leaf);
        if (certificateCountry == null) {
            throw invalid("the document signer certificate " + leaf.getSubjectX500Principal()
                    + " has no subject country (C), so it cannot sign a document for issuing_country " + issuingCountry);
        }
        if (!issuingCountry.equalsIgnoreCase(certificateCountry)) {
            throw invalid("issuing_country is " + issuingCountry + " but the document signer certificate belongs to "
                    + certificateCountry.toUpperCase(Locale.ROOT));
        }
    }

    /** The subject {@code C} of a certificate, or {@code null} when it has none. */
    static String subjectCountry(X509Certificate certificate) {
        String name = certificate.getSubjectX500Principal().getName(javax.security.auth.x500.X500Principal.RFC2253);
        try {
            for (Rdn rdn : new LdapName(name).getRdns()) {
                if ("C".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
        } catch (InvalidNameException e) {
            throw invalid("the document signer certificate subject " + name + " is not a parseable distinguished name");
        }
        return null;
    }

    private static void requireByteString(Map<String, Object> mdl, String element) {
        if (!(mdl.get(element) instanceof byte[])) {
            throw invalid(element + " must be a byte string (bstr), was " + typeName(mdl.get(element)));
        }
    }

    /**
     * The portrait must be a JPEG a verifier can decode (7.2.1 Table 5 allows JPEG or JPEG 2000; this issuer issues the
     * JPEG subset only, decision log 2026-11-13). In order, cheapest first: the byte size is capped; the file starts with
     * SOI ({@code FF D8 FF}) and ends with EOI ({@code FF D9}); the dimensions are read from the header and the pixel
     * count is capped before anything is decoded, so a small file declaring a huge image cannot exhaust memory; then the
     * image is decoded, and any decoder warning (a truncated or corrupt scan that ImageIO would otherwise paper over with
     * grey pixels) refuses it.
     */
    private static void portraitIsAJpeg(byte[] bytes) {
        if (bytes.length == 0) {
            throw invalid("portrait is empty; it must carry a JPEG image (ISO/IEC 18013-5 7.2.1)");
        }
        if (bytes.length > PORTRAIT_MAX_BYTES) {
            throw invalid("portrait is " + bytes.length + " bytes; this issuer accepts JPEG portraits of at most "
                    + PORTRAIT_MAX_BYTES + " bytes");
        }
        if (!startsAt(bytes, 0, JPEG_SOI)) {
            throw invalid("portrait is not a JPEG: it must start with the SOI marker FF D8 FF (this issuer accepts JPEG "
                    + "portraits only, ISO/IEC 18013-5 7.2.1); the first bytes are " + hex(Arrays.copyOf(bytes, Math.min(4, bytes.length))));
        }
        if (bytes.length < JPEG_SOI.length + JPEG_EOI.length || !startsAt(bytes, bytes.length - JPEG_EOI.length, JPEG_EOI)) {
            throw invalid("portrait is not a complete JPEG: it does not end with the EOI marker FF D9 (truncated?)");
        }
        Iterator<ImageReader> readers = ImageIO.getImageReadersByFormatName("jpeg");
        if (!readers.hasNext()) {
            throw invalid("portrait cannot be checked: this runtime has no JPEG reader");
        }
        ImageReader reader = readers.next();
        // in memory only: ImageIO.createImageInputStream may spill an InputStream to a temporary file cache
        try (ImageInputStream input = new MemoryCacheImageInputStream(new ByteArrayInputStream(bytes))) {
            reader.setInput(input, true, true);
            int width = reader.getWidth(0);
            int height = reader.getHeight(0);
            if (width <= 0 || height <= 0 || (long) width * height > PORTRAIT_MAX_PIXELS) {
                throw invalid("portrait declares " + width + "x" + height + " pixels; this issuer accepts JPEG portraits of at most "
                        + PORTRAIT_MAX_PIXELS + " pixels (4096x4096)");
            }
            List<String> warnings = new ArrayList<>();
            reader.addIIOReadWarningListener((source, warning) -> warnings.add(warning));
            BufferedImage image = reader.read(0);
            if (!warnings.isEmpty()) {
                throw invalid("portrait does not decode cleanly as a JPEG: " + String.join("; ", warnings));
            }
            if (image == null || image.getWidth() != width || image.getHeight() != height) {
                throw invalid("portrait does not decode to the " + width + "x" + height + " image its header declares");
            }
        } catch (IOException | RuntimeException e) {
            if (e instanceof FormatException formatException) {
                throw formatException;
            }
            throw invalid("portrait starts like a JPEG but does not decode to an image: " + e.getMessage());
        } finally {
            reader.dispose();
        }
    }

    /** The UN distinguishing sign of the issuing state (7.2.1 Table 5), e.g. {@code IND}: 1-3 upper-case Latin letters. */
    private static void unDistinguishingSign(Object value) {
        if (!(value instanceof String sign)) {
            throw invalid("un_distinguishing_sign must be a text string (tstr), was " + typeName(value));
        }
        if (!UN_SIGN.matcher(sign).matches()) {
            throw invalid("un_distinguishing_sign '" + sign + "' is not a UN distinguishing sign (1-3 upper-case Latin letters, "
                    + "e.g. IND)");
        }
    }

    /** {@code issuing_jurisdiction}: an ISO 3166-2 subdivision code ({@code CC-XXX}) of {@code issuing_country} (7.2.1 Table 5). */
    private static void jurisdiction(Object value, String issuingCountry) {
        if (!(value instanceof String code)) {
            throw invalid("issuing_jurisdiction must be a text string (tstr), was " + typeName(value));
        }
        java.util.regex.Matcher matcher = SUBDIVISION.matcher(code);
        if (!matcher.matches()) {
            throw invalid("issuing_jurisdiction '" + code + "' is not an ISO 3166-2 subdivision code (CC-XXX, e.g. IN-KA)");
        }
        if (!matcher.group(1).equals(issuingCountry)) {
            throw invalid("issuing_jurisdiction '" + code + "' is not a subdivision of issuing_country " + issuingCountry);
        }
    }

    /** ISO 3166-1 alpha-2, upper case (7.2.1 Table 5: {@code issuing_country}, {@code nationality}, {@code resident_country}). */
    private static String country(String element, Object value) {
        if (!(value instanceof String country)) {
            throw invalid(element + " must be a text string (tstr), was " + typeName(value));
        }
        if (country.length() != 2 || !country.equals(country.toUpperCase(Locale.ROOT))) {
            throw invalid(element + " '" + country + "' is not an upper-case ISO 3166-1 alpha-2 code");
        }
        if (!COUNTRIES.contains(country)) {
            throw invalid(element + " '" + country + "' is not an assigned ISO 3166-1 alpha-2 code");
        }
        return country;
    }

    private static boolean startsAt(byte[] bytes, int offset, byte[] prefix) {
        if (bytes.length < offset + prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[offset + i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            out.append(String.format("%02X ", b));
        }
        return out.toString().trim();
    }

    private static String typeName(Object value) {
        if (value == null) {
            return "nothing";
        }
        if (value instanceof byte[]) {
            return "a byte string";
        }
        if (value instanceof String) {
            return "a text string";
        }
        if (value instanceof Number) {
            return "a number";
        }
        if (value instanceof Boolean) {
            return "a boolean";
        }
        if (value instanceof Map) {
            return "a map";
        }
        if (value instanceof List) {
            return "an array";
        }
        return value.getClass().getSimpleName();
    }

    private static FormatException invalid(String message) {
        return new FormatException(MdocConstants.ERROR_DATA_MODEL, message);
    }
}
