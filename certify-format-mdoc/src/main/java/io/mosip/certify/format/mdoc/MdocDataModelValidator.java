package io.mosip.certify.format.mdoc;

import io.mosip.certify.spi.FormatException;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * ISO/IEC 18013-5 7.2.1: what an {@code org.iso.18013.5.1.mDL} must contain. A document that does not is refused before it
 * is signed, with a message that names the element and the clause, so an operator sees which template value is wrong
 * rather than a verifier refusing the credential later (CLAUDE.md non-negotiable 2).
 *
 * <p>The checks are: every mandatory element of Table 5 is present; {@code portrait} is a byte string carrying a JPEG
 * ({@code FF D8 FF}) or JPEG 2000 codestream signature; {@code issuing_country} is an ISO 3166-1 alpha-2 code in upper
 * case; {@code un_distinguishing_sign} is a text string. At signing time the country is compared with the subject
 * {@code C} of the document signer certificate: a document whose issuer is not the country the DSC belongs to is not
 * validly signed (7.2.1, Annex B).
 */
final class MdocDataModelValidator {

    static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = MdocElementTypes.MDL_NAMESPACE;

    /** JPEG: SOI marker {@code FF D8 FF}. */
    private static final byte[] JPEG = {(byte) 0xff, (byte) 0xd8, (byte) 0xff};
    /** JPEG 2000 codestream: SOC marker {@code FF 4F}. */
    private static final byte[] JPEG2000 = {(byte) 0xff, (byte) 0x4f};
    /** JPEG 2000 JP2 file signature box: {@code 00 00 00 0C 6A 50 20 20 0D 0A 87 0A}. */
    private static final byte[] JP2 = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, (byte) 0x87, 0x0A};

    private static final Set<String> COUNTRIES = Set.of(Locale.getISOCountries());

    /** Validates the element values of a document; {@code elements} is namespace to element identifier to typed value. */
    void validate(String docType, Map<String, Map<String, Object>> elements) {
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
        requireByteString(mdl, "portrait");
        portraitIsAnImage(mdl.get("portrait"));
        requireText(mdl, "un_distinguishing_sign");
        country(mdl.get("issuing_country"));
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
        String issuingCountry = country(mdl.get("issuing_country"));
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

    private static void portraitIsAnImage(Object portrait) {
        byte[] bytes = (byte[]) portrait;
        if (bytes.length == 0) {
            throw invalid("portrait is empty; it must carry a JPEG or JPEG 2000 image (ISO/IEC 18013-5 7.2.1)");
        }
        if (startsWith(bytes, JPEG) || startsWith(bytes, JPEG2000) || startsWith(bytes, JP2)) {
            return;
        }
        throw invalid("portrait does not start with a JPEG (FF D8 FF), JPEG 2000 codestream (FF 4F) or JP2 signature; "
                + "the first bytes are " + hex(Arrays.copyOf(bytes, Math.min(4, bytes.length))));
    }

    private static void requireText(Map<String, Object> mdl, String element) {
        if (!(mdl.get(element) instanceof String)) {
            throw invalid(element + " must be a text string (tstr), was " + typeName(mdl.get(element)));
        }
    }

    /** ISO 3166-1 alpha-2, upper case (7.2.1 Table 5: {@code issuing_country}). */
    private static String country(Object value) {
        if (!(value instanceof String country)) {
            throw invalid("issuing_country must be a text string (tstr), was " + typeName(value));
        }
        if (country.length() != 2 || !country.equals(country.toUpperCase(Locale.ROOT))) {
            throw invalid("issuing_country '" + country + "' is not an upper-case ISO 3166-1 alpha-2 code");
        }
        if (!COUNTRIES.contains(country)) {
            throw invalid("issuing_country '" + country + "' is not an assigned ISO 3166-1 alpha-2 code");
        }
        return country;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
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
