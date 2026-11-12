package io.mosip.certify.format.mdoc;

/** The document keys the mDoc template contract uses (mirrors certify-core's Constants for the legacy path). */
final class MdocConstants {
    static final String VALIDITY_INFO = "validityInfo";
    static final String VALID_FROM = "validFrom";
    static final String VALID_UNTIL = "validUntil";
    static final String SIGNED = "signed";
    static final String NAMESPACES = "nameSpaces";
    static final String DOCTYPE = "docType";
    static final String DIGEST_ID = "digestID";
    static final String ELEMENT_IDENTIFIER = "elementIdentifier";
    static final String ELEMENT_VALUE = "elementValue";
    static final String _HOLDER_ID = "_holderId";
    static final String DID_URL = "didUrl";
    static final String DID_JWK_PREFIX = "did:jwk:";
    static final String DID_KEY_PREFIX = "did:key:";
    static final String __CBOR_TAG = "__cbor_tag";
    static final String __CBOR_VALUE = "__cbor_value";

    /** ISO/IEC 18013-5 9.1.2.4: {@code tdate = #6.0(tstr)} in RFC 3339, without fractional seconds (20 characters). */
    static final int CBOR_TAG_TDATE = 0;
    /** {@code full-date = #6.1004(tstr)}: {@code YYYY-MM-DD}. */
    static final int CBOR_TAG_FULL_DATE = 1004;
    static final String TDATE_PATTERN = "uuuu-MM-dd'T'HH:mm:ss'Z'";

    static final String ERROR_TEMPLATE = "mdoc_template_processing_failed";
    static final String ERROR_SIGNING = "mdoc_signing_failed";
    /**
     * The holder's proof carries no device key the MSO can bind to. The code is OpenID4VCI's {@code invalid_proof} so the
     * core answers 400 rather than 500: the caller chose the key (docs/design/20-mdl-issuer.md G6).
     */
    static final String ERROR_HOLDER_KEY = "invalid_proof";

    private MdocConstants() {}
}
