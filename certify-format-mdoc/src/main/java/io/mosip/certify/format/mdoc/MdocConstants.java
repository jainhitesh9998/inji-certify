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
    static final String __CBOR_TAG = "__cbor_tag";
    static final String __CBOR_VALUE = "__cbor_value";
    static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    static final String ERROR_TEMPLATE = "mdoc_template_processing_failed";
    static final String ERROR_SIGNING = "mdoc_signing_failed";

    private MdocConstants() {}
}
