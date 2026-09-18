package io.mosip.certify.spi;

/** The protocol a request arrived through; adapters set it, formatters and listeners may vary output by it. */
public enum ProtocolVersion {
    /** OpenID4VCI draft 13 (the 0.14.0 surface). */
    OID4VCI_D13,
    /** OpenID4VCI 1.0. */
    OID4VCI_1_0,
    /** W3C CCG VC-API issuer. */
    VC_API,
    /** Command line or embedded use with no wire protocol. */
    NONE
}
