package io.mosip.certify.spi;

/** How a credential configuration obtains its unsigned credential. */
public enum IssuanceStrategy {
    /** Fetch claims from a {@link CredentialDataSource}, render with a {@link TemplateEngine}, build with the formatter. */
    TEMPLATE,
    /** Delegate the whole credential to an {@link ExternalIssuer} (the VCIssuance plugin mode). */
    EXTERNAL,
    /** The caller supplied the credential body (VC-API, {@code certify sign}); the formatter validates and signs it. */
    SUPPLIED
}
