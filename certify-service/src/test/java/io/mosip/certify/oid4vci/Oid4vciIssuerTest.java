package io.mosip.certify.oid4vci;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The new surface's identifier is {domain}{servletPath}/oid4vci whatever shape mosip.certify.identifier has. */
class Oid4vciIssuerTest {

    @Test
    void aBareDomainIdentifierGetsTheServletPath() {
        Oid4vciIssuer issuer = Oid4vciIssuer.derive("http://localhost:8090", "/v1/certify", null);
        assertEquals("http://localhost:8090/v1/certify/oid4vci", issuer.identifier());
        assertEquals("http://localhost:8090/v1/certify/oid4vci/credential", issuer.credentialEndpoint());
        assertEquals("http://localhost:8090/v1/certify/oid4vci/nonce", issuer.nonceEndpoint());
        assertEquals("http://localhost:8090/v1/certify/oid4vci/notification", issuer.notificationEndpoint());
    }

    @Test
    void anIdentifierThatAlreadyEndsWithTheServletPathIsKept() {
        assertEquals("http://localhost:8090/v1/certify/oid4vci", Oid4vciIssuer.derive("http://localhost:8090/v1/certify/", "/v1/certify", null).identifier());
        assertEquals("http://localhost:8090/v1/certify/oid4vci", Oid4vciIssuer.derive("http://localhost:8090/v1/certify", "/v1/certify/", null).identifier());
    }

    @Test
    void noServletPathAndTheConfiguredIdentifierWin() {
        assertEquals("http://localhost:8090/oid4vci", Oid4vciIssuer.derive("http://localhost:8090", "", null).identifier());
        assertEquals("http://localhost:8090/oid4vci", Oid4vciIssuer.derive("http://localhost:8090", "/", null).identifier());
        assertEquals("https://issuer.example/vci", Oid4vciIssuer.derive("http://localhost:8090", "/v1/certify", "https://issuer.example/vci/").identifier());
        assertEquals("http://localhost:8090/v1/certify/oid4vci", Oid4vciIssuer.derive("http://localhost:8090/v1/certify", null).identifier());
    }
}
