package io.mosip.certify.oid4vci;

import io.mosip.certify.issuance.IssuanceException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The OpenID4VCI 1.0 error mapping of {@code /oid4vci/credential}: {@code credential_request_denied} (8.3.1.2) is a
 * client error carrying its own code, not the 500 the old data-source failures produced.
 */
class Oid4vciErrorMappingTest {

    private final Oid4vciCredentialController controller =
            new Oid4vciCredentialController(null, null, null, null, Oid4vciIssuer.derive("https://issuer.example", null), null, null);

    @Test
    void credentialRequestDeniedIsA400WithItsOwnCode() {
        ResponseEntity<Map<String, String>> response = controller.issuanceError(
                new IssuanceException(IssuanceException.CREDENTIAL_REQUEST_DENIED, "No data in data source 'mdl-demo'"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("credential_request_denied", response.getBody().get("error"));
        assertEquals("No data in data source 'mdl-demo'", response.getBody().get("error_description"));
    }

    @Test
    void issuanceFailedStaysAServerError() {
        ResponseEntity<Map<String, String>> response = controller.issuanceError(
                new IssuanceException(IssuanceException.ISSUANCE_FAILED, "boom"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("server_error", response.getBody().get("error"));
    }
}
