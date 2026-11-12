package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.issuance.IssuanceException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The draft-13 error answers: a 1.0 code draft 13 does not know is mapped to the one it does (M-10 review). */
class D13ErrorAdviceTest {

    private final D13ErrorAdvice advice = new D13ErrorAdvice(null);

    @Test
    void credentialRequestDeniedBecomesInvalidCredentialRequest() {
        ResponseEntity<Map<String, Object>> response = advice.issuanceError(
                new IssuanceException(IssuanceException.CREDENTIAL_REQUEST_DENIED, "no record for sub"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(IssuanceException.INVALID_CREDENTIAL_REQUEST, response.getBody().get("error"),
                "draft 13 has no credential_request_denied");
        assertEquals("no record for sub", response.getBody().get("error_description"));
    }

    @Test
    void otherClientErrorsKeepTheirCodeAnd400() {
        ResponseEntity<Map<String, Object>> response = advice.issuanceError(
                new IssuanceException(IssuanceException.INVALID_PROOF, "bad proof"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(IssuanceException.INVALID_PROOF, response.getBody().get("error"));
    }
}
