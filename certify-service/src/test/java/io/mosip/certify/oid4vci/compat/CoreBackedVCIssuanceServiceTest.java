package io.mosip.certify.oid4vci.compat;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.issuance.IssuanceException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class CoreBackedVCIssuanceServiceTest {

    @Test
    void coreErrorsBecomeTheLegacyExceptions() {
        assertInstanceOf(NotAuthenticatedException.class, CoreBackedVCIssuanceService.legacy(new IssuanceException(IssuanceException.NOT_AUTHENTICATED, "x")));
        CertifyException unknown = CoreBackedVCIssuanceService.legacy(new IssuanceException(IssuanceException.INVALID_CREDENTIAL_REQUEST, "No credential configuration with id X"));
        assertEquals("invalid_credential_request", unknown.getErrorCode());
        assertEquals("No credential configuration found for credential_configuration_id", unknown.getMessage());
        CertifyException nonce = CoreBackedVCIssuanceService.legacy(new IssuanceException(IssuanceException.INVALID_NONCE, "c_nonce is invalid or expired"));
        assertEquals("invalid_nonce", nonce.getErrorCode());
        assertEquals("c_nonce is invalid or expired", nonce.getMessage());
        assertEquals("invalid_scope", CoreBackedVCIssuanceService.legacy(new IssuanceException(IssuanceException.INVALID_SCOPE, "x")).getErrorCode());
        assertEquals("vc_issuance_failed", CoreBackedVCIssuanceService.legacy(new IssuanceException(IssuanceException.ISSUANCE_FAILED, "boom")).getErrorCode());
    }
}
