package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.deprecation.DeprecatedEndpoint;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * {@code POST /issuance/credential} with a draft-13 body (the 1.0 body on the same path stays with the compatibility
 * controller, see {@link D13Body}). Deprecated from day one: {@code Deprecation} and {@code Link} headers, the
 * {@code certify.deprecated.calls} counter and the {@code mosip.certify.deprecated.oid4vci-d13-credential.enabled}
 * kill switch come from {@link DeprecatedEndpoint}.
 */
@RestController
@RequestMapping("/issuance")
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13CredentialController {

    public static final String DEPRECATION_NAME = "oid4vci-d13-credential";
    static final String SINCE = "2026-09-19";
    static final String REPLACEMENT = "/oid4vci/credential";

    private final D13IssuanceHandler handler;

    public D13CredentialController(D13IssuanceHandler handler) {
        this.handler = handler;
    }

    @D13Body
    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = SINCE, replacement = REPLACEMENT)
    @PostMapping(value = "/credential", produces = "application/json")
    public Map<String, Object> credential(@Valid @RequestBody D13CredentialRequest request) {
        return handler.issue(request, false);
    }
}
