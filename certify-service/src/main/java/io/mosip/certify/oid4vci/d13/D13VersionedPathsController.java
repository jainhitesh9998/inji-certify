package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.deprecation.DeprecatedEndpoint;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** The 0.14.0 versioned paths: same body as {@link D13CredentialController}, the answer echoes {@code format}. */
@RestController
@RequestMapping("/issuance")
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = {"enabled", "versioned-paths.enabled"}, havingValue = "true", matchIfMissing = true)
public class D13VersionedPathsController {

    public static final String DEPRECATION_NAME = "oid4vci-d13-versioned-credential";

    private final D13IssuanceHandler handler;

    public D13VersionedPathsController(D13IssuanceHandler handler) {
        this.handler = handler;
    }

    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = D13CredentialController.SINCE, replacement = D13CredentialController.REPLACEMENT)
    @PostMapping(value = "/vd12/credential", produces = "application/json")
    public Map<String, Object> vd12(@Valid @RequestBody D13CredentialRequest request) {
        return handler.issue(request, true);
    }

    @DeprecatedEndpoint(name = DEPRECATION_NAME, since = D13CredentialController.SINCE, replacement = D13CredentialController.REPLACEMENT)
    @PostMapping(value = "/vd11/credential", produces = "application/json")
    public Map<String, Object> vd11(@Valid @RequestBody D13CredentialRequest request) {
        return handler.issue(request, true);
    }
}
