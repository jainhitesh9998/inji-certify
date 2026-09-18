package io.mosip.certify.issuance;

import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.ProtocolVersion;

import java.util.Arrays;

/** Decides whether the caller may obtain a configuration; adapters may replace it (authorization_details, client policies). */
@FunctionalInterface
public interface AuthorizationPolicy {

    void check(Authorization authorization, CredentialConfiguration configuration, ProtocolVersion protocol) throws IssuanceException;

    /**
     * Today's rule: a holder token whose {@code scope} contains the configuration's scope. No token is accepted
     * only for supplied-credential configurations reached without a wire protocol (CLI) or through VC-API,
     * whose adapter authenticates the client itself.
     */
    AuthorizationPolicy SCOPE = (authorization, configuration, protocol) -> {
        if (!authorization.isPresent()) {
            boolean trustedPath = protocol == ProtocolVersion.NONE || protocol == ProtocolVersion.VC_API;
            if (trustedPath && configuration.strategy() == IssuanceStrategy.SUPPLIED) {
                return;
            }
            throw new IssuanceException(IssuanceException.NOT_AUTHENTICATED, "No authorization presented");
        }
        boolean matches = Arrays.stream(authorization.scope().split(" ")).anyMatch(s -> s.equals(configuration.scope()));
        if (!matches) {
            throw new IssuanceException(IssuanceException.INVALID_SCOPE,
                    "Scope does not authorize credential configuration " + configuration.id());
        }
    };
}
