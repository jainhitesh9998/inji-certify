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
     * Today's rule: a holder token whose {@code scope} contains the configuration's scope. Supplied-credential
     * configurations reached through VC-API (the adapter authenticates the client) or without a wire protocol (CLI)
     * need no holder token.
     */
    AuthorizationPolicy SCOPE = (authorization, configuration, protocol) -> {
        if (protocol == ProtocolVersion.VC_API && configuration.strategy() == IssuanceStrategy.SUPPLIED) {
            return; // the VC-API adapter authenticated the client and checked what it may issue
        }
        if (!authorization.isPresent()) {
            if (protocol == ProtocolVersion.NONE && configuration.strategy() == IssuanceStrategy.SUPPLIED) {
                return; // the CLI
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
