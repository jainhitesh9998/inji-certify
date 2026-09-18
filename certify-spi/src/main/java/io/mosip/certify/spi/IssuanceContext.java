package io.mosip.certify.spi;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Everything an issuance step may need to know about the request it serves. Built once by the core per
 * command and passed, unchanged, to data sources, template engines, formatters, status providers and listeners.
 *
 * @param tenant         the tenant the request belongs to
 * @param authorization  what the caller proved
 * @param holders        holder bindings established from the proofs; one credential is issued per binding
 * @param protocol       the protocol the request arrived through
 * @param correlationId  request id for logs and the ledger
 * @param now            the instant the core uses for validity fields, fixed per request
 * @param protocolParams protocol-specific parameters the adapter forwards (e.g. requested claims, encryption)
 */
public record IssuanceContext(TenantContext tenant, Authorization authorization, List<HolderBinding> holders,
                              ProtocolVersion protocol, String correlationId, Instant now, Map<String, Object> protocolParams) {

    public IssuanceContext {
        Objects.requireNonNull(tenant, "tenant");
        authorization = authorization == null ? Authorization.NONE : authorization;
        holders = holders == null ? List.of() : List.copyOf(holders);
        protocol = protocol == null ? ProtocolVersion.NONE : protocol;
        now = now == null ? Instant.now() : now;
        protocolParams = protocolParams == null ? Map.of() : Map.copyOf(protocolParams);
    }
}
