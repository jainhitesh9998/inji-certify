package io.mosip.certify.issuance;

import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ProofValidator.NonceCheck;
import io.mosip.certify.spi.ProofValidator.ProofInput;
import io.mosip.certify.spi.ProofValidator.ProofPolicy;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * What every protocol adapter and the CLI hand to {@link IssuanceService}: which configuration, on whose
 * authority, with which proofs, and for OpenID4VCI draft 13 a (format, selector) pair instead of an id.
 *
 * @param tenant                    resolved by the adapter's {@link io.mosip.certify.spi.TenantResolver}
 * @param credentialConfigurationId the configuration id, or {@code null} when {@code selector} is used
 * @param selector                  draft-13 style lookup, or {@code null}
 * @param authorization             what the caller proved
 * @param proofs                    holder proofs as received; may be empty for {@code SUPPLIED} configurations
 * @param proofPolicy               what the adapter requires of proofs (audience, nonce, algorithms)
 * @param nonceCheck                the adapter's nonce store, or {@link NonceCheck#NONE}
 * @param suppliedCredential        a caller-supplied document (VC-API, {@code certify sign}), if any
 * @param protocol                  the protocol the request arrived through
 * @param protocolParams            protocol-specific parameters forwarded to formatters and listeners
 * @param correlationId             request id for logs and the ledger
 * @param maxCredentials            the most credentials one request may yield (a proof may bind several holders), 0 for no cap
 */
public record IssuanceCommand(TenantContext tenant, String credentialConfigurationId, ConfigurationSelector selector,
                              Authorization authorization, List<ProofInput> proofs, ProofPolicy proofPolicy, NonceCheck nonceCheck,
                              Optional<Map<String, Object>> suppliedCredential, ProtocolVersion protocol,
                              Map<String, Object> protocolParams, String correlationId, int maxCredentials) {

    public IssuanceCommand {
        tenant = tenant == null ? TenantContext.DEFAULT : tenant;
        authorization = authorization == null ? Authorization.NONE : authorization;
        proofs = proofs == null ? List.of() : List.copyOf(proofs);
        nonceCheck = nonceCheck == null ? NonceCheck.NONE : nonceCheck;
        suppliedCredential = suppliedCredential == null ? Optional.empty() : suppliedCredential;
        protocol = protocol == null ? ProtocolVersion.NONE : protocol;
        protocolParams = protocolParams == null ? Map.of() : Map.copyOf(protocolParams);
        if (credentialConfigurationId == null && selector == null) {
            throw new IllegalArgumentException("IssuanceCommand needs a credentialConfigurationId or a selector");
        }
    }

    /** Draft-13 lookup: the format and the format's selector (types plus context, vct, or doctype). */
    public record ConfigurationSelector(String format, String selectorKey) {
        public ConfigurationSelector {
            Objects.requireNonNull(format, "format");
            Objects.requireNonNull(selectorKey, "selectorKey");
        }
    }

    public static Builder builder(String credentialConfigurationId) {
        return new Builder().credentialConfigurationId(credentialConfigurationId);
    }

    public static final class Builder {
        private TenantContext tenant = TenantContext.DEFAULT;
        private String credentialConfigurationId;
        private ConfigurationSelector selector;
        private Authorization authorization = Authorization.NONE;
        private List<ProofInput> proofs = List.of();
        private ProofPolicy proofPolicy;
        private NonceCheck nonceCheck = NonceCheck.NONE;
        private Optional<Map<String, Object>> suppliedCredential = Optional.empty();
        private ProtocolVersion protocol = ProtocolVersion.NONE;
        private Map<String, Object> protocolParams = Map.of();
        private String correlationId;
        private int maxCredentials;

        public Builder tenant(TenantContext v) { tenant = v; return this; }
        public Builder credentialConfigurationId(String v) { credentialConfigurationId = v; return this; }
        public Builder selector(ConfigurationSelector v) { selector = v; return this; }
        public Builder authorization(Authorization v) { authorization = v; return this; }
        public Builder proofs(List<ProofInput> v) { proofs = v; return this; }
        public Builder proofPolicy(ProofPolicy v) { proofPolicy = v; return this; }
        public Builder nonceCheck(NonceCheck v) { nonceCheck = v; return this; }
        public Builder suppliedCredential(Map<String, Object> v) { suppliedCredential = Optional.ofNullable(v); return this; }
        public Builder protocol(ProtocolVersion v) { protocol = v; return this; }
        public Builder protocolParams(Map<String, Object> v) { protocolParams = v; return this; }
        public Builder correlationId(String v) { correlationId = v; return this; }
        public Builder maxCredentials(int v) { maxCredentials = v; return this; }

        public IssuanceCommand build() {
            return new IssuanceCommand(tenant, credentialConfigurationId, selector, authorization, proofs, proofPolicy, nonceCheck,
                    suppliedCredential, protocol, protocolParams, correlationId, maxCredentials);
        }
    }
}
