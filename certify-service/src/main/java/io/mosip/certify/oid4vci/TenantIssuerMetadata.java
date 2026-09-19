package io.mosip.certify.oid4vci;

import com.authlete.cose.constants.COSEAlgorithms;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The OpenID4VCI 1.0 issuer metadata of a tenant other than {@code default}, built from the core's view of its
 * configurations (formatter fragments, the configuration's scope, binding methods, signing algorithms, proof types
 * and display) under the tenant's own issuer identifier. The default tenant keeps the document develop builds, so
 * the goldens stay untouched; a tenant's `display` and `authorization-servers` settings replace the deployment's in its document.
 */
@Component
public class TenantIssuerMetadata {

    static final Map<String, Integer> JOSE_TO_COSE = Map.of("ES256", COSEAlgorithms.ES256, "EdDSA", COSEAlgorithms.EdDSA,
            "ES256K", COSEAlgorithms.ES256K, "RS256", COSEAlgorithms.RS256);

    private final ConfigurationRegistry configurations;
    private final List<CredentialFormatter> formatters;
    private final Oid4vciProperties properties;
    private final io.mosip.certify.tenancy.TenancyProperties tenancy;

    public TenantIssuerMetadata(ConfigurationRegistry configurations, List<CredentialFormatter> formatters, Oid4vciProperties properties,
                                io.mosip.certify.tenancy.TenancyProperties tenancy) {
        this.properties = properties;
        this.tenancy = tenancy;
        this.configurations = configurations;
        this.formatters = formatters;
    }

    public Map<String, Object> document(TenantContext tenant, Oid4vciIssuer issuer, CredentialIssuerMetadataDTO deployment) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("credential_issuer", issuer.identifier());
        io.mosip.certify.tenancy.TenancyProperties.Tenant overrides = tenancy.tenant(tenant.tenantId());
        boolean ownAuthorizationServers = overrides != null && overrides.authorizationServers() != null && !overrides.authorizationServers().isEmpty();
        document.put("authorization_servers", ownAuthorizationServers ? overrides.authorizationServers() : deployment.getAuthorizationServers());
        document.put("credential_endpoint", issuer.credentialEndpoint());
        document.put("nonce_endpoint", issuer.nonceEndpoint());
        document.put("notification_endpoint", issuer.notificationEndpoint());
        if (properties.batch().size() > 1) {
            document.put("batch_credential_issuance", Map.of("batch_size", properties.batch().size()));
        }
        boolean ownDisplay = overrides != null && overrides.display() != null && !overrides.display().isEmpty();
        if (ownDisplay) {
            document.put("display", overrides.display());
        } else if (deployment.getDisplay() != null) {
            document.put("display", deployment.getDisplay());
        }
        Map<String, Object> supported = new LinkedHashMap<>();
        for (CredentialConfiguration configuration : configurations.all(tenant.tenantId())) {
            supported.put(configuration.id(), entry(configuration));
        }
        document.put("credential_configurations_supported", supported);
        return document;
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> entry(CredentialConfiguration configuration) {
        Map<String, Object> raw = configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
        Map<String, Object> entry = new LinkedHashMap<>();
        formatters.stream().filter(f -> f.handles(configuration.format())).findFirst()
                .ifPresent(f -> entry.putAll(f.metadataFragment(configuration, ProtocolVersion.OID4VCI_1_0)));
        entry.putIfAbsent("format", configuration.format());
        entry.put("scope", configuration.scope());
        put(entry, "cryptographic_binding_methods_supported", raw.get("cryptographicBindingMethodsSupported"));
        // the JOSE name of the configured algorithm (the legacy column holds the suite name); COSE identifiers for mDoc
        if (configuration.signing() != null && configuration.signing().algorithm() != null) {
            String jose = configuration.signing().algorithm().joseName();
            Object value = "mso_mdoc".equals(configuration.format()) ? JOSE_TO_COSE.get(jose) : jose;
            if (value != null) {
                entry.put("credential_signing_alg_values_supported", List.of(value));
            }
        }
        put(entry, "proof_types_supported", raw.get("proofTypesSupported"));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("display", configuration.display() == null ? List.of() : configuration.display().display());
        List<Map<String, Object>> claims = new ArrayList<>();
        switch (configuration.format()) {
            case "mso_mdoc" -> {
                Object namespaces = raw.get("msoMdocClaims");
                if (namespaces instanceof Map<?, ?> byNamespace) {
                    byNamespace.forEach((namespace, inner) -> {
                        if (inner instanceof Map<?, ?> names) {
                            names.forEach((name, claim) -> claims.add(claim(List.of(String.valueOf(namespace), String.valueOf(name)), claim)));
                        }
                    });
                }
            }
            case "dc+sd-jwt", "vc+sd-jwt" -> {
                Object names = raw.get("sdJwtClaims");
                if (names instanceof Map<?, ?> map) {
                    map.forEach((name, claim) -> claims.add(claim(List.of(String.valueOf(name)), claim)));
                }
            }
            default -> {
                Map<String, Object> names = configuration.display() == null ? Map.of() : configuration.display().claims();
                names.forEach((name, claim) -> claims.add(claim(List.of(name), claim)));
            }
        }
        metadata.put("claims", claims);
        entry.put("credential_metadata", metadata);
        return entry;
    }

    private static Map<String, Object> claim(List<String> path, Object stored) {
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("path", path);
        if (stored instanceof Map<?, ?> map) {
            claim.put("display", map.get("display"));
            if (Boolean.TRUE.equals(map.get("mandatory"))) {
                claim.put("mandatory", true);
            }
        } else {
            claim.put("display", null);
        }
        return claim;
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
