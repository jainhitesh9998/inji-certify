package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialRegistry;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The versioned issuer metadata of 0.14.0 ({@code ?version=latest|vd12|vd11}) built from the same rows as the
 * current document: {@code latest} is the draft-13 shape (per configuration {@code display}, {@code order},
 * {@code credential_definition.credentialSubject} or {@code claims}, JOSE names in
 * {@code credential_signing_alg_values_supported}); {@code vd12} keys {@code credentials_supported} by id with
 * {@code cryptographic_suites_supported}; {@code vd11} lists them with an {@code id}. An unknown version raises
 * {@code UNSUPPORTED_METADATA_VERSION}, which the service's advice answers as 0.14.0 did.
 */
@Component
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13MetadataService {

    public static final String VERSION_LATEST = "latest";
    public static final String VERSION_VD12 = "vd12";
    public static final String VERSION_VD11 = "vd11";
    public static final String ERROR_UNSUPPORTED_VERSION = "UNSUPPORTED_METADATA_VERSION";
    static final String PROPERTY_CREDENTIAL_ISSUER = "mosip.certify.domain.url";
    static final String PROPERTY_SERVLET_PATH = "server.servlet.path";
    /** COSE algorithm identifiers the current document publishes for mDoc, back to the JOSE names 0.14.0 listed. */
    static final Map<Integer, String> COSE_TO_JOSE = Map.of(-7, "ES256", -35, "ES384", -36, "ES512", -8, "EdDSA", -47, "ES256K", -257, "RS256", -37, "PS256");

    private final CredentialRegistry registry;
    private final CredentialConfigRepository repository;
    private final CredentialConfigMapper mapper;
    private final String credentialIssuer;
    private final String servletPath;

    public D13MetadataService(CredentialRegistry registry, CredentialConfigRepository repository, CredentialConfigMapper mapper, Environment environment) {
        this.registry = registry;
        this.repository = repository;
        this.mapper = mapper;
        this.credentialIssuer = environment.getRequiredProperty(PROPERTY_CREDENTIAL_ISSUER);
        this.servletPath = environment.getProperty(PROPERTY_SERVLET_PATH, "");
    }

    public Map<String, Object> metadata(String version) {
        if (!VERSION_LATEST.equals(version) && !VERSION_VD12.equals(version) && !VERSION_VD11.equals(version)) {
            throw new CertifyException(ERROR_UNSUPPORTED_VERSION, "Unsupported version: " + version);
        }
        CredentialIssuerMetadataDTO current = registry.issuerMetadata();
        List<CredentialConfig> rows = repository.findAll().stream().filter(row -> Constants.ACTIVE.equals(row.getStatus()))
                .filter(row -> row.getTenantId() == null || row.getTenantId().isBlank() || "default".equals(row.getTenantId())).toList(); // draft-13 is the default tenant's surface
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("credential_issuer", credentialIssuer);
        document.put("authorization_servers", current.getAuthorizationServers());
        document.put("credential_endpoint", credentialIssuer + servletPath
                + (VERSION_LATEST.equals(version) ? "/issuance/credential" : "/issuance/" + version + "/credential"));
        document.put("display", current.getDisplay());
        if (VERSION_VD11.equals(version)) {
            List<Map<String, Object>> entries = new ArrayList<>();
            rows.forEach(row -> entries.add(entry(row, current, version)));
            document.put("credentials_supported", entries);
        } else {
            Map<String, Object> entries = new LinkedHashMap<>();
            rows.forEach(row -> entries.put(row.getCredentialConfigKeyId(), entry(row, current, version)));
            document.put(VERSION_LATEST.equals(version) ? "credential_configurations_supported" : "credentials_supported", entries);
        }
        return document;
    }

    Map<String, Object> entry(CredentialConfig row, CredentialIssuerMetadataDTO current, String version) {
        CredentialConfigurationDTO dto = mapper.toDto(row);
        Map<String, Object> entry = new LinkedHashMap<>();
        // draft-13 wallets know SD-JWT VC as vc+sd-jwt only; rows written by develop carry dc+sd-jwt
        entry.put("format", D13IssuanceHandler.FORMAT_DC_SD_JWT.equals(dto.getCredentialFormat()) ? D13IssuanceHandler.FORMAT_VC_SD_JWT : dto.getCredentialFormat());
        entry.put("scope", dto.getScope());
        entry.put("cryptographic_binding_methods_supported", row.getCryptographicBindingMethodsSupported());
        entry.put("proof_types_supported", row.getProofTypesSupported());
        entry.put("display", dto.getMetaDataDisplay());
        entry.put("order", dto.getDisplayOrder());
        if (VERSION_LATEST.equals(version)) {
            entry.put("credential_signing_alg_values_supported", joseNames(current, row.getCredentialConfigKeyId()));
        } else {
            entry.put("cryptographic_suites_supported", row.getCredentialSigningAlgValuesSupported());
        }
        if (VERSION_VD11.equals(version)) {
            entry.put("id", row.getCredentialConfigKeyId());
        }
        switch (dto.getCredentialFormat()) {
            case D13IssuanceHandler.FORMAT_LDP_VC -> {
                Map<String, Object> definition = new LinkedHashMap<>();
                definition.put("@context", dto.getContextURLs());
                definition.put("type", dto.getCredentialTypes());
                if (dto.getClaims() != null) {
                    Map<String, Object> subject = new LinkedHashMap<>();
                    dto.getClaims().forEach((name, claim) -> subject.put(name, displayOf(claim)));
                    definition.put("credentialSubject", subject);
                }
                entry.put("credential_definition", definition);
            }
            case D13IssuanceHandler.FORMAT_MSO_MDOC -> {
                entry.put("doctype", dto.getDocType());
                if (dto.getMsoMdocClaims() != null) {
                    Map<String, Object> namespaces = new LinkedHashMap<>();
                    dto.getMsoMdocClaims().forEach((namespace, claims) -> {
                        Map<String, Object> mapped = new LinkedHashMap<>();
                        if (claims != null) {
                            claims.forEach((name, claim) -> mapped.put(name, displayOf(claim)));
                        }
                        namespaces.put(namespace, mapped);
                    });
                    entry.put("claims", namespaces);
                }
            }
            default -> {
                entry.put("vct", dto.getSdJwtVct());
                if (dto.getSdJwtClaims() != null) {
                    Map<String, Object> claims = new LinkedHashMap<>();
                    dto.getSdJwtClaims().forEach((name, claim) -> claims.put(name, displayOf(claim)));
                    entry.put("claims", claims);
                }
            }
        }
        return entry;
    }

    private static Map<String, Object> displayOf(ClaimsDTO claim) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("display", claim == null ? null : claim.getDisplay());
        return out;
    }

    private static Map<String, Object> displayOf(ClaimsDisplayFieldsConfigDTO claim) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("display", claim == null ? null : claim.getDisplay());
        return out;
    }

    static List<String> joseNames(CredentialIssuerMetadataDTO current, String id) {
        CredentialConfigurationSupportedDTO entry = current.getCredentialConfigurationSupportedDTO() == null ? null
                : current.getCredentialConfigurationSupportedDTO().get(id);
        List<String> names = new ArrayList<>();
        if (entry != null && entry.getCredentialSigningAlgValuesSupported() != null) {
            for (Object value : entry.getCredentialSigningAlgValuesSupported()) {
                names.add(value instanceof Number number ? COSE_TO_JOSE.getOrDefault(number.intValue(), value.toString()) : String.valueOf(value));
            }
        }
        return names;
    }
}
