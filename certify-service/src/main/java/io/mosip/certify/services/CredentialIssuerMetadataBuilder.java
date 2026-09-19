package io.mosip.certify.services;

import com.authlete.cose.constants.COSEAlgorithms;
import com.nimbusds.jose.JWSAlgorithm;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.CredentialMetadataDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.utils.CredentialConfigMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The compatibility surface's credential issuer metadata document (`/.well-known/openid-credential-issuer`) built from
 * the active `credential_config` rows: one `credential_configurations_supported` entry per row plus the deployment's
 * issuer, authorization servers, endpoints and display. The new surface builds its own document (`TenantIssuerMetadata`).
 */
@Component
public class CredentialIssuerMetadataBuilder {

    private static final Map<String, Integer> COSE_ALGORITHMS = Map.of(
            JWSAlgorithm.ES256.getName(), COSEAlgorithms.ES256,
            JWSAlgorithm.EdDSA.getName(), COSEAlgorithms.EdDSA,
            JWSAlgorithm.ES256K.getName(), COSEAlgorithms.ES256K,
            JWSAlgorithm.RS256.getName(), COSEAlgorithms.RS256);

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Value("${mosip.certify.domain.url}")
    private String credentialIssuer;

    @Value("${mosip.certify.allow-c-nonce:false}")
    private boolean allowCNonce;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, Object>> issuerDisplay;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.credential-config.as-mapping:{}}}")
    private Map<String, String> authorizationServerMapping;

    public CredentialIssuerMetadataDTO build(List<CredentialConfig> credentialConfigs) {
        CredentialIssuerMetadataDTO metadata = new CredentialIssuerMetadataDTO();
        Map<String, CredentialConfigurationSupportedDTO> supported = new HashMap<>();
        for (CredentialConfig credentialConfig : credentialConfigs) {
            CredentialConfigurationSupportedDTO dto = toSupportedDTO(credentialConfig);
            dto.setCredentialSigningAlgValuesSupported(signingAlgorithms(credentialConfig));
            supported.put(credentialConfig.getCredentialConfigKeyId(), dto);
        }
        metadata.setCredentialConfigurationSupportedDTO(supported);
        metadata.setCredentialIssuer(credentialIssuer);
        metadata.setAuthorizationServers(resolveAuthorizationServers());
        metadata.setCredentialEndpoint(credentialIssuer + servletPath + "/issuance/credential");
        metadata.setDisplay(issuerDisplay);
        if (allowCNonce) {
            metadata.setNonceEndpoint(credentialIssuer + servletPath + "/nonce");
        }
        return metadata;
    }

    /** The JOSE names the configured suite maps to (or the row's own algorithm), as COSE integers for mDoc. */
    private List<Object> signingAlgorithms(CredentialConfig credentialConfig) {
        List<String> algs = credentialConfig.getSignatureCryptoSuite() != null
                ? credentialSigningAlgValuesSupportedMap.get(credentialConfig.getSignatureCryptoSuite())
                : Collections.singletonList(credentialConfig.getSignatureAlgo());
        if (algs == null) {
            return null;
        }
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            List<Object> coseAlgs = new ArrayList<>();
            for (String alg : algs) {
                coseAlgs.add(coseAlgorithm(alg));
            }
            return coseAlgs;
        }
        return new ArrayList<>(algs);
    }

    static Integer coseAlgorithm(String signAlgorithm) {
        if (signAlgorithm == null) {
            throw new IllegalArgumentException("Missing COSE signing algorithm");
        }
        Integer coseAlg = COSE_ALGORITHMS.get(signAlgorithm);
        if (coseAlg == null) {
            throw new IllegalArgumentException("Unsupported COSE signing algorithm for mso_mdoc: " + signAlgorithm);
        }
        return coseAlg;
    }

    /** `mosip.certify.authorization.url` (comma-separated) followed by the per-configuration mapping, without duplicates. */
    private List<String> resolveAuthorizationServers() {
        Set<String> servers = new LinkedHashSet<>();
        if (StringUtils.hasText(authUrl)) {
            Arrays.stream(authUrl.split(",")).map(String::trim).filter(StringUtils::hasText).forEach(servers::add);
        }
        if (authorizationServerMapping != null) {
            authorizationServerMapping.values().stream().filter(StringUtils::hasText).map(String::trim).forEach(servers::add);
        }
        return new ArrayList<>(servers);
    }

    private CredentialConfigurationSupportedDTO toSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO supported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO dto = credentialConfigMapper.toDto(credentialConfig);
        supported.setFormat(dto.getCredentialFormat());
        supported.setScope(dto.getScope());
        supported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        supported.setProofTypesSupported(credentialConfig.getProofTypesSupported());

        CredentialMetadataDTO credentialMetadata = new CredentialMetadataDTO();
        credentialMetadata.setDisplay(dto.getMetaDataDisplay());
        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(dto.getCredentialTypes());
            credentialDefinition.setContext(dto.getContextURLs());
            supported.setCredentialDefinition(credentialDefinition);
            credentialMetadata.setClaims(standardClaims(credentialConfig.getClaims()));
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            supported.setDocType(credentialConfig.getDocType());
            credentialMetadata.setClaims(mdocClaims(credentialConfig.getMsoMdocClaims()));
        } else if (VCFormats.DC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            supported.setVct(credentialConfig.getSdJwtVct());
            credentialMetadata.setClaims(standardClaims(credentialConfig.getSdJwtClaims()));
        }
        supported.setCredentialMetadataDTO(credentialMetadata);
        return supported;
    }

    private static List<CredentialMetadataDTO.Claims> standardClaims(Map<String, Claims> claims) {
        if (claims == null) {
            return Collections.emptyList();
        }
        return claims.entrySet().stream()
                .map(entry -> claim(Collections.singletonList(entry.getKey()), entry.getValue()))
                .toList();
    }

    private static List<CredentialMetadataDTO.Claims> mdocClaims(Map<String, Map<String, Claims>> mdocClaims) {
        if (mdocClaims == null) {
            return Collections.emptyList();
        }
        return mdocClaims.entrySet().stream()
                .filter(namespace -> namespace.getValue() != null)
                .flatMap(namespace -> namespace.getValue().entrySet().stream()
                        .map(entry -> claim(Arrays.asList(namespace.getKey(), entry.getKey()), entry.getValue())))
                .toList();
    }

    private static CredentialMetadataDTO.Claims claim(List<String> path, Claims value) {
        CredentialMetadataDTO.Claims claim = new CredentialMetadataDTO.Claims();
        claim.setPath(path);
        if (value != null) {
            if (value.getDisplay() != null) {
                claim.setDisplay(value.getDisplay().stream()
                        .map(d -> new ClaimsDisplayFieldsConfigDTO.Display(d.getName(), d.getLocale()))
                        .toList());
            }
            claim.setMandatory(value.isMandatory());
        }
        return claim;
    }
}
