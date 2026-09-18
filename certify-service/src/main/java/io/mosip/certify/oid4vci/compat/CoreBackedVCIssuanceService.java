package io.mosip.certify.oid4vci.compat;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.issuance.IssuanceCommand;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.issuance.IssuanceResult;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.oid4vci.CacheNonceCheck;
import io.mosip.certify.oid4vci.Oid4vciV1Properties;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.utils.DIDDocumentUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The compatibility path {@code POST /issuance/credential} (OpenID4VCI 1.0 body) served by the new core when
 * {@code certify.protocol.oid4vci-v1.compat-core.enabled=true}: the same command the new surface builds, with today's
 * issuer identifier as tenant identifier and proof audience, the shared nonce store, and the legacy error codes and
 * messages so that the v1 goldens hold byte for byte. Replaces {@code CertifyIssuanceServiceImpl} for the controller
 * ({@code @Primary}); the legacy service stays until the default flips.
 */
@Slf4j
@Service
@Primary
// the VCIssuance plugin mode has no ExternalIssuer adapter yet, so the flag only applies to DataProvider deployments
@ConditionalOnExpression("${" + Oid4vciV1Properties.COMPAT_CORE_PREFIX + ".enabled:false} and '${mosip.certify.plugin-mode:}' == 'DataProvider'")
public class CoreBackedVCIssuanceService implements VCIssuanceService {

    static final List<String> DEFAULT_PROOF_ALGORITHMS = List.of("ES256", "EdDSA", "RS256", "PS256", "ES256K");
    static final String PARAM_SURFACE = "surface";
    static final String SURFACE_COMPAT = "compat";

    private final IssuanceService issuanceService;
    private final ConfigurationRegistry configurations;
    private final AuthorizationContext authorizationContext;
    private final CacheNonceCheck nonceCheck;
    private final DIDDocumentUtil didDocumentUtil;
    private final String issuerIdentifier;
    private final String didUrl;

    public CoreBackedVCIssuanceService(@Qualifier("oid4vciIssuanceService") IssuanceService issuanceService, ConfigurationRegistry configurations,
                                       AuthorizationContext authorizationContext, CacheNonceCheck nonceCheck, DIDDocumentUtil didDocumentUtil,
                                       Environment environment) {
        this.issuanceService = issuanceService;
        this.configurations = configurations;
        this.authorizationContext = authorizationContext;
        this.nonceCheck = nonceCheck;
        this.didDocumentUtil = didDocumentUtil;
        this.issuerIdentifier = environment.getRequiredProperty("mosip.certify.identifier").replaceAll("/+$", "");
        this.didUrl = environment.getProperty("mosip.certify.data-provider-plugin.did-url", "");
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> CredentialResponse<T> getCredential(CredentialRequest request) {
        if (!authorizationContext.isActive()) {
            throw new NotAuthenticatedException();
        }
        Authorization authorization = new Authorization(authorizationContext.getScheme() == null ? "bearer" : authorizationContext.getScheme(),
                authorizationContext.getClaims(), authorizationContext.getAccessTokenHash());
        List<ProofValidator.ProofInput> proofs = new ArrayList<>();
        if (request.getProofs() != null) {
            request.getProofs().forEach((type, values) -> values.forEach(value -> proofs.add(new ProofValidator.ProofInput(type.name().toLowerCase(), value))));
        }
        ProofValidator.ProofPolicy policy = new ProofValidator.ProofPolicy(allowedProofAlgorithms(request.getCredentialConfigId()), issuerIdentifier, true,
                authorization.clientId(), Map.of());
        IssuanceCommand command = IssuanceCommand.builder(request.getCredentialConfigId())
                .tenant(TenantContext.defaultTenant(issuerIdentifier, null)).authorization(authorization).proofs(proofs).proofPolicy(policy).nonceCheck(nonceCheck)
                .protocol(ProtocolVersion.OID4VCI_1_0).protocolParams(Map.of(PARAM_SURFACE, SURFACE_COMPAT)).correlationId(UUID.randomUUID().toString()).build();
        IssuanceResult result;
        try {
            result = issuanceService.issue(command);
        } catch (IssuanceException e) {
            throw legacy(e);
        }
        if (!(result instanceof IssuanceResult.Issued issued)) {
            throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED, "Deferred issuance is not available on the compatibility path");
        }
        CredentialResponse<T> response = new CredentialResponse<>();
        List<CredentialResponse.CredentialWrapper<T>> wrappers = new ArrayList<>();
        for (IssuedCredential credential : issued.credentials()) {
            CredentialResponse.CredentialWrapper<T> wrapper = new CredentialResponse.CredentialWrapper<>();
            wrapper.setCredential((T) credential.credential());
            wrappers.add(wrapper);
        }
        response.setCredentials(wrappers);
        return response;
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        return didDocumentUtil.generateDIDDocument(didUrl);
    }

    /** The legacy exception, code and message for each core error, so the compatibility surface answers as before. */
    static CertifyException legacy(IssuanceException e) {
        return switch (e.getErrorCode()) {
            case IssuanceException.NOT_AUTHENTICATED -> new NotAuthenticatedException();
            case IssuanceException.INVALID_CREDENTIAL_REQUEST -> new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST, "No credential configuration found for credential_configuration_id");
            case IssuanceException.INVALID_SCOPE -> new CertifyException(VCIErrorConstants.INVALID_SCOPE, "No credential mapping found for the provided scope.");
            case IssuanceException.INVALID_PROOF -> new CertifyException(VCIErrorConstants.INVALID_PROOF, "None of the submitted proofs passed validation.");
            case IssuanceException.UNSUPPORTED_CREDENTIAL_FORMAT -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, "Invalid or unsupported VC format requested.");
            case IssuanceException.ISSUANCE_FAILED -> new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED, e.getMessage());
            default -> new CertifyException(e.getErrorCode(), e.getMessage());
        };
    }

    @SuppressWarnings("unchecked")
    private List<String> allowedProofAlgorithms(String configurationId) {
        return configurations.byId(TenantContext.DEFAULT_TENANT_ID, configurationId)
                .map(c -> c.formatConfig() == null ? null : c.formatConfig().raw().get("proofTypesSupported"))
                .filter(Map.class::isInstance)
                .map(m -> ((Map<String, Object>) m).get("jwt"))
                .filter(Map.class::isInstance)
                .map(m -> ((Map<String, Object>) m).get("proof_signing_alg_values_supported"))
                .filter(List.class::isInstance)
                .map(l -> ((List<Object>) l).stream().map(String::valueOf).toList())
                .orElse(DEFAULT_PROOF_ALGORITHMS);
    }
}
