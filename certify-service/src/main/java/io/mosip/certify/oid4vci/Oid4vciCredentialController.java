package io.mosip.certify.oid4vci;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.issuance.IssuanceCommand;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.issuance.IssuanceResult;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OpenID4VCI 1.0 Credential Endpoint of the new surface: {@code POST {servletPath}/oid4vci/credential}. Builds an
 * {@link IssuanceCommand} from the request and the request-scoped {@link AuthorizationContext}, answers
 * {@code {"credentials":[{"credential":...}]}} and OpenID4VCI error bodies ({@code error}, {@code error_description}).
 */
@RestController
@RequestMapping("/oid4vci")
public class Oid4vciCredentialController {

    static final List<String> DEFAULT_PROOF_ALGORITHMS = List.of("ES256", "EdDSA", "RS256", "PS256", "ES256K");

    private final IssuanceService issuanceService;
    private final ConfigurationRegistry configurations;
    private final AuthorizationContext authorizationContext;
    private final ProofValidator.NonceCheck nonceCheck;
    private final String issuerIdentifier;

    public Oid4vciCredentialController(IssuanceService oid4vciIssuanceService, ConfigurationRegistry configurations,
                                       AuthorizationContext authorizationContext, CacheNonceCheck nonceCheck,
                                       @Value("${mosip.certify.identifier}") String issuerIdentifier) {
        this.issuanceService = oid4vciIssuanceService;
        this.configurations = configurations;
        this.authorizationContext = authorizationContext;
        this.nonceCheck = nonceCheck;
        this.issuerIdentifier = issuerIdentifier;
    }

    @PostMapping(value = "/credential", produces = "application/json")
    public ResponseEntity<Map<String, Object>> credential(@Valid @RequestBody CredentialRequest request) {
        Authorization authorization = authorizationContext.isActive()
                ? new Authorization(authorizationContext.getScheme() == null ? "bearer" : authorizationContext.getScheme(),
                        authorizationContext.getClaims(), authorizationContext.getAccessTokenHash())
                : Authorization.NONE;
        if (!authorization.isPresent()) {
            throw new IssuanceException(IssuanceException.NOT_AUTHENTICATED, "The credential endpoint needs an access token");
        }
        List<ProofValidator.ProofInput> proofs = new ArrayList<>();
        if (request.getProofs() != null) {
            request.getProofs().forEach((type, values) -> values.forEach(value -> proofs.add(new ProofValidator.ProofInput(type.name().toLowerCase(), value))));
        }
        ProofValidator.ProofPolicy policy = new ProofValidator.ProofPolicy(allowedProofAlgorithms(request.getCredentialConfigId()), issuerIdentifier, true,
                authorization.clientId(), Map.of());
        IssuanceCommand command = IssuanceCommand.builder(request.getCredentialConfigId())
                .tenant(TenantContext.DEFAULT).authorization(authorization).proofs(proofs).proofPolicy(policy).nonceCheck(nonceCheck)
                .protocol(ProtocolVersion.OID4VCI_1_0).correlationId(UUID.randomUUID().toString()).build();

        IssuanceResult result = issuanceService.issue(command);
        List<Map<String, Object>> credentials = new ArrayList<>();
        if (result instanceof IssuanceResult.Issued issued) {
            for (IssuedCredential credential : issued.credentials()) {
                credentials.add(Map.of("credential", credential.credential()));
            }
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("credentials", credentials);
        if (result instanceof IssuanceResult.Deferred deferred) {
            body.put("transaction_id", deferred.transactionId());
            return ResponseEntity.accepted().body(body);
        }
        return ResponseEntity.ok(body);
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

    /** OpenID4VCI 1.0 error responses: the core's codes are the spec's names; only authentication and internal failures differ in status. */
    @ExceptionHandler(IssuanceException.class)
    public ResponseEntity<Map<String, String>> issuanceError(IssuanceException e) {
        HttpStatus status = switch (e.getErrorCode()) {
            case IssuanceException.NOT_AUTHENTICATED -> HttpStatus.UNAUTHORIZED;
            case IssuanceException.ISSUANCE_FAILED -> HttpStatus.INTERNAL_SERVER_ERROR;
            default -> HttpStatus.BAD_REQUEST;
        };
        String error = status == HttpStatus.INTERNAL_SERVER_ERROR ? "server_error" : e.getErrorCode();
        return ResponseEntity.status(status).body(Map.of("error", error, "error_description", e.getMessage()));
    }
}
