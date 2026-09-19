package io.mosip.certify.vcapi;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.issuance.IssuanceCommand;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.issuance.IssuanceResult;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The VC-API issuer endpoints (W3C VCALM, formerly CCG VC-API) under {@code /vc-api}: {@code POST /credentials/issue}
 * signs a caller-supplied credential body through the core with the {@code SUPPLIED} configuration whose
 * {@code @context} and {@code type} match it, and {@code POST /credentials/status} updates a status list entry found
 * through the ledger or named in the request. The calling client is authenticated by {@link VcApiClientAuthFilter}.
 * Failures answer RFC 9457 problem details as the specification's {@code ProblemDetails}.
 */
@Slf4j
@RestController
@RequestMapping("/vc-api")
@ConditionalOnProperty(prefix = VcApiProperties.PREFIX, name = "enabled", havingValue = "true")
public class VcApiController {

    static final String PROBLEM_TYPE_PREFIX = "https://www.w3.org/TR/vc-data-model#";
    static final String CERTIFY_TYPE_PREFIX = "urn:mosip:certify:vc-api:";

    private final IssuanceService issuanceService;
    private final ConfigurationRegistry configurations;
    private final VcApiProperties properties;
    private final LedgerRepository ledger;
    private final CredentialStatusService credentialStatusService;

    public VcApiController(IssuanceService issuanceService, ConfigurationRegistry configurations, VcApiProperties properties,
                           LedgerRepository ledger, CredentialStatusService credentialStatusService) {
        this.issuanceService = issuanceService;
        this.configurations = configurations;
        this.properties = properties;
        this.ledger = ledger;
        this.credentialStatusService = credentialStatusService;
    }

    @PostMapping(value = "/credentials/issue", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> issue(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        String clientId = String.valueOf(request.getAttribute(VcApiClientAuthFilter.CLIENT_ATTRIBUTE));
        Map<String, Object> credential = object(body.get("credential"));
        if (credential == null) {
            return problem(HttpStatus.BAD_REQUEST, "MALFORMED_VALUE_ERROR", "credential must be a JSON object");
        }
        Map<String, Object> options = object(body.get("options"));
        options = options == null ? Map.of() : options;
        if (options.get("mandatoryPointers") instanceof List<?> pointers && !pointers.isEmpty()) {
            return problem(HttpStatus.BAD_REQUEST, "NOT_SUPPORTED", "mandatoryPointers (selective disclosure suites) are not supported");
        }
        Set<String> contexts = strings(credential.get("@context"));
        Set<String> types = strings(credential.get("type"));
        if (contexts.isEmpty() || types.isEmpty()) {
            return problem(HttpStatus.BAD_REQUEST, "MALFORMED_VALUE_ERROR", "credential needs @context and type");
        }
        Optional<CredentialConfiguration> match = configuration(contexts, types);
        if (match.isEmpty()) {
            return problem(HttpStatus.BAD_REQUEST, "NOT_CONFIGURED", "No supplied-credential configuration issues @context " + contexts + " with type " + types);
        }
        CredentialConfiguration configuration = match.get();
        VcApiProperties.Client client = properties.clients().get(clientId);
        if (client != null && client.credentialConfigurations() != null && !client.credentialConfigurations().isEmpty()
                && !client.credentialConfigurations().contains(configuration.id())) {
            return problem(HttpStatus.FORBIDDEN, "FORBIDDEN", "Client " + clientId + " may not issue configuration " + configuration.id());
        }
        String issuer = issuerId(credential.get("issuer"));
        String configuredIssuer = configuration.signing() == null ? null : configuration.signing().issuerDid();
        if (configuredIssuer != null && issuer != null && !configuredIssuer.equals(issuer)) {
            return problem(HttpStatus.BAD_REQUEST, "ISSUER_MISMATCH", "The provided value of 'issuer' does not match the expected configuration");
        }
        IssuanceCommand command = IssuanceCommand.builder(configuration.id())
                .tenant(TenantContext.DEFAULT)
                .authorization(new Authorization("client_credentials", Map.of("client_id", clientId), null))
                .suppliedCredential(credential)
                .protocol(ProtocolVersion.VC_API)
                .protocolParams(options)
                .correlationId(UUID.randomUUID().toString())
                .build();
        try {
            IssuanceResult result = issuanceService.issue(command);
            if (result instanceof IssuanceResult.Issued issued && !issued.credentials().isEmpty()) {
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("verifiableCredential", issued.credentials().get(0).credential());
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            }
            return problem(HttpStatus.INTERNAL_SERVER_ERROR, "ISSUANCE_FAILED", "The credential was not issued synchronously");
        } catch (IssuanceException e) {
            HttpStatus status = switch (e.getErrorCode()) {
                case IssuanceException.NOT_AUTHENTICATED -> HttpStatus.UNAUTHORIZED;
                case IssuanceException.INVALID_SCOPE -> HttpStatus.FORBIDDEN;
                case IssuanceException.ISSUANCE_FAILED -> HttpStatus.INTERNAL_SERVER_ERROR;
                default -> HttpStatus.BAD_REQUEST;
            };
            log.warn("VC-API issuance refused ({}): {}", e.getErrorCode(), e.getMessage());
            return problem(status, e.getErrorCode().toUpperCase(), e.getMessage());
        }
    }

    @PostMapping(value = "/credentials/status", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> status(@RequestBody Map<String, Object> body) {
        Object credentialId = body.get("credentialId");
        Map<String, Object> credentialStatus = object(body.get("credentialStatus"));
        Object status = body.get("status");
        if (!(credentialId instanceof String id) || id.isBlank() || credentialStatus == null || !(status instanceof Boolean revoked)
                || !(credentialStatus.get("type") instanceof String) || !(credentialStatus.get("statusPurpose") instanceof String purpose)) {
            return problem(HttpStatus.BAD_REQUEST, "MALFORMED_VALUE_ERROR", "credentialId, credentialStatus {type, statusPurpose} and a boolean status are required");
        }
        String listId = credentialStatus.get("statusListCredential") instanceof String s ? s : null;
        Long index = credentialStatus.get("statusListIndex") == null ? null : parseIndex(credentialStatus.get("statusListIndex"));
        if (listId == null || index == null) {
            Optional<Ledger> row = ledger.findByCredentialId(id);
            if (row.isEmpty() || row.get().getCredentialStatusDetails() == null) {
                return problem(HttpStatus.NOT_FOUND, "NOT_FOUND", "No issued credential with id " + id + " has a status entry");
            }
            Optional<CredentialStatusDetail> entry = row.get().getCredentialStatusDetails().stream()
                    .filter(detail -> purpose.equals(detail.getStatusPurpose())).findFirst();
            if (entry.isEmpty()) {
                return problem(HttpStatus.NOT_FOUND, "NOT_FOUND", "Credential " + id + " has no status entry for purpose " + purpose);
            }
            listId = entry.get().getStatusListCredentialId();
            index = entry.get().getStatusListIndex();
        }
        UpdateCredentialStatusRequest update = new UpdateCredentialStatusRequest();
        UpdateCredentialStatusRequest.CredentialStatusDto dto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        dto.setType((String) credentialStatus.get("type"));
        dto.setStatusPurpose(purpose);
        dto.setStatusListCredential(listId);
        dto.setStatusListIndex(index);
        update.setCredentialStatus(dto);
        update.setStatus(revoked);
        try {
            credentialStatusService.updateCredentialStatus(update);
        } catch (CertifyException e) {
            log.warn("VC-API status update refused ({}): {}", e.getErrorCode(), e.getMessage());
            boolean notFound = e.getErrorCode() != null && e.getErrorCode().toLowerCase().contains("not_found");
            return problem(notFound ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST, e.getErrorCode(), e.getMessage());
        }
        return ResponseEntity.ok().build();
    }

    /** The supplied-credential {@code ldp_vc} configuration whose stored contexts and types are exactly the credential's. */
    private Optional<CredentialConfiguration> configuration(Set<String> contexts, Set<String> types) {
        return configurations.all(TenantContext.DEFAULT_TENANT_ID).stream()
                .filter(c -> VCFormats.LDP_VC.equals(c.format()) && c.strategy() == IssuanceStrategy.SUPPLIED && c.formatConfig() != null)
                .filter(c -> commaSet(c.formatConfig().raw().get("context")).equals(contexts) && commaSet(c.formatConfig().raw().get("credentialType")).equals(types))
                .findFirst();
    }

    private static Set<String> commaSet(Object joined) {
        if (joined == null) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.stream(joined.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    /** The string members of {@code @context} or {@code type} (a single string, or an array whose object entries are skipped). */
    private static Set<String> strings(Object value) {
        Set<String> result = new LinkedHashSet<>();
        if (value instanceof String s) {
            result.add(s);
        } else if (value instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof String s) {
                    result.add(s);
                }
            }
        }
        return result;
    }

    private static String issuerId(Object issuer) {
        if (issuer instanceof String s) {
            return s;
        }
        if (issuer instanceof Map<?, ?> map && map.get("id") instanceof String s) {
            return s;
        }
        return null;
    }

    private static Long parseIndex(Object value) {
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
    }

    static ResponseEntity<Map<String, Object>> problem(HttpStatus status, String title, String detail) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problemBody(title, detail));
    }

    static Map<String, Object> problemBody(String title, String detail) {
        boolean vcdm = title.equals("PARSING_ERROR") || title.equals("MALFORMED_VALUE_ERROR");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", (vcdm ? PROBLEM_TYPE_PREFIX : CERTIFY_TYPE_PREFIX) + title);
        body.put("title", title);
        body.put("detail", detail);
        return body;
    }

    static String problemJson(String title, String detail) {
        return "{\"type\":\"" + CERTIFY_TYPE_PREFIX + title + "\",\"title\":\"" + title + "\",\"detail\":\"" + detail.replace("\"", "'") + "\"}";
    }
}
