package io.mosip.certify.oid4vci.d13;

import io.mosip.certify.core.dto.AuthorizationContext;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.deprecation.DeprecatedEndpoint;
import io.mosip.certify.format.sdjwt.SdJwtFormatter;
import io.mosip.certify.issuance.ConfigurationRegistry;
import io.mosip.certify.issuance.IssuanceCommand;
import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.issuance.IssuanceResult;
import io.mosip.certify.issuance.IssuanceService;
import io.mosip.certify.oid4vci.CacheNonceCheck;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The draft-13 request as 0.14.0 served it, executed by the new core: the configuration is picked by the token's
 * scopes plus (format, context and type | vct | doctype) instead of an id, the single proof must carry the
 * token-bound {@code c_nonce} ({@link D13NonceCheck}), the proof audience is today's issuer identifier, and the answer
 * is {@code {"credential": ...}} with the 0.14.0 shapes: {@code vc+sd-jwt} keeps that {@code typ}, the mDoc is a
 * Document with a tagged {@code issuerAuth}. Deprecated from day one ({@link DeprecatedEndpoint} on the handlers).
 */
@Component
@ConditionalOnProperty(prefix = D13Properties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class D13IssuanceHandler {

    static final String FORMAT_LDP_VC = "ldp_vc";
    static final String FORMAT_MSO_MDOC = "mso_mdoc";
    static final String FORMAT_DC_SD_JWT = SdJwtFormatter.FORMAT;
    static final String FORMAT_VC_SD_JWT = SdJwtFormatter.ALIAS_VC_SD_JWT;
    static final String PROPERTY_IDENTIFIER = "mosip.certify.identifier";
    static final String PROPERTY_C_NONCE_EXPIRE_SECONDS = "mosip.certify.cnonce-expire-seconds";
    static final List<String> DEFAULT_PROOF_ALGORITHMS = List.of("ES256", "EdDSA", "RS256", "PS256", "ES256K");

    private final IssuanceService issuanceService;
    private final ConfigurationRegistry configurations;
    private final AuthorizationContext authorizationContext;
    private final ProofValidator.NonceCheck sharedNonceCheck;
    private final VCICacheService cache;
    private final String issuerIdentifier;
    private final int cNonceExpireSeconds;
    private final Clock clock;

    @Autowired
    public D13IssuanceHandler(@Qualifier("oid4vciIssuanceService") IssuanceService issuanceService, ConfigurationRegistry configurations,
                              AuthorizationContext authorizationContext, CacheNonceCheck sharedNonceCheck, VCICacheService cache,
                              Environment environment) {
        this(issuanceService, configurations, authorizationContext, sharedNonceCheck, cache,
                environment.getRequiredProperty(PROPERTY_IDENTIFIER),
                environment.getProperty(PROPERTY_C_NONCE_EXPIRE_SECONDS, Integer.class, 300), Clock.systemUTC());
    }

    D13IssuanceHandler(IssuanceService issuanceService, ConfigurationRegistry configurations, AuthorizationContext authorizationContext,
                       ProofValidator.NonceCheck sharedNonceCheck, VCICacheService cache, String issuerIdentifier, int cNonceExpireSeconds, Clock clock) {
        this.issuanceService = issuanceService;
        this.configurations = configurations;
        this.authorizationContext = authorizationContext;
        this.sharedNonceCheck = sharedNonceCheck;
        this.cache = cache;
        this.issuerIdentifier = issuerIdentifier.replaceAll("/+$", "");
        this.cNonceExpireSeconds = cNonceExpireSeconds;
        this.clock = clock;
    }

    public Map<String, Object> issue(D13CredentialRequest request, boolean echoFormat) {
        Authorization authorization = authorization();
        String format = request.getFormat();
        CredentialConfiguration configuration = resolve(request, authorization);
        D13CredentialRequest.Proof proof = request.getProof();
        Object proofValue = "cwt".equalsIgnoreCase(proof.getProof_type()) ? proof.getCwt() : proof.getJwt();
        if (proofValue == null || proofValue.toString().isBlank()) {
            throw new IssuanceException(IssuanceException.INVALID_PROOF, "Error encountered during proof jwt parsing.");
        }
        List<ProofValidator.ProofInput> proofs = List.of(new ProofValidator.ProofInput(proof.getProof_type().toLowerCase(), proofValue));
        ProofValidator.ProofPolicy policy = new ProofValidator.ProofPolicy(allowedProofAlgorithms(configuration), issuerIdentifier, true,
                authorization.clientId(), Map.of());
        IssuanceCommand command = IssuanceCommand.builder(configuration.id())
                .tenant(TenantContext.defaultTenant(issuerIdentifier, null)).authorization(authorization).proofs(proofs).proofPolicy(policy)
                .nonceCheck(new D13NonceCheck(authorization, cache, sharedNonceCheck, clock))
                .protocol(ProtocolVersion.OID4VCI_D13).protocolParams(Map.of(SdJwtFormatter.PARAM_REQUESTED_FORMAT, format))
                .correlationId(UUID.randomUUID().toString()).build();
        IssuanceResult result = issuanceService.issue(command);
        if (!(result instanceof IssuanceResult.Issued issued) || issued.credentials().isEmpty()) {
            throw new IssuanceException(IssuanceException.ISSUANCE_FAILED, "Deferred issuance is not part of draft 13");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        if (echoFormat) {
            body.put("format", format);
        }
        body.put("credential", value(issued.credentials().get(0), configuration));
        return body;
    }

    /** A fresh token-bound {@code c_nonce}, cached under the token hash and in the shared nonce store (0.14.0 hands it out inside the error). */
    public VCIssuanceTransaction freshNonce() {
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(UUID.randomUUID().toString());
        transaction.setCNonceIssuedEpoch(clock.instant().getEpochSecond());
        transaction.setCNonceExpireSeconds(cNonceExpireSeconds);
        cache.setNonceTransaction(transaction.getCNonce(), transaction);
        String tokenHash = authorizationContext.isActive() ? authorizationContext.getAccessTokenHash() : null;
        if (tokenHash != null) {
            cache.setVCITransaction(tokenHash, transaction);
        }
        return transaction;
    }

    private Authorization authorization() {
        if (!authorizationContext.isActive()) {
            throw new IssuanceException(IssuanceException.NOT_AUTHENTICATED, "The credential endpoint needs an access token");
        }
        return new Authorization(authorizationContext.getScheme() == null ? "bearer" : authorizationContext.getScheme(),
                authorizationContext.getClaims(), authorizationContext.getAccessTokenHash());
    }

    /** 0.14.0's scope-then-selector lookup, with its error codes and messages. */
    CredentialConfiguration resolve(D13CredentialRequest request, Authorization authorization) {
        String format = request.getFormat();
        if (!Set.of(FORMAT_LDP_VC, FORMAT_MSO_MDOC, FORMAT_DC_SD_JWT, FORMAT_VC_SD_JWT).contains(format)) {
            throw new IssuanceException(IssuanceException.UNSUPPORTED_CREDENTIAL_FORMAT, IssuanceException.UNSUPPORTED_CREDENTIAL_FORMAT);
        }
        requireSelector(request);
        List<String> scopes = Arrays.stream(authorization.scope() == null ? new String[0] : authorization.scope().split(" "))
                .filter(s -> !s.isBlank()).toList();
        List<CredentialConfiguration> all = configurations.all(TenantContext.DEFAULT_TENANT_ID);
        for (String scope : scopes) {
            List<CredentialConfiguration> inScope = all.stream().filter(c -> scope.equals(c.scope())).toList();
            if (inScope.isEmpty()) {
                continue;
            }
            Optional<CredentialConfiguration> match = inScope.stream().filter(c -> matches(c, request)).findFirst();
            if (match.isPresent()) {
                return match.get();
            }
            throw new IssuanceException(IssuanceException.INVALID_CREDENTIAL_REQUEST,
                    "No matching " + format + " credential configuration found for scope: " + scope);
        }
        throw new IssuanceException(IssuanceException.INVALID_SCOPE, "No credential mapping found for the provided scope.");
    }

    private static void requireSelector(D13CredentialRequest request) {
        boolean valid = switch (request.getFormat()) {
            case FORMAT_LDP_VC -> request.getCredential_definition() != null
                    && request.getCredential_definition().getContext() != null && !request.getCredential_definition().getContext().isEmpty()
                    && request.getCredential_definition().getType() != null && !request.getCredential_definition().getType().isEmpty();
            case FORMAT_MSO_MDOC -> request.getDoctype() != null && !request.getDoctype().isBlank();
            default -> request.getVct() != null && !request.getVct().isEmpty();
        };
        if (!valid) {
            throw new IssuanceException(IssuanceException.INVALID_CREDENTIAL_REQUEST, IssuanceException.INVALID_CREDENTIAL_REQUEST);
        }
    }

    private static boolean matches(CredentialConfiguration configuration, D13CredentialRequest request) {
        String format = request.getFormat();
        Map<String, Object> raw = configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
        return switch (format) {
            case FORMAT_LDP_VC -> FORMAT_LDP_VC.equals(configuration.format())
                    && commaSet(raw.get("context")).equals(new LinkedHashSet<>(request.getCredential_definition().getContext()))
                    && commaSet(raw.get("credentialType")).equals(new LinkedHashSet<>(request.getCredential_definition().getType()));
            case FORMAT_MSO_MDOC -> FORMAT_MSO_MDOC.equals(configuration.format()) && request.getDoctype().equals(raw.get("docType"));
            default -> (FORMAT_DC_SD_JWT.equals(configuration.format()) || FORMAT_VC_SD_JWT.equals(configuration.format()))
                    && request.getVct().equals(raw.get("vct"));
        };
    }

    static Set<String> commaSet(Object stored) {
        Set<String> out = new LinkedHashSet<>();
        if (stored != null) {
            for (String part : stored.toString().split(",")) {
                if (!part.isBlank()) {
                    out.add(part.trim());
                }
            }
        }
        return out;
    }

    private Object value(IssuedCredential credential, CredentialConfiguration configuration) {
        if (FORMAT_MSO_MDOC.equals(credential.format()) && credential.credential() instanceof String encoded) {
            Object docType = credential.attributes() == null ? null : credential.attributes().get("docType");
            if (docType == null && configuration.formatConfig() != null) {
                docType = configuration.formatConfig().raw().get("docType");
            }
            return D13Mdoc.wrapDocument(encoded, String.valueOf(docType));
        }
        return credential.credential();
    }

    @SuppressWarnings("unchecked")
    private static List<String> allowedProofAlgorithms(CredentialConfiguration configuration) {
        return Optional.ofNullable(configuration.formatConfig())
                .map(c -> c.raw().get("proofTypesSupported"))
                .filter(Map.class::isInstance)
                .map(m -> ((Map<String, Object>) m).get("jwt"))
                .filter(Map.class::isInstance)
                .map(m -> ((Map<String, Object>) m).get("proof_signing_alg_values_supported"))
                .filter(List.class::isInstance)
                .map(l -> ((List<Object>) l).stream().map(String::valueOf).toList())
                .orElse(DEFAULT_PROOF_ALGORITHMS);
    }
}
