package io.mosip.certify.issuance;

import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.ExternalIssuer;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.UnsignedCredential;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The issuance flow of docs/design/05-target-architecture.md, step by step: resolve the configuration, check
 * authorization, validate proofs into holder bindings, obtain the unsigned credential by the configuration's
 * strategy, attach status, run listeners, sign, notify. It knows no protocol, no storage and no key store.
 */
public class DefaultIssuanceService implements IssuanceService {

    /** Attribute on {@link ClaimSet#provenance()} that marks a caller-supplied document. */
    public static final String PROVENANCE_SUPPLIED = "supplied";
    /** Attribute on {@link ClaimSet#provenance()} that carries the template mode used to render the document. */
    public static final String PROVENANCE_TEMPLATE_MODE = "templateMode";

    private final ConfigurationRegistry configurations;
    private final FormatterRegistry formatters;
    private final KeyProviderRegistry keyProviders;
    private final Map<String, CredentialDataSource> dataSources;
    private final Map<String, ExternalIssuer> externalIssuers;
    private final Map<String, ProofValidator> proofValidators;
    private final Map<String, TemplateEngine> templateEngines;
    private final List<StatusProvider> statusProviders;
    private final List<IssuanceListener> listeners;
    private final AuthorizationPolicy authorizationPolicy;
    private final Clock clock;
    private final Duration defaultValidity;
    private final String defaultDataSourceId;

    public DefaultIssuanceService(ConfigurationRegistry configurations, FormatterRegistry formatters, KeyProviderRegistry keyProviders,
                                  List<CredentialDataSource> dataSources, List<ExternalIssuer> externalIssuers,
                                  List<ProofValidator> proofValidators, List<TemplateEngine> templateEngines,
                                  List<StatusProvider> statusProviders, List<IssuanceListener> listeners,
                                  AuthorizationPolicy authorizationPolicy, Clock clock, Duration defaultValidity) {
        this(configurations, formatters, keyProviders, dataSources, externalIssuers, proofValidators, templateEngines,
                statusProviders, listeners, authorizationPolicy, clock, defaultValidity, null);
    }

    /**
     * @param defaultDataSourceId the {@link CredentialDataSource#id()} a configuration that names none resolves to, or
     *                            {@code null} to keep the historical behaviour (the only registered source). Deployments
     *                            register more than one source (the data-provider plugin and a file source, say), and a
     *                            configuration written before {@code dataSourceId} existed names none: it must keep
     *                            resolving to the source it was written for rather than fail with "several registered".
     */
    public DefaultIssuanceService(ConfigurationRegistry configurations, FormatterRegistry formatters, KeyProviderRegistry keyProviders,
                                  List<CredentialDataSource> dataSources, List<ExternalIssuer> externalIssuers,
                                  List<ProofValidator> proofValidators, List<TemplateEngine> templateEngines,
                                  List<StatusProvider> statusProviders, List<IssuanceListener> listeners,
                                  AuthorizationPolicy authorizationPolicy, Clock clock, Duration defaultValidity,
                                  String defaultDataSourceId) {
        this.configurations = configurations;
        this.formatters = formatters;
        this.keyProviders = keyProviders;
        this.dataSources = dataSources.stream().collect(Collectors.toUnmodifiableMap(CredentialDataSource::id, Function.identity()));
        this.externalIssuers = externalIssuers.stream().collect(Collectors.toUnmodifiableMap(ExternalIssuer::id, Function.identity()));
        this.proofValidators = proofValidators.stream().collect(Collectors.toUnmodifiableMap(ProofValidator::proofType, Function.identity()));
        this.templateEngines = templateEngines.stream().collect(Collectors.toUnmodifiableMap(TemplateEngine::id, Function.identity()));
        this.statusProviders = List.copyOf(statusProviders);
        this.listeners = List.copyOf(listeners);
        this.authorizationPolicy = authorizationPolicy;
        this.clock = clock;
        this.defaultValidity = defaultValidity;
        this.defaultDataSourceId = defaultDataSourceId;
    }

    @Override
    public IssuanceResult issue(IssuanceCommand command) {
        CredentialConfiguration configuration = resolve(command);
        String correlationId = command.correlationId() == null ? UUID.randomUUID().toString() : command.correlationId();
        IssuanceContext base = new IssuanceContext(command.tenant(), command.authorization(), List.of(), command.protocol(),
                correlationId, clock.instant(), command.protocolParams());
        try {
            authorizationPolicy.check(command.authorization(), configuration, command.protocol());
            List<HolderBinding> holders = holders(command, configuration, base);
            IssuanceContext context = new IssuanceContext(base.tenant(), base.authorization(), holders, base.protocol(),
                    base.correlationId(), base.now(), base.protocolParams());
            List<IssuedCredential> credentials = new ArrayList<>();
            ClaimSet lastClaims = null;
            for (HolderBinding holder : holders) {
                Issued issued = issueOne(command, configuration, context, holder);
                credentials.add(issued.credential());
                lastClaims = issued.claims();
            }
            String transactionId = UUID.randomUUID().toString();
            IssuanceListener.IssuanceEvent event = new IssuanceListener.IssuanceEvent(context, configuration, lastClaims, credentials, transactionId);
            listeners.forEach(l -> l.onIssued(event));
            return new IssuanceResult.Issued(credentials, transactionId);
        } catch (IssuanceException e) {
            notifyFailure(base, configuration, e.getErrorCode(), e);
            throw e;
        } catch (RuntimeException e) {
            notifyFailure(base, configuration, IssuanceException.ISSUANCE_FAILED, e);
            throw new IssuanceException(IssuanceException.ISSUANCE_FAILED, "Issuance failed: " + e.getMessage(), e);
        }
    }

    private record Issued(IssuedCredential credential, ClaimSet claims) {}

    private CredentialConfiguration resolve(IssuanceCommand command) {
        String tenantId = command.tenant().tenantId();
        Optional<CredentialConfiguration> configuration = command.credentialConfigurationId() != null
                ? configurations.byId(tenantId, command.credentialConfigurationId())
                : configurations.bySelector(tenantId, command.selector().format(), command.selector().selectorKey());
        return configuration.orElseThrow(() -> new IssuanceException(
                command.credentialConfigurationId() != null ? IssuanceException.INVALID_CREDENTIAL_REQUEST : IssuanceException.UNSUPPORTED_CREDENTIAL_TYPE,
                "No credential configuration for " + (command.credentialConfigurationId() != null
                        ? "id " + command.credentialConfigurationId() : command.selector())));
    }

    private List<HolderBinding> holders(IssuanceCommand command, CredentialConfiguration configuration, IssuanceContext context) {
        if (!configuration.requiresHolderBinding() && command.proofs().isEmpty()) {
            return List.of(HolderBinding.NONE);
        }
        if (command.proofs().isEmpty()) {
            throw new IssuanceException(IssuanceException.INVALID_PROOF, "Credential configuration " + configuration.id() + " requires a proof of possession");
        }
        List<HolderBinding> holders = new ArrayList<>();
        ProofValidationException lastFailure = null;
        for (ProofValidator.ProofInput proof : command.proofs()) {
            ProofValidator validator = proofValidators.get(proof.type());
            if (validator == null) {
                throw new IssuanceException(IssuanceException.INVALID_PROOF, "Unsupported proof type " + proof.type());
            }
            try {
                holders.addAll(validator.validateAll(proof, command.proofPolicy(), command.nonceCheck(), context));
            } catch (ProofValidationException e) {
                if (IssuanceException.INVALID_NONCE.equals(e.getErrorCode())) {
                    throw new IssuanceException(e.getErrorCode(), e.getMessage(), e);
                }
                lastFailure = e;
            }
        }
        if (holders.isEmpty()) {
            throw new IssuanceException(IssuanceException.INVALID_PROOF,
                    lastFailure != null ? lastFailure.getMessage() : "None of the submitted proofs passed validation", lastFailure);
        }
        if (command.maxCredentials() > 0 && holders.size() > command.maxCredentials()) {
            throw new IssuanceException(IssuanceException.INVALID_CREDENTIAL_REQUEST,
                    "The proofs bind " + holders.size() + " keys; batch_size is " + command.maxCredentials());
        }
        return holders;
    }

    private Issued issueOne(IssuanceCommand command, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        CredentialFormatter formatter = formatters.require(configuration.format());
        ClaimSet claims;
        switch (configuration.strategy()) {
            case EXTERNAL -> {
                ExternalIssuer issuer = required(externalIssuers, configuration.dataSourceId(), "external issuer");
                try {
                    return new Issued(issuer.issue(context, configuration, holder), null);
                } catch (DataSourceException e) {
                    throw new IssuanceException(e.getErrorCode(), e.getMessage(), e);
                }
            }
            case SUPPLIED -> {
                Map<String, Object> supplied = command.suppliedCredential().orElseThrow(() -> new IssuanceException(
                        IssuanceException.INVALID_CREDENTIAL_REQUEST, "Configuration " + configuration.id() + " expects a supplied credential"));
                claims = new ClaimSet(supplied, Map.of(PROVENANCE_SUPPLIED, Boolean.TRUE));
            }
            default -> {
                CredentialDataSource source = dataSource(configuration.dataSourceId());
                ClaimSet fetched;
                try {
                    fetched = source.fetch(context, configuration);
                } catch (DataSourceException e) {
                    throw new IssuanceException(e.getErrorCode(), e.getMessage(), e);
                }
                claims = render(fetched, configuration, context, holder);
            }
        }
        UnsignedCredential unsigned = build(formatter, claims, configuration, context, holder);
        if (configuration.status().isEnabled()) {
            StatusProvider status = statusProviders.stream()
                    .filter(p -> p.mechanism().equals(configuration.status().mechanism()) && p.supports(configuration.format()))
                    .findFirst().orElseThrow(() -> new IssuanceException(IssuanceException.ISSUANCE_FAILED,
                            "No status provider for " + configuration.status().mechanism() + " and format " + configuration.format()));
            unsigned = status.attach(unsigned, configuration, context);
        }
        for (IssuanceListener listener : listeners) {
            unsigned = listener.beforeSign(unsigned, configuration, context);
        }
        // a tenant with its own DID issues under it: the proof's verification method and the issuer must resolve together
        String tenantDid = context.tenant() == null ? null : context.tenant().issuerDid();
        SigningConfig signingConfig = tenantDid == null || tenantDid.isBlank() || tenantDid.equals(configuration.signing().issuerDid())
                ? configuration.signing() : configuration.signing().withIssuerDid(tenantDid);
        SigningContext signing = keyProviders.signingContext(signingConfig);
        try {
            return new Issued(formatter.sign(unsigned, signing, context), claims);
        } catch (FormatException e) {
            throw callerError(e);
        }
    }

    private static UnsignedCredential build(CredentialFormatter formatter, ClaimSet claims, CredentialConfiguration configuration,
                                            IssuanceContext context, HolderBinding holder) {
        try {
            return formatter.build(claims, configuration, context, holder);
        } catch (FormatException e) {
            throw callerError(e);
        }
    }

    /**
     * A formatter may find the caller's own input unusable — an mDoc device key it cannot encode, for instance. The
     * format names that with OpenID4VCI's {@code invalid_proof}, and this is where it becomes a protocol error instead of
     * a 500 (docs/design/20-mdl-issuer.md G6, OID4VCI 8.3.1).
     */
    private static RuntimeException callerError(FormatException e) {
        if (IssuanceException.INVALID_PROOF.equals(e.getErrorCode())) {
            return new IssuanceException(IssuanceException.INVALID_PROOF, e.getMessage(), e);
        }
        return e;
    }

    @Override
    public UnsignedCredential preview(CredentialConfiguration configuration, ClaimSet claims, IssuanceContext context, HolderBinding holder) {
        CredentialFormatter formatter = formatters.require(configuration.format());
        ClaimSet rendered = configuration.strategy() == io.mosip.certify.spi.IssuanceStrategy.TEMPLATE
                ? render(claims, configuration, context, holder) : claims;
        return formatter.build(rendered, configuration, context, holder);
    }

    private ClaimSet render(ClaimSet fetched, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        TemplateRef template = configuration.template();
        if (template.mode() == TemplateRef.Mode.NONE) {
            return fetched;
        }
        TemplateEngine engine = templateEngines.get(template.engine());
        if (engine == null) {
            throw new IssuanceException(IssuanceException.ISSUANCE_FAILED, "No template engine '" + template.engine()
                    + "' for configuration " + configuration.id());
        }
        Instant validFrom = context.now();
        TemplateEngine.Validity validity = new TemplateEngine.Validity(validFrom, validFrom.plus(defaultValidity));
        ClaimSet model = fetched;
        for (IssuanceListener listener : listeners) {
            model = listener.beforeRender(model, configuration, context, holder);
        }
        TemplateEngine.RenderedDocument rendered = engine.render(template,
                new TemplateEngine.TemplateModel(model, context.tenant(), holder, validity, configuration, template.params()));
        Map<String, Object> provenance = new HashMap<>(model.provenance());
        provenance.put(PROVENANCE_TEMPLATE_MODE, template.mode().name());
        return new ClaimSet(rendered.document(), provenance);
    }

    /**
     * The configuration's source: the id it names, else {@link #defaultDataSourceId}, else the only registered source.
     * The default id is the data-provider plugin's source, which the service always registers
     * ({@code DataProviderPluginDataSource} is a component and resolves the plugin lazily), so a default id no
     * provider registered only happens outside the service, with a bare core; it falls through so a single-source
     * deployment keeps issuing as it did before several sources could coexist.
     *
     * <p>The messages are the ones this method has always produced: they reach a client's
     * {@code error_description} through the compatibility and draft-13 surfaces, so changing them would change bytes
     * on the wire (CLAUDE.md rule 1).</p>
     */
    private CredentialDataSource dataSource(String configuredId) {
        if (configuredId != null) {
            CredentialDataSource found = dataSources.get(configuredId);
            if (found == null) {
                throw new IssuanceException(IssuanceException.ISSUANCE_FAILED, "No data source with id '" + configuredId + "'");
            }
            return found;
        }
        if (defaultDataSourceId != null) {
            CredentialDataSource fallback = dataSources.get(defaultDataSourceId);
            if (fallback != null) {
                return fallback;
            }
        }
        if (dataSources.size() == 1) {
            return dataSources.values().iterator().next();
        }
        throw new IssuanceException(IssuanceException.ISSUANCE_FAILED,
                dataSources.isEmpty() ? "No data source registered" : "Several data sources registered; the configuration must name one");
    }

    private static <T> T required(Map<String, T> byId, String id, String what) {
        if (id != null) {
            T found = byId.get(id);
            if (found == null) {
                throw new IssuanceException(IssuanceException.ISSUANCE_FAILED, "No " + what + " with id '" + id + "'");
            }
            return found;
        }
        if (byId.size() == 1) {
            return byId.values().iterator().next();
        }
        throw new IssuanceException(IssuanceException.ISSUANCE_FAILED,
                byId.isEmpty() ? "No " + what + " registered" : "Several " + what + "s registered; the configuration must name one");
    }

    private void notifyFailure(IssuanceContext context, CredentialConfiguration configuration, String errorCode, Throwable cause) {
        IssuanceListener.IssuanceFailure failure = new IssuanceListener.IssuanceFailure(context, configuration, errorCode, cause);
        listeners.forEach(l -> l.onFailed(failure));
    }
}
