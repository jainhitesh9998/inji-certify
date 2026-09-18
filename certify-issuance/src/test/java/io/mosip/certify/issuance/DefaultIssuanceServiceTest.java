package io.mosip.certify.issuance;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import io.mosip.certify.issuance.IssuanceCommand.ConfigurationSelector;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialDataSource;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.ExternalIssuer;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;
import io.mosip.certify.spi.ProofValidator.NonceCheck;
import io.mosip.certify.spi.ProofValidator.ProofInput;
import io.mosip.certify.spi.ProofValidator.ProofPolicy;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.StatusConfig;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.TemplateEngine;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the full flow with fakes for every SPI and a real {@link JcaKeyProvider}; the produced JWS is verified
 * with Nimbus so the core is proven to hand formatters a usable signing context.
 */
class DefaultIssuanceServiceTest {

    static final Instant NOW = Instant.parse("2026-09-18T10:00:00Z");
    static final JcaKeyProvider JCA = JcaKeyProvider.devMode();
    static final KeyRef KEY = KeyRef.parse("jca:dev-es256");
    static final Authorization HOLDER_TOKEN = new Authorization("bearer", Map.of("scope", "farmer_vc other_vc", "client_id", "wallet"), "h");

    FakeDataSource dataSource;
    FakeFormatter formatter;
    FakeProofValidator proofValidator;
    RecordingListener listener;
    FakeStatusProvider statusProvider;
    FakeTemplateEngine templateEngine;
    InMemoryConfigurationRegistry registry;
    DefaultIssuanceService service;

    @BeforeEach
    void setUp() {
        dataSource = new FakeDataSource();
        formatter = new FakeFormatter();
        proofValidator = new FakeProofValidator();
        listener = new RecordingListener();
        statusProvider = new FakeStatusProvider();
        templateEngine = new FakeTemplateEngine();
        registry = new InMemoryConfigurationRegistry()
                .register(config("farmer", "farmer_vc", IssuanceStrategy.TEMPLATE, StatusConfig.NONE))
                .register(config("farmer-status", "farmer_vc", IssuanceStrategy.TEMPLATE, new StatusConfig("token-status-list", List.of("revocation"))))
                .register(config("supplied", "any", IssuanceStrategy.SUPPLIED, StatusConfig.NONE))
                .register(config("external", "farmer_vc", IssuanceStrategy.EXTERNAL, StatusConfig.NONE));
        service = new DefaultIssuanceService(registry, new FormatterRegistry(List.of(formatter)), new KeyProviderRegistry(List.of(JCA)),
                List.of(dataSource), List.of(new FakeExternalIssuer()), List.of(proofValidator), List.of(templateEngine),
                List.of(statusProvider), List.of(listener), AuthorizationPolicy.SCOPE, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(30));
    }

    /** The draft-13 selector is the configuration id in upper camel case, so each configuration stays uniquely selectable. */
    static CredentialConfiguration config(String id, String scope, IssuanceStrategy strategy, StatusConfig status) {
        String type = id.equals("farmer") ? "FarmerCredential" : id + "Credential";
        return new CredentialConfiguration(null, id, scope, "vc+jwt", new FormatConfig.Generic(Map.of("types", List.of(type)), type),
                TemplateRef.inline("fake", "{{claims}}", TemplateRef.Mode.FULL_DOCUMENT), SigningConfig.of(KEY, SignatureAlgorithm.ES256),
                strategy, null, status, null, null);
    }

    static IssuanceCommand.Builder command(String id) {
        return IssuanceCommand.builder(id).authorization(HOLDER_TOKEN).protocol(ProtocolVersion.OID4VCI_1_0)
                .proofs(List.of(new ProofInput("jwt", "proof-1"))).proofPolicy(new ProofPolicy(List.of("ES256"), "https://issuer", true, "wallet", Map.of()))
                .correlationId("corr-1");
    }

    @Test
    void templateStrategyRunsEveryStepInOrderAndSignsVerifiably() throws Exception {
        IssuanceResult result = service.issue(command("farmer").build());

        IssuanceResult.Issued issued = assertInstanceOf(IssuanceResult.Issued.class, result);
        assertEquals(1, issued.credentials().size());
        IssuedCredential credential = issued.credentials().get(0);
        assertEquals("vc+jwt", credential.format());

        JWSObject jws = JWSObject.parse((String) credential.credential());
        ECDSAVerifier verifier = new ECDSAVerifier((ECKey) JCA.resolve(KEY).descriptor().toJwk());
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(jws.verify(verifier), "credential must verify with the published key");
        Map<String, Object> payload = jws.getPayload().toJSONObject();
        assertEquals("did:key:holder", payload.get("sub"));
        assertEquals("rendered:Alice", payload.get("name"));
        assertEquals("FULL_DOCUMENT", ((Map<?, ?>) payload.get("provenance")).get(DefaultIssuanceService.PROVENANCE_TEMPLATE_MODE));

        assertEquals(List.of("proof", "fetch", "render", "build", "beforeSign", "sign", "onIssued"), Trace.STEPS);
        assertEquals("farmer", listener.issued.configuration().id());
        assertEquals(issued.transactionId(), listener.issued.transactionId());
        assertEquals(TenantContext.DEFAULT_TENANT_ID, dataSource.context.tenant().tenantId());
        assertEquals(NOW, dataSource.context.now());
        assertEquals("corr-1", dataSource.context.correlationId());
        assertEquals(HolderBinding.Kind.DID, dataSource.context.holders().get(0).kind());
        assertEquals(NOW.plus(Duration.ofDays(30)), templateEngine.model.validity().validUntil());
    }

    @Test
    void draft13SelectorResolvesByFormatAndType() {
        IssuanceCommand cmd = command(null).credentialConfigurationId(null).selector(new ConfigurationSelector("vc+jwt", "FarmerCredential")).build();

        IssuanceResult result = service.issue(cmd);

        assertInstanceOf(IssuanceResult.Issued.class, result);
        assertEquals("farmer", listener.issued.configuration().id());
    }

    @Test
    void unknownSelectorIsUnsupportedCredentialType() {
        IssuanceCommand cmd = command(null).credentialConfigurationId(null).selector(new ConfigurationSelector("vc+jwt", "Nope")).build();

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(cmd));

        assertEquals(IssuanceException.UNSUPPORTED_CREDENTIAL_TYPE, e.getErrorCode());
        assertTrue(listener.failures.isEmpty(), "no configuration resolved, so nothing to report against");
    }

    @Test
    void ambiguousSelectorIsAConfigurationError() {
        registry.register(config("farmer-twin", "farmer_vc", IssuanceStrategy.TEMPLATE, StatusConfig.NONE));
        registry.register(new CredentialConfiguration(null, "farmer-twin", "farmer_vc", "vc+jwt",
                new FormatConfig.Generic(Map.of(), "FarmerCredential"), null, SigningConfig.of(KEY, SignatureAlgorithm.ES256), null, null, null, null, null));
        IssuanceCommand cmd = command(null).credentialConfigurationId(null).selector(new ConfigurationSelector("vc+jwt", "FarmerCredential")).build();

        assertThrows(IllegalStateException.class, () -> service.issue(cmd));
    }

    @Test
    void unknownIdIsInvalidCredentialRequest() {
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("missing").build()));
        assertEquals(IssuanceException.INVALID_CREDENTIAL_REQUEST, e.getErrorCode());
    }

    @Test
    void scopeMismatchIsInvalidScopeAndNothingRuns() {
        Authorization wrong = new Authorization("bearer", Map.of("scope", "some_other"), "h");

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").authorization(wrong).build()));

        assertEquals(IssuanceException.INVALID_SCOPE, e.getErrorCode());
        assertTrue(Trace.STEPS.isEmpty());
        assertEquals(IssuanceException.INVALID_SCOPE, listener.failures.get(0).errorCode(), "refusals are audited too");
    }

    @Test
    void missingTokenIsInvalidToken() {
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").authorization(Authorization.NONE).build()));
        assertEquals(IssuanceException.NOT_AUTHENTICATED, e.getErrorCode());
    }

    @Test
    void invalidProofFailsBeforeDataIsFetched() {
        proofValidator.failWith = new ProofValidationException(IssuanceException.INVALID_PROOF, "bad signature");

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").build()));

        assertEquals(IssuanceException.INVALID_PROOF, e.getErrorCode());
        assertEquals("bad signature", e.getMessage());
        assertEquals(List.of("proof"), Trace.STEPS);
        assertEquals(IssuanceException.INVALID_PROOF, listener.failures.get(0).errorCode());
    }

    @Test
    void invalidNonceIsReportedAsSuchEvenWhenAnotherProofWouldPass() {
        proofValidator.nonceFailure = true;
        IssuanceCommand cmd = command("farmer").proofs(List.of(new ProofInput("jwt", "stale"), new ProofInput("jwt", "proof-1"))).build();

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(cmd));

        assertEquals(IssuanceException.INVALID_NONCE, e.getErrorCode());
    }

    @Test
    void unknownProofTypeIsInvalidProof() {
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> service.issue(command("farmer").proofs(List.of(new ProofInput("cwt", "x"))).build()));
        assertEquals(IssuanceException.INVALID_PROOF, e.getErrorCode());
    }

    @Test
    void missingProofOnHolderBoundConfigurationIsInvalidProof() {
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").proofs(List.of()).build()));
        assertEquals(IssuanceException.INVALID_PROOF, e.getErrorCode());
    }

    @Test
    void oneCredentialPerValidProof() {
        IssuanceCommand cmd = command("farmer").proofs(List.of(new ProofInput("jwt", "proof-1"), new ProofInput("jwt", "proof-2"))).build();

        IssuanceResult.Issued issued = assertInstanceOf(IssuanceResult.Issued.class, service.issue(cmd));

        assertEquals(2, issued.credentials().size());
        assertEquals(2, formatter.holders.size());
        assertEquals(Set.of("did:key:holder", "did:key:holder2"), Set.copyOf(formatter.holders.stream().map(HolderBinding::value).toList()));
        assertEquals(2, listener.issued.credentials().size());
    }

    @Test
    void statusIsAttachedBetweenBuildAndListeners() {
        service.issue(command("farmer-status").build());

        assertEquals(List.of("proof", "fetch", "render", "build", "status", "beforeSign", "sign", "onIssued"), Trace.STEPS);
        assertEquals("farmer-status", statusProvider.configuration.id());
        assertNotNull(formatter.signed.attributes().get("status"));
    }

    @Test
    void statusMechanismWithoutProviderFails() {
        registry.register(config("no-status", "farmer_vc", IssuanceStrategy.TEMPLATE, new StatusConfig("bitstring", List.of("revocation"))));

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("no-status").build()));

        assertEquals(IssuanceException.ISSUANCE_FAILED, e.getErrorCode());
        assertEquals(1, listener.failures.size());
    }

    @Test
    void suppliedStrategySkipsDataSourceAndTemplateAndNeedsNoTokenOffWire() {
        Map<String, Object> document = Map.of("name", "Supplied");
        IssuanceCommand cmd = IssuanceCommand.builder("supplied").suppliedCredential(document).protocol(ProtocolVersion.NONE).build();

        IssuanceResult.Issued issued = assertInstanceOf(IssuanceResult.Issued.class, service.issue(cmd));

        assertEquals(List.of("build", "beforeSign", "sign", "onIssued"), Trace.STEPS);
        assertEquals(Boolean.TRUE, listener.issued.claims().provenance().get(DefaultIssuanceService.PROVENANCE_SUPPLIED));
        assertEquals(HolderBinding.NONE, formatter.holders.get(0));
        assertEquals(1, issued.credentials().size());
    }

    @Test
    void suppliedStrategyOverOid4vciStillNeedsAToken() {
        IssuanceCommand cmd = IssuanceCommand.builder("supplied").suppliedCredential(Map.of()).protocol(ProtocolVersion.OID4VCI_1_0).build();
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(cmd));
        assertEquals(IssuanceException.NOT_AUTHENTICATED, e.getErrorCode());
    }

    @Test
    void suppliedStrategyWithoutDocumentIsInvalidRequest() {
        IssuanceCommand cmd = IssuanceCommand.builder("supplied").build();
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(cmd));
        assertEquals(IssuanceException.INVALID_CREDENTIAL_REQUEST, e.getErrorCode());
    }

    @Test
    void externalStrategyDelegatesWholeCredential() {
        IssuanceResult.Issued issued = assertInstanceOf(IssuanceResult.Issued.class, service.issue(command("external").build()));

        assertEquals(List.of("proof", "external", "onIssued"), Trace.STEPS);
        assertEquals("external-credential", issued.credentials().get(0).credential());
    }

    @Test
    void dataSourceErrorsKeepTheirCodeAndAreReported() {
        dataSource.failWith = new DataSourceException("record_not_found", "no such farmer");

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").build()));

        assertEquals("record_not_found", e.getErrorCode());
        assertEquals("record_not_found", listener.failures.get(0).errorCode());
        assertEquals(List.of("proof", "fetch"), Trace.STEPS);
    }

    @Test
    void unexpectedFailuresBecomeIssuanceFailed() {
        formatter.explode = true;

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("farmer").build()));

        assertEquals(IssuanceException.ISSUANCE_FAILED, e.getErrorCode());
        assertInstanceOf(IllegalStateException.class, e.getCause());
        assertEquals(IssuanceException.ISSUANCE_FAILED, listener.failures.get(0).errorCode());
    }

    @Test
    void unknownFormatIsUnsupportedFormat() {
        registry.register(new CredentialConfiguration(null, "mdoc", "farmer_vc", "mso_mdoc", null, null, SigningConfig.of(KEY, SignatureAlgorithm.ES256),
                IssuanceStrategy.TEMPLATE, null, null, null, null));
        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("mdoc").build()));
        assertEquals(IssuanceException.UNSUPPORTED_CREDENTIAL_FORMAT, e.getErrorCode());
    }

    @Test
    void unknownKeyProviderFails() {
        registry.register(config("hsm", "farmer_vc", IssuanceStrategy.TEMPLATE, StatusConfig.NONE));
        CredentialConfiguration hsm = registry.byId("default", "hsm").orElseThrow();
        registry.register(new CredentialConfiguration(null, "hsm", "farmer_vc", "vc+jwt", hsm.formatConfig(), hsm.template(),
                SigningConfig.of(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_ED25519"), SignatureAlgorithm.EdDSA), IssuanceStrategy.TEMPLATE, null, null, null, null));

        IssuanceException e = assertThrows(IssuanceException.class, () -> service.issue(command("hsm").build()));

        assertEquals(IssuanceException.ISSUANCE_FAILED, e.getErrorCode());
        assertTrue(e.getMessage().contains("keymanager"));
    }

    @Test
    void tenantIsolationInRegistry() {
        registry.register(new CredentialConfiguration("acme", "farmer", "farmer_vc", "vc+jwt", null, null, SigningConfig.of(KEY, SignatureAlgorithm.ES256),
                IssuanceStrategy.TEMPLATE, null, null, null, null));
        IssuanceCommand cmd = command("farmer").tenant(new TenantContext("acme", "https://acme", null, "acme")).build();

        service.issue(cmd);

        assertEquals("acme", dataSource.context.tenant().tenantId());
        assertEquals("acme", listener.issued.configuration().tenantId());
        assertEquals(List.of("proof", "fetch", "build", "beforeSign", "sign", "onIssued"), Trace.STEPS, "no template on the acme configuration");
    }

    // ---- fakes -------------------------------------------------------------------------------------------------

    static final class Trace {
        static final List<String> STEPS = new ArrayList<>();
        static void step(String name) { STEPS.add(name); }
    }

    @BeforeEach
    void clearTrace() { Trace.STEPS.clear(); }

    static final class FakeDataSource implements CredentialDataSource {
        IssuanceContext context;
        DataSourceException failWith;

        public String id() { return "fake"; }

        public ClaimSet fetch(IssuanceContext context, CredentialConfiguration configuration) throws DataSourceException {
            Trace.step("fetch");
            this.context = context;
            if (failWith != null) throw failWith;
            return ClaimSet.of(Map.of("name", "Alice"));
        }
    }

    static final class FakeExternalIssuer implements ExternalIssuer {
        public String id() { return "ext"; }

        public IssuedCredential issue(IssuanceContext context, CredentialConfiguration configuration, HolderBinding holder) {
            Trace.step("external");
            return new IssuedCredential(configuration.format(), "external-credential", null, Map.of());
        }
    }

    static final class FakeProofValidator implements ProofValidator {
        ProofValidationException failWith;
        boolean nonceFailure;

        public String proofType() { return "jwt"; }

        public HolderBinding validate(ProofInput proof, ProofPolicy policy, NonceCheck nonce, IssuanceContext context) throws ProofValidationException {
            Trace.step("proof");
            if (failWith != null) throw failWith;
            if (nonceFailure && "stale".equals(proof.value())) {
                throw new ProofValidationException(IssuanceException.INVALID_NONCE, "nonce expired");
            }
            return HolderBinding.did("proof-2".equals(proof.value()) ? "did:key:holder2" : "did:key:holder", "jwt");
        }
    }

    static final class FakeTemplateEngine implements TemplateEngine {
        TemplateModel model;

        public String id() { return "fake"; }

        public Set<TemplateRef.Mode> modes() { return Set.of(TemplateRef.Mode.FULL_DOCUMENT); }

        public RenderedDocument render(TemplateRef template, TemplateModel model) {
            Trace.step("render");
            this.model = model;
            return new RenderedDocument(Map.of("name", "rendered:" + model.claims().get("name")));
        }
    }

    static final class FakeStatusProvider implements StatusProvider {
        CredentialConfiguration configuration;

        public String mechanism() { return "token-status-list"; }

        public boolean supports(String format) { return true; }

        public UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
            Trace.step("status");
            this.configuration = configuration;
            return credential.withAttribute("status", "list#1");
        }

        public void update(StatusUpdate update) {}
    }

    static final class RecordingListener implements IssuanceListener {
        IssuanceEvent issued;
        final List<IssuanceFailure> failures = new ArrayList<>();

        public UnsignedCredential beforeSign(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
            Trace.step("beforeSign");
            return credential;
        }

        public void onIssued(IssuanceEvent event) {
            Trace.step("onIssued");
            issued = event;
        }

        public void onFailed(IssuanceFailure failure) { failures.add(failure); }
    }

    /** A JWT-VC-shaped formatter: claims + holder into a payload, then a compact JWS through the signing context. */
    static final class FakeFormatter implements CredentialFormatter {
        final List<HolderBinding> holders = new ArrayList<>();
        IssuedCredential signed;
        boolean explode;

        public String formatId() { return "vc+jwt"; }

        public Set<String> aliases() { return Set.of("jwt_vc_json"); }

        public FormatConfig parseConfig(Map<String, Object> raw) { return new FormatConfig.Generic(raw, null); }

        public Map<String, Object> metadataFragment(CredentialConfiguration configuration, ProtocolVersion version) { return Map.of(); }

        public UnsignedCredential build(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
            Trace.step("build");
            if (explode) throw new IllegalStateException("boom");
            holders.add(holder);
            Map<String, Object> payload = new LinkedHashMap<>(claims.claims());
            payload.put("sub", holder.value());
            payload.put("provenance", claims.provenance());
            return new UnsignedCredential(formatId(), payload, Map.of());
        }

        public IssuedCredential sign(UnsignedCredential credential, SigningContext signing, IssuanceContext context) {
            Trace.step("sign");
            String json = toJson(credential.asMap());
            String jws = JwsEnvelope.sign(json, JwsHeaderPolicy.compact("JWT"), signing.key(), signing.signer());
            signed = new IssuedCredential(formatId(), jws, null, credential.attributes());
            return signed;
        }

        private static String toJson(Map<String, Object> map) {
            StringBuilder sb = new StringBuilder("{");
            map.forEach((k, v) -> {
                if (sb.length() > 1) sb.append(',');
                sb.append('"').append(k).append("\":");
                if (v instanceof Map<?, ?> m) {
                    @SuppressWarnings("unchecked") Map<String, Object> nested = (Map<String, Object>) m;
                    sb.append(toJson(nested));
                } else if (v == null) {
                    sb.append("null");
                } else {
                    sb.append('"').append(v).append('"');
                }
            });
            return sb.append('}').toString();
        }
    }
}
