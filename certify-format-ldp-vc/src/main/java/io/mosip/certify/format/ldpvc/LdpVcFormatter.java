package io.mosip.certify.format.ldpvc;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.signing.AlgorithmRegistry;
import io.mosip.certify.signing.LdLegacyEnvelope;
import io.mosip.certify.signing.SignerByteSigner;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.CredentialFormatter;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.UnsignedCredential;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * {@code ldp_vc}: the rendered document is the credential; {@link #sign} adds either a Data Integrity proof
 * (cryptosuites such as eddsa-rdfc-2022, ecdsa-rdfc-2019) or a legacy Linked Data suite proof (Ed25519Signature2020,
 * RsaSignature2018, ...), canonicalized with danubetech and signed through the {@link SigningContext}. The proof's
 * {@code created} is the credential's issuanceDate/validFrom, read as UTC.
 */
public class LdpVcFormatter implements CredentialFormatter {

    public static final String FORMAT = "ldp_vc";
    public static final String ERROR_UNSUPPORTED_SUITE = "unsupported_cryptosuite";
    public static final String ERROR_PROOF_FAILED = "ldp_proof_failed";
    static final String ASSERTION_METHOD = "assertionMethod";
    static final String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    static final Set<String> PROOF_VALUE_SUITES = Set.of("Ed25519Signature2020", "EcdsaSecp256r1Signature2019");
    static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private final DocumentLoader documentLoader;

    public LdpVcFormatter(DocumentLoader documentLoader) {
        this.documentLoader = documentLoader;
    }

    @Override
    public String formatId() {
        return FORMAT;
    }

    @Override
    public FormatConfig parseConfig(Map<String, Object> raw) {
        Map<String, Object> copy = raw == null ? Map.of() : raw;
        return new FormatConfig.Generic(copy, copy.get("context") + "|" + copy.get("credentialType"));
    }

    /** The issuer-metadata entry: format plus credential_definition (@context and type from the configuration). */
    @Override
    public Map<String, Object> metadataFragment(CredentialConfiguration configuration, ProtocolVersion version) {
        Map<String, Object> raw = configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
        Map<String, Object> definition = new LinkedHashMap<>();
        definition.put("@context", commaList(raw.get("context")));
        definition.put("type", commaList(raw.get("credentialType")));
        Map<String, Object> fragment = new LinkedHashMap<>();
        fragment.put("format", FORMAT);
        fragment.put("credential_definition", definition);
        return fragment;
    }

    @Override
    public UnsignedCredential build(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        return new UnsignedCredential(FORMAT, claims.claims(), Map.of());
    }

    @Override
    public IssuedCredential sign(UnsignedCredential credential, SigningContext signing, IssuanceContext context) {
        String suite = signing.config().cryptosuite();
        if (suite == null || suite.isBlank()) {
            throw new FormatException(ERROR_UNSUPPORTED_SUITE, "ldp_vc needs a cryptosuite or Linked Data suite in the signing configuration");
        }
        JsonLDObject jsonLd = JsonLDObject.fromJsonObject(new LinkedHashMap<>(credential.asMap()));
        jsonLd.setDocumentLoader(documentLoader);
        Date created = createdFrom(jsonLd, context.now());
        String issuer = signing.config().issuerDid() != null ? signing.config().issuerDid() : String.valueOf(jsonLd.getJsonObject().get("issuer"));
        URI verificationMethod = URI.create(issuer + "#" + signing.key().kid());
        try {
            if (AlgorithmRegistry.isDataIntegrityCryptosuite(suite)) {
                dataIntegrityProof(jsonLd, suite, created, verificationMethod, signing).addToJsonLDObject(jsonLd);
            } else if (AlgorithmRegistry.isLegacyLdSuite(suite)) {
                legacyProof(jsonLd, suite, created, verificationMethod, signing).addToJsonLDObject(jsonLd);
            } else {
                throw new FormatException(ERROR_UNSUPPORTED_SUITE, "Unknown Linked Data suite or cryptosuite " + suite);
            }
        } catch (FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new FormatException(ERROR_PROOF_FAILED, "Could not add the " + suite + " proof: " + e.getMessage(), e);
        }
        Object id = jsonLd.getJsonObject().get("id");
        return new IssuedCredential(FORMAT, jsonLd.getJsonObject(), id == null ? null : id.toString(), Map.of("suite", suite));
    }

    private DataIntegrityProof dataIntegrityProof(JsonLDObject jsonLd, String cryptosuite, Date created, URI verificationMethod, SigningContext signing) throws Exception {
        LdSigner<?> signer = LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(DATA_INTEGRITY_PROOF);
        signer.setSigner(new SignerByteSigner(signing.signer(), signing.key(), signing.key().algorithm()));
        signer.setCryptosuite(cryptosuite);
        DataIntegrityProof options = DataIntegrityProof.builder()
                .created(created).proofPurpose(ASSERTION_METHOD).cryptosuite(cryptosuite)
                .verificationMethod(verificationMethod).type(DATA_INTEGRITY_PROOF).build();
        DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> builder = DataIntegrityProof.builder().base(options).defaultContexts(false);
        signer.initialize(builder);
        DataIntegrityProof proofOptions = DataIntegrityProof.fromJson(options.toJson());
        if (proofOptions.getContexts() == null || proofOptions.getContexts().isEmpty()) {
            JsonLDUtils.jsonLdAdd(proofOptions, Keywords.CONTEXT, jsonLd.getContexts().stream().map(JsonLDUtils::uriToString).filter(Objects::nonNull).toList());
        }
        Canonicalizer canonicalizer = signer.getCanonicalizer(proofOptions);
        byte[] hash = canonicalizer.canonicalize(proofOptions, jsonLd);
        signer.sign(builder, hash);
        return builder.build();
    }

    private LdProof legacyProof(JsonLDObject jsonLd, String suite, Date created, URI verificationMethod, SigningContext signing) throws Exception {
        LdProof options = LdProof.builder().defaultContexts(false).defaultTypes(false).type(suite)
                .created(created).proofPurpose(ASSERTION_METHOD).verificationMethod(verificationMethod).build();
        byte[] hash = new URDNA2015Canonicalizer().canonicalize(options, jsonLd);
        LdProof.Builder<?> proof = LdProof.builder().base(options).defaultContexts(false);
        if (PROOF_VALUE_SUITES.contains(suite)) {
            proof.proofValue(LdLegacyEnvelope.proofValueBase58(hash, signing.key(), signing.signer()));
        } else {
            proof.jws(LdLegacyEnvelope.detachedJws(hash, signing.key(), signing.signer()));
        }
        return proof.build();
    }

    /** issuanceDate (VC 1.1) or validFrom (VC 2.0) as the proof's created, read as UTC; the issuance instant otherwise. */
    static Date createdFrom(JsonLDObject jsonLd, Instant now) {
        Object value = jsonLd.getJsonObject().containsKey("issuanceDate") ? jsonLd.getJsonObject().get("issuanceDate") : jsonLd.getJsonObject().get("validFrom");
        if (value != null) {
            try {
                return Date.from(Instant.from(TIMESTAMP.parse(value.toString())));
            } catch (DateTimeParseException e) {
                try {
                    return Date.from(Instant.parse(value.toString()));
                } catch (DateTimeParseException ignored) {
                    // fall through to the issuance instant
                }
            }
        }
        return Date.from(now == null ? Instant.now() : now);
    }

    static List<String> commaList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        if (value == null) {
            return List.of();
        }
        return Arrays.stream(value.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
