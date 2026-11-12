package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code mso_mdoc}: the rendered document (docType, validityInfo, nameSpaces of IssuerSignedItems) becomes salted,
 * digested namespaces and a Mobile Security Object whose device key is the holder's; {@link #sign} produces the
 * IssuerAuth COSE_Sign1 (alg protected, x5chain unprotected, untagged) through the {@link SigningContext} and returns
 * the base64url CBOR IssuerSigned structure, exactly as the legacy path does.
 *
 * <p>The document type is checked here, before anything is signed: a template whose {@code docType} differs from the
 * configuration's {@code doctype} is a template error (ISO/IEC 18013-5 9.1.2.4). {@code validityInfo} is finalised at
 * signing time (decision D7): the build step only prepares it for a preview.
 */
public class MdocFormatter implements CredentialFormatter {

    public static final String FORMAT = "mso_mdoc";
    static final String ATTRIBUTE_NAMESPACES = "taggedNamespaces";
    static final String RAW_DOCTYPE = "docType";

    private final MdocProcessor processor;
    private final MdocProperties properties;
    private final ObjectMapper objectMapper;

    public MdocFormatter(ObjectMapper objectMapper, MdocProperties properties) {
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.processor = new MdocProcessor(objectMapper, properties);
    }

    @Override
    public String formatId() {
        return FORMAT;
    }

    @Override
    public FormatConfig parseConfig(Map<String, Object> raw) {
        Map<String, Object> copy = raw == null ? Map.of() : raw;
        MdocProcessor.digestAlgorithmName(properties.digestAlgorithm());
        return new FormatConfig.Generic(copy, String.valueOf(copy.get(RAW_DOCTYPE)));
    }

    @Override
    public Map<String, Object> metadataFragment(CredentialConfiguration configuration, ProtocolVersion version) {
        Map<String, Object> fragment = new LinkedHashMap<>();
        fragment.put("format", FORMAT);
        fragment.put("doctype", configuration.formatConfig() == null ? null : configuration.formatConfig().raw().get(RAW_DOCTYPE));
        return fragment;
    }

    @Override
    public UnsignedCredential build(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        Map<String, Object> params = new HashMap<>();
        if (configuration.signing() != null && configuration.signing().issuerDid() != null) {
            params.put(MdocConstants.DID_URL, configuration.signing().issuerDid());
        }
        if (holder != null && holder.isBound()) {
            params.put(MdocConstants._HOLDER_ID, holder.value());
        }
        String configuredDocType = configuredDocType(configuration);
        Instant now = context == null ? Instant.now() : context.now();
        try {
            Map<String, Object> mDocJson = processor.processTemplatedJson(objectMapper.writeValueAsString(claims.claims()), params, now);
            String templateDocType = String.valueOf(mDocJson.get("_docType"));
            if (!configuredDocType.equals(templateDocType)) {
                throw new FormatException(MdocConstants.ERROR_TEMPLATE, "The template's docType " + templateDocType
                        + " differs from the configuration's doctype " + configuredDocType);
            }
            // a preview has no signing key yet: the signing step replaces this with the finalised validity
            mDocJson.put(MdocConstants.VALIDITY_INFO, MdocProcessor.validityInfo(now, properties.validity(), null));

            Map<Object, Object> deviceKey = MdocCoseKey.fromHolder(holder == null ? null : holder.value(), objectMapper);
            Map<String, Object> salted = MdocProcessor.addRandomSalts(mDocJson);
            Map<String, Map<Integer, byte[]>> digests = new HashMap<>();
            Map<String, Object> taggedNamespaces = MdocProcessor.calculateDigests(salted, digests, properties.digestAlgorithm());
            Map<String, Object> mso = processor.createMobileSecurityObject(mDocJson, digests, deviceKey);
            return new UnsignedCredential(FORMAT, mso, Map.of(ATTRIBUTE_NAMESPACES, taggedNamespaces));
        } catch (FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new FormatException(MdocConstants.ERROR_TEMPLATE, "Could not build the mDoc: " + e.getMessage(), e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public IssuedCredential sign(UnsignedCredential credential, SigningContext signing, IssuanceContext context) {
        try {
            Instant now = context == null ? Instant.now() : context.now();
            X509Certificate leaf = signing.key().chain() == null ? null : signing.key().chain().leaf().orElse(null);
            // 9.1.2.4: validityInfo is decided when the document is signed, and never outlives the DSC
            Map<String, Object> mso = new HashMap<>(credential.asMap());
            mso.put(MdocConstants.VALIDITY_INFO,
                    MdocProcessor.validityInfo(now, properties.validity(), leaf == null ? null : leaf.getNotAfter().toInstant()));

            byte[] msoCbor = MdocProcessor.encodeToTaggedCBOR(mso);
            CoseHeaderPolicy policy = signing.config().coseHeaders() == null ? CoseHeaderPolicy.mdocIssuerAuth()
                    : new CoseHeaderPolicy(signing.config().coseHeaders().x5chain(), null, false); // the configuration's x5chain choice
            try {
                io.mosip.certify.signing.CertificateChainPolicy.check(signing.key().chain(), now);
            } catch (io.mosip.certify.signing.SigningException e) {
                throw new FormatException("certificate_chain_invalid", e.getMessage(), e);
            }
            byte[] issuerAuth = CoseEnvelope.sign1(msoCbor, policy, signing.key(), signing.signer());
            Map<String, Object> namespaces = (Map<String, Object>) credential.attributes().getOrDefault(ATTRIBUTE_NAMESPACES, Map.of());
            Map<String, Object> issuerSigned = MdocProcessor.createIssuerSignedStructure(namespaces, issuerAuth);
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(MdocProcessor.encodeToCBOR(issuerSigned));
            return new IssuedCredential(FORMAT, encoded, null, Map.of("docType", String.valueOf(mso.get(MdocConstants.DOCTYPE))));
        } catch (FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new FormatException(MdocConstants.ERROR_SIGNING, "Could not sign the mDoc: " + e.getMessage(), e);
        }
    }

    private static String configuredDocType(CredentialConfiguration configuration) {
        Object doctype = configuration.formatConfig() == null ? null : configuration.formatConfig().raw().get(RAW_DOCTYPE);
        if (doctype == null || String.valueOf(doctype).isBlank() || "null".equals(String.valueOf(doctype))) {
            throw new FormatException(MdocConstants.ERROR_TEMPLATE,
                    "the configuration carries no doctype for format " + FORMAT);
        }
        return String.valueOf(doctype);
    }
}
