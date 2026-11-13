package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.JwsHeaderPolicy;
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
import java.util.List;
import java.util.Map;

/**
 * {@code mso_mdoc}: the rendered document (docType, validityInfo, nameSpaces of IssuerSignedItems) becomes salted,
 * digested namespaces and a Mobile Security Object whose device key is the holder's; {@link #sign} produces the
 * IssuerAuth COSE_Sign1 (alg protected, x5chain unprotected, untagged) through the {@link SigningContext} and returns
 * the base64url CBOR IssuerSigned structure, exactly as the legacy path does. The key must carry a certificate chain
 * and the IssuerAuth always carries {@code x5chain} (9.1.2.4); see {@link #requireX5chain}.
 *
 * <p>The document type and the data model are checked here, before anything is signed: a template whose {@code docType}
 * differs from the configuration's {@code doctype} is a template error, and an {@code org.iso.18013.5.1.mDL} that
 * breaks ISO/IEC 18013-5 7.2.1 Table 5 is {@code mdoc_data_model_invalid}. {@code validityInfo} is finalised at signing
 * time (D7): the build step only prepares it for a preview.
 */
public class MdocFormatter implements CredentialFormatter {

    public static final String FORMAT = "mso_mdoc";
    static final String ATTRIBUTE_NAMESPACES = "taggedNamespaces";
    static final String ATTRIBUTE_ELEMENTS = "elementValues";
    static final String RAW_DOCTYPE = "docType";

    private final MdocProcessor processor;
    private final MdocProperties properties;
    private final ObjectMapper objectMapper;
    private final MdocDataModelValidator validator = new MdocDataModelValidator();

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
        Object doctype = copy.containsKey(RAW_DOCTYPE) ? copy.get(RAW_DOCTYPE) : copy.get("doctype");
        if (copy.get(MdocConstants.ELEMENT_TYPES) != null) {
            // refuse a malformed table, or one that would change a Table 5 element, when the row is saved
            MdocElementTypes.of(copy.get(MdocConstants.ELEMENT_TYPES), doctype == null ? null : String.valueOf(doctype));
        }
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
        MdocElementTypes elementTypes = MdocElementTypes.forConfig(configuration.formatConfig());
        Instant now = context == null ? Instant.now() : context.now();
        try {
            Map<String, Object> mDocJson = processor.processTemplatedJson(objectMapper.writeValueAsString(claims.claims()), params,
                    elementTypes, now);
            String templateDocType = String.valueOf(mDocJson.get("_docType"));
            if (!configuredDocType.equals(templateDocType)) {
                throw new FormatException(MdocConstants.ERROR_TEMPLATE, "The template's docType " + templateDocType
                        + " differs from the configuration's doctype " + configuredDocType);
            }
            Map<String, Map<String, Object>> elementValues = elementValues(mDocJson);
            validator.validate(configuredDocType, elementValues, now);
            // a preview has no signing key yet: the signing step replaces this with the finalised validity
            mDocJson.put(MdocConstants.VALIDITY_INFO, MdocProcessor.validityInfo(now, properties.validity(), null,
                    MdocDataModelValidator.documentExpiry(configuredDocType, elementValues)));

            Map<Object, Object> deviceKey = MdocCoseKey.fromHolder(holder == null ? null : holder.value(), objectMapper);
            Map<String, Object> salted = MdocProcessor.addRandomSalts(mDocJson);
            Map<String, Map<Integer, byte[]>> digests = new HashMap<>();
            // the encoded items, not COSE DataItems: the preview returns the attributes as JSON
            Map<String, List<byte[]>> encodedNamespaces = MdocProcessor.calculateDigests(salted, digests, properties.digestAlgorithm());
            Map<String, Object> mso = processor.createMobileSecurityObject(mDocJson, digests, deviceKey);
            return new UnsignedCredential(FORMAT, mso, Map.of(ATTRIBUTE_NAMESPACES, encodedNamespaces, ATTRIBUTE_ELEMENTS, elementValues));
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
            CertificateChain chain = signing.key().chain();
            CoseHeaderPolicy policy = signing.config().coseHeaders() == null ? CoseHeaderPolicy.mdocIssuerAuth()
                    : new CoseHeaderPolicy(signing.config().coseHeaders().x5chain(), null, false); // the configuration's x5chain choice
            requireX5chain(policy.x5chain(), chain);
            X509Certificate leaf = chain.leaf().orElseThrow();
            // 9.1.2.4: validityInfo is decided when the document is signed, and never outlives the DSC or the document
            Map<String, Object> mso = new HashMap<>(credential.asMap());
            String docType = String.valueOf(mso.get(MdocConstants.DOCTYPE));
            Map<String, Map<String, Object>> elementValues = (Map<String, Map<String, Object>>) credential.attributes()
                    .getOrDefault(ATTRIBUTE_ELEMENTS, Map.of());
            validator.validateAgainstCertificate(docType, elementValues, leaf);
            mso.put(MdocConstants.VALIDITY_INFO, MdocProcessor.validityInfo(now, properties.validity(),
                    leaf.getNotAfter().toInstant(), MdocDataModelValidator.documentExpiry(docType, elementValues)));

            byte[] msoCbor = MdocProcessor.encodeToTaggedCBOR(mso);
            try {
                io.mosip.certify.signing.CertificateChainPolicy.check(chain, now);
            } catch (io.mosip.certify.signing.SigningException e) {
                throw new FormatException(MdocConstants.ERROR_CHAIN, e.getMessage(), e);
            }
            byte[] issuerAuth = CoseEnvelope.sign1(msoCbor, policy, signing.key(), signing.signer());
            Map<String, List<byte[]>> encodedNamespaces = (Map<String, List<byte[]>>) credential.attributes()
                    .getOrDefault(ATTRIBUTE_NAMESPACES, Map.of());
            Map<String, Object> issuerSigned = MdocProcessor.createIssuerSignedStructure(
                    MdocProcessor.taggedNamespaces(encodedNamespaces), issuerAuth);
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(MdocProcessor.encodeToCBOR(issuerSigned));
            return new IssuedCredential(FORMAT, encoded, null, Map.of("docType", docType));
        } catch (FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new FormatException(MdocConstants.ERROR_SIGNING, "Could not sign the mDoc: " + e.getMessage(), e);
        }
    }

    /**
     * ISO/IEC 18013-5 9.1.2.4: the IssuerAuth's unprotected header carries {@code x5chain} (RFC 9360, label 33) with the
     * document signer certificate, and a verifier builds the path from it to the IACA it trusts. So the key must have a
     * chain, the configuration may not leave the chain out ({@code none}), may not cut it to the DSC alone ({@code leaf})
     * when intermediates stand between the DSC and the IACA, and may not carry the self-signed IACA ({@code full}; HAIP).
     * The signer itself may not be self-signed: {@code without-anchor} keeps a lone self-signed certificate, which no
     * Annex B Document Signer is.
     */
    static void requireX5chain(JwsHeaderPolicy.ChainInclusion inclusion, CertificateChain chain) {
        if (chain == null || chain.isEmpty()) {
            throw new FormatException(MdocConstants.ERROR_CHAIN, "the signing key has no certificate chain; ISO/IEC 18013-5"
                    + " 9.1.2.4 requires the IssuerAuth to carry the document signer certificate in x5chain (label 33)");
        }
        X509Certificate leaf = chain.leafFirst().get(0);
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            // a lone self-signed certificate survives without-anchor (nothing above it to drop), so the IssuerAuth would
            // carry a self-signed signer; an ISO/IEC 18013-5 Annex B Document Signer is always issued by an IACA
            throw new FormatException(MdocConstants.ERROR_CHAIN, "the signing certificate " + leaf.getSubjectX500Principal()
                    + " is self-signed; an ISO/IEC 18013-5 Annex B document signer certificate is issued by an IACA,"
                    + " so the key needs a DSC chain (docs/design/06a-x509-pki-and-mdoc.md)");
        }
        switch (inclusion) {
            case NONE -> throw new FormatException(MdocConstants.ERROR_CHAIN, "x5chain none would leave the IssuerAuth"
                    + " without the document signer certificate, which ISO/IEC 18013-5 9.1.2.4 requires; use without-anchor");
            case LEAF -> {
                if (chain.withoutAnchor().leafFirst().size() > 1) {
                    throw new FormatException(MdocConstants.ERROR_CHAIN, "x5chain leaf would drop the "
                            + (chain.withoutAnchor().leafFirst().size() - 1) + " intermediate certificate(s) between the"
                            + " document signer certificate and the IACA, so no verifier could build the path; use without-anchor");
                }
            }
            case FULL -> {
                X509Certificate root = chain.root().orElseThrow();
                if (root.getSubjectX500Principal().equals(root.getIssuerX500Principal())) {
                    // HAIP forbids carrying the trust anchor; the verifier must supply the IACA itself (D9, 9.1.2.4)
                    throw new FormatException(MdocConstants.ERROR_CHAIN, "x5chain FULL would carry the self-signed trust anchor "
                            + root.getSubjectX500Principal() + " in the IssuerAuth; an mDL carries at most the DSC and its"
                            + " intermediates (HAIP, without-anchor)");
                }
            }
            case WITHOUT_ANCHOR -> { }
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

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> elementValues(Map<String, Object> mDocJson) {
        Object values = mDocJson.get(MdocProcessor.ELEMENT_VALUES);
        return values instanceof Map<?, ?> map ? (Map<String, Map<String, Object>>) map : Map.of();
    }
}
