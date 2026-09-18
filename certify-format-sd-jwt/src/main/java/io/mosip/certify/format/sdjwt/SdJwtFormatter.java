package io.mosip.certify.format.sdjwt;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.signing.JwsEnvelope;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code dc+sd-jwt} (alias {@code vc+sd-jwt}): the rendered document becomes the SD-JWT payload with {@code iss},
 * {@code vct} and {@code cnf}; the claims named by the configuration's {@code sdClaim} JSON paths are replaced by
 * {@code _sd} digests with matching disclosures; the issuer JWS carries {@code typ dc+sd-jwt}, {@code kid},
 * {@code x5c} and {@code x5t#S256} as today's issuance does. Output: {@code <jws>~<disclosure>~...~}.
 */
public class SdJwtFormatter implements CredentialFormatter {

    public static final String FORMAT = "dc+sd-jwt";
    public static final String ALIAS_VC_SD_JWT = "vc+sd-jwt";
    public static final String ERROR_SD_CLAIMS = "sd_claims_parse_error";
    public static final String ATTRIBUTE_DISCLOSURES = "disclosures";
    static final String RAW_VCT = "vct";
    static final String RAW_SD_CLAIM = "sdClaim";

    private final ObjectMapper objectMapper;

    public SdJwtFormatter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String formatId() {
        return FORMAT;
    }

    @Override
    public Set<String> aliases() {
        return Set.of(ALIAS_VC_SD_JWT);
    }

    @Override
    public FormatConfig parseConfig(Map<String, Object> raw) {
        Map<String, Object> copy = raw == null ? Map.of() : raw;
        return new FormatConfig.Generic(copy, String.valueOf(copy.get(RAW_VCT)));
    }

    @Override
    public Map<String, Object> metadataFragment(CredentialConfiguration configuration, ProtocolVersion version) {
        Map<String, Object> fragment = new LinkedHashMap<>();
        fragment.put("format", FORMAT);
        fragment.put("vct", raw(configuration).get(RAW_VCT));
        return fragment;
    }

    /** Payload with iss/vct/cnf, the SD paths digested; disclosures travel as an attribute until signing. */
    @Override
    public UnsignedCredential build(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        Map<String, Object> raw = raw(configuration);
        Map<String, Object> document = new LinkedHashMap<>(claims.claims());
        document.put("vct", raw.get(RAW_VCT));
        String issuer = context.tenant() == null ? null : context.tenant().issuerIdentifier();
        if (issuer != null) {
            document.put("iss", issuer);
        }
        if (holder != null && holder.isBound()) {
            document.put("cnf", Map.of("kid", holder.value()));
        }
        List<String> sdPaths = sdPaths(raw.get(RAW_SD_CLAIM));
        JsonNode node = objectMapper.valueToTree(document);
        for (String path : sdPaths) {
            if (!SdJsonUtils.isPathValid(node, path)) {
                throw new FormatException(ERROR_SD_CLAIMS, "SD-Claim path '" + path + "' not found in the credential");
            }
        }
        SDObjectBuilder builder = new SDObjectBuilder();
        List<Disclosure> disclosures = new ArrayList<>();
        SdJsonUtils.constructSDPayload(node, builder, disclosures, sdPaths, "$");
        List<String> encoded = disclosures.stream().map(Disclosure::getDisclosure).toList();
        return new UnsignedCredential(FORMAT, builder.build(), Map.of(ATTRIBUTE_DISCLOSURES, encoded));
    }

    @Override
    public IssuedCredential sign(UnsignedCredential credential, SigningContext signing, IssuanceContext context) {
        String payload;
        try {
            payload = objectMapper.writeValueAsString(credential.asMap());
        } catch (Exception e) {
            throw new FormatException(ERROR_SD_CLAIMS, "SD-JWT payload is not serializable: " + e.getMessage(), e);
        }
        String jws = JwsEnvelope.sign(payload, JwsHeaderPolicy.sdJwtVc(), signing.key(), signing.signer());
        @SuppressWarnings("unchecked")
        List<String> disclosures = (List<String>) credential.attributes().getOrDefault(ATTRIBUTE_DISCLOSURES, List.of());
        StringBuilder out = new StringBuilder(jws).append('~');
        for (String disclosure : disclosures) {
            out.append(disclosure).append('~');
        }
        return new IssuedCredential(FORMAT, out.toString(), null, credential.attributes());
    }

    private static Map<String, Object> raw(CredentialConfiguration configuration) {
        return configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
    }

    static List<String> sdPaths(Object sdClaim) {
        if (sdClaim == null || sdClaim.toString().isBlank()) {
            return List.of();
        }
        return Arrays.stream(sdClaim.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
