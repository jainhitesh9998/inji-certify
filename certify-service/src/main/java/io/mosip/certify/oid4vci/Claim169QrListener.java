package io.mosip.certify.oid4vci;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.pixelpass.PixelPass;
import io.mosip.pixelpass.shared.ConstantsKt;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Claim-169 QR codes as the legacy issuance produced them: the configuration's {@code qrSettings} rendered against
 * the template model ({@code VCFormatter.formatQRData}), mapped by PixelPass, signed as a CWT with the configured QR
 * key ({@code Credential.signQRData}, same bytes as today) and handed to the template as {@code claim_169_values}.
 */
@Slf4j
@Component
@Order(Claim169QrListener.ORDER)
public class Claim169QrListener implements IssuanceListener {

    public static final int ORDER = 30;
    static final String PARAM_CLAIM_169_VALUES = "claim_169_values";

    private final VCFormatter vcFormatter;
    private final CredentialFactory credentialFactory;
    private final PixelPass pixelPass;
    private final Map<String, List<List<String>>> keyAliasMapper;
    private final String domainUrl;

    public Claim169QrListener(VCFormatter vcFormatter, CredentialFactory credentialFactory, @Qualifier("certifyPixelPass") PixelPass pixelPass,
                              @Qualifier("legacyKeyAliasMapper") Map<String, List<List<String>>> keyAliasMapper, Environment environment) {
        this.vcFormatter = vcFormatter;
        this.credentialFactory = credentialFactory;
        this.pixelPass = pixelPass;
        this.keyAliasMapper = keyAliasMapper;
        this.domainUrl = environment.getRequiredProperty("mosip.certify.domain.url");
    }

    @Override
    public ClaimSet beforeRender(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        if (configuration.template() == null || configuration.template().mode() == TemplateRef.Mode.NONE) {
            return claims;
        }
        Object qrSettings = configuration.formatConfig() == null ? null : configuration.formatConfig().raw().get("qrSettings");
        if (!(qrSettings instanceof List<?> settings) || settings.isEmpty()) {
            return claims;
        }
        Map<String, Object> params = new HashMap<>(claims.claims());
        String templateName = String.valueOf(params.get(Constants.TEMPLATE_NAME));
        JSONArray qrData = vcFormatter.formatQRData(new HashMap<>(params));
        List<String> signed = new ArrayList<>();
        if (qrData != null) {
            Credential credential = credentialFactory.getCredential(VCFormats.LDP_VC)
                    .orElseThrow(() -> new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "No credential signer for QR data"));
            for (int i = 0; i < qrData.length(); i++) {
                Object entry = qrData.get(i);
                if (!(entry instanceof JSONObject json)) {
                    throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Unsupported QR entry type: " + entry.getClass().getName());
                }
                String mapped = pixelPass.getMappedData(json, ConstantsKt.getCLAIM_169_KEY_MAPPER(), ConstantsKt.getCLAIM_169_VALUE_MAPPER(), true).toString();
                String[] signer = signer(templateName);
                String cwtHex = credential.signQRData(mapped, signer[0], signer[1], signer[2], domainUrl);
                if (cwtHex == null || cwtHex.isEmpty()) {
                    continue;
                }
                try {
                    signed.add(pixelPass.generateQRData(cwtHex, ""));
                } catch (Exception e) {
                    throw new CertifyException(ErrorConstants.QR_CBOR_ENCODING_ERROR, e.getMessage());
                }
            }
        }
        params.put(PARAM_CLAIM_169_VALUES, signed);
        return new ClaimSet(params, claims.provenance());
    }

    /** {algorithm, appId, refId}: the configuration's QR algorithm through the alias table, else the credential's own signer. */
    private String[] signer(String templateName) {
        String algorithm = vcFormatter.getQRSignatureAlgo(templateName);
        if (algorithm == null || algorithm.isEmpty()) {
            return new String[] {vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName)};
        }
        List<List<String>> pairs = keyAliasMapper.get(algorithm);
        if (pairs == null || pairs.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, "No key configuration found for QR signature algorithm: " + algorithm);
        }
        return new String[] {algorithm, pairs.get(0).get(0), pairs.get(0).get(pairs.get(0).size() - 1)};
    }
}
