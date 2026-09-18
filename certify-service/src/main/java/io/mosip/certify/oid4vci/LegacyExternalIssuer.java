package io.mosip.certify.oid4vci;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.ExternalIssuer;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The legacy {@code VCIssuancePlugin} (plugin mode {@code VCIssuance}: the plugin builds and signs the credential)
 * as the core's {@link ExternalIssuer}, with the calls and error codes of {@code VCIssuanceServiceImpl}: {@code ldp_vc}
 * through {@code getVerifiableCredentialWithLinkedDataProof}, {@code mso_mdoc} through {@code getVerifiableCredential},
 * any other format refused as unsupported; the token claims plus {@code accessTokenHash} are the identity details.
 */
@Component
public class LegacyExternalIssuer implements ExternalIssuer {

    public static final String ID = "vci-plugin";
    static final String CLAIM_ACCESS_TOKEN_HASH = "accessTokenHash";
    static final String ERROR_UNAVAILABLE = "vci_plugin_unavailable";

    private final ObjectProvider<VCIssuancePlugin> plugin;

    public LegacyExternalIssuer(ObjectProvider<VCIssuancePlugin> plugin) {
        this.plugin = plugin;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public IssuedCredential issue(IssuanceContext context, CredentialConfiguration configuration, HolderBinding holder) throws DataSourceException {
        VCIssuancePlugin vcIssuancePlugin = plugin.getIfAvailable();
        if (vcIssuancePlugin == null) {
            throw new DataSourceException(ERROR_UNAVAILABLE, "No VCIssuancePlugin is configured (plugin mode VCIssuance)");
        }
        Map<String, Object> raw = configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
        Map<String, Object> identity = new HashMap<>(context.authorization() == null ? Map.of() : context.authorization().claims());
        if (context.authorization() != null && context.authorization().tokenHash() != null) {
            identity.put(CLAIM_ACCESS_TOKEN_HASH, context.authorization().tokenHash());
        }
        String holderId = holder == null || !holder.isBound() ? null : holder.value();
        VCRequestDto request = new VCRequestDto();
        request.setFormat(configuration.format());
        VCResult<?> result;
        try {
            switch (configuration.format()) {
                case VCFormats.LDP_VC -> {
                    request.setContext(split(raw.get("context")));
                    request.setType(split(raw.get("credentialType")));
                    result = vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(request, holderId, identity);
                }
                case VCFormats.MSO_MDOC -> {
                    request.setDoctype(String.valueOf(raw.get("docType")));
                    result = vcIssuancePlugin.getVerifiableCredential(request, holderId, identity);
                }
                default -> throw new DataSourceException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, "Invalid or unsupported VC format requested.");
            }
        } catch (VCIExchangeException e) {
            throw new DataSourceException(e.getErrorCode(), e.getErrorCode(), e); // legacy: CertifyException(errorCode), message = code
        }
        if (result == null || result.getCredential() == null) {
            throw new DataSourceException(ErrorConstants.VC_ISSUANCE_FAILED, ErrorConstants.VC_ISSUANCE_FAILED);
        }
        Object credential = result.getCredential();
        if (credential instanceof JsonLDObject jsonLd) {
            Map<String, Object> document = jsonLd.getJsonObject();
            Object id = document.get("id");
            return new IssuedCredential(configuration.format(), document, id == null ? null : id.toString(), Map.of());
        }
        return new IssuedCredential(configuration.format(), credential, null, Map.of());
    }

    private static List<String> split(Object commaSeparated) {
        return commaSeparated == null ? List.of() : Arrays.stream(commaSeparated.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
