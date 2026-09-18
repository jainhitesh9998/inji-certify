package io.mosip.certify.oid4vci;

import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.utils.CredentialUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The template model parameters the legacy issuance put in front of every Velocity template and the new engine does
 * not: {@code templateName} (the legacy lookup key), {@code didUrl}, {@code _doctype}, {@code vct}/{@code cnf}/{@code iss},
 * {@code credentialId} (when the id prefix is set), {@code rootContext} (a copy of the model) and {@code envConfigs}.
 * Existing templates that reference them render the same through the core. Runs first among the listeners.
 */
@Component
@Order(LegacyTemplateParamsListener.ORDER)
public class LegacyTemplateParamsListener implements IssuanceListener {

    public static final int ORDER = 10;
    static final String PARAM_ROOT_CONTEXT = "rootContext";
    static final String PARAM_ENV_CONFIGS = "envConfigs";
    static final String PARAM_DOCTYPE = "_doctype";
    static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN).withZone(ZoneOffset.UTC);

    private final VelocityEnvConfig velocityEnvConfig;
    private final String didUrl;
    private final String idPrefix;
    private final Duration validity;

    public LegacyTemplateParamsListener(VelocityEnvConfig velocityEnvConfig, Environment environment) {
        this.velocityEnvConfig = velocityEnvConfig;
        this.didUrl = environment.getProperty("mosip.certify.data-provider-plugin.did-url", "");
        this.idPrefix = environment.getProperty("mosip.certify.data-provider-plugin.id-field-prefix-uri", "");
        this.validity = Duration.parse(environment.getProperty("mosip.certify.data-provider-plugin.vc-expiry-duration", "P730D").toUpperCase());
    }

    @Override
    public ClaimSet beforeRender(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        if (configuration.template() == null || configuration.template().mode() == TemplateRef.Mode.NONE) {
            return claims;
        }
        Map<String, Object> raw = configuration.formatConfig() == null ? Map.of() : configuration.formatConfig().raw();
        Map<String, Object> params = new HashMap<>(claims.claims());
        params.put(Constants.TEMPLATE_NAME, templateName(configuration.format(), raw));
        params.put(Constants.DID_URL, didUrl);
        switch (configuration.format()) {
            case VCFormats.MSO_MDOC -> params.put(PARAM_DOCTYPE, raw.get("docType"));
            case VCFormats.DC_SD_JWT, "vc+sd-jwt" -> {
                params.put(Constants.VCTYPE, raw.get("vct"));
                if (holder != null && holder.isBound()) {
                    params.put(Constants.CONFIRMATION, Map.of("kid", holder.value()));
                }
                params.put(Constants.ISSUER, context.tenant() == null ? null : context.tenant().issuerIdentifier());
            }
            default -> {
                if (!idPrefix.isBlank()) {
                    params.put(VCDMConstants.CREDENTIAL_ID, idPrefix + UUID.randomUUID());
                }
            }
        }
        if (holder != null && holder.isBound()) {
            params.put(Constants._HOLDER_ID, holder.value());
        }
        String validFrom = TIMESTAMP.format(context.now());
        params.put(VCDM2Constants.VALID_FROM, validFrom);
        params.put(VCDM2Constants.VALID_UNTIL, TIMESTAMP.format(context.now().plus(validity)));
        params.put(PARAM_ROOT_CONTEXT, new HashMap<>(params));
        params.put(PARAM_ENV_CONFIGS, velocityEnvConfig.getEnvConfigs());
        return new ClaimSet(params, claims.provenance());
    }

    /** The legacy template key ({@code CredentialUtils.getTemplateName}) built from the configuration's own row. */
    static String templateName(String format, Map<String, Object> raw) {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(format);
        switch (format) {
            case VCFormats.MSO_MDOC -> request.setDoctype(String.valueOf(raw.get("docType")));
            case VCFormats.DC_SD_JWT, "vc+sd-jwt" -> {
                request.setFormat(VCFormats.DC_SD_JWT);
                request.setVct(String.valueOf(raw.get("vct")));
            }
            default -> {
                request.setContext(split(raw.get("context")));
                request.setType(split(raw.get("credentialType")));
            }
        }
        return CredentialUtils.getTemplateName(request);
    }

    private static List<String> split(Object commaSeparated) {
        return commaSeparated == null ? List.of() : Arrays.stream(commaSeparated.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
