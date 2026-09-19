package io.mosip.certify.oid4vci;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.utils.CredentialUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * The render-method digest the legacy Velocity engine added for VC 2.0 templates when
 * {@code mosip.certify.data-provider-plugin.rendering-template-id} names an SVG template: {@code renderingTemplateId}
 * and {@code _renderMethodSVGdigest} (multibase SHA-256 of the SVG) in the template model.
 */
@Slf4j
@Component
@Order(RenderMethodDigestListener.ORDER)
public class RenderMethodDigestListener implements IssuanceListener {

    public static final int ORDER = 20;
    static final String PARAM_DIGEST = "_renderMethodSVGdigest";

    private final RenderingTemplateService renderingTemplateService;
    private final String renderingTemplateId;

    public RenderMethodDigestListener(RenderingTemplateService renderingTemplateService, Environment environment) {
        this.renderingTemplateService = renderingTemplateService;
        this.renderingTemplateId = environment.getProperty("mosip.certify.data-provider-plugin.rendering-template-id", "");
    }

    @Override
    public ClaimSet beforeRender(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder) {
        if (renderingTemplateId.isBlank() || configuration.template() == null || configuration.template().mode() == TemplateRef.Mode.NONE
                || !VCFormats.LDP_VC.equals(configuration.format())) {
            return claims;
        }
        Object contexts = configuration.formatConfig() == null ? null : configuration.formatConfig().raw().get("context");
        if (contexts == null || !contexts.toString().contains(VCDM2Constants.URL)) {
            return claims;
        }
        Map<String, Object> params = new HashMap<>(claims.claims());
        params.put(Constants.RENDERING_TEMPLATE_ID, renderingTemplateId);
        try {
            params.put(PARAM_DIGEST, CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(renderingTemplateId).getTemplate()));
        } catch (RenderingTemplateException e) {
            log.error("Template: {} not available in DB", renderingTemplateId, e);
        }
        return new ClaimSet(params, claims.provenance());
    }
}
