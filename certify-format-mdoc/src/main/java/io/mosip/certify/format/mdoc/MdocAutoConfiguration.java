package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.signing.TrustAnchorRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers the mDoc formatter wherever this module is on the classpath (CLAUDE.md rule 10), with the DSC policy over
 * the application's {@link TrustAnchorRegistry} when one is registered (M-06).
 */
@AutoConfiguration
@EnableConfigurationProperties(MdocProperties.class)
public class MdocAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(MdocAutoConfiguration.class);

    /** The 1.0.0-beta.1 keys (certify-service {@code MDocConfig}) kept as aliases (CLAUDE.md rule 9). */
    static final String LEGACY_VALIDITY_YEARS = "mosip.certify.mdoc.validity-period-years";
    static final String LEGACY_DIGEST_ALGORITHM = "mosip.certify.mdoc.digest-algorithm";

    @Bean
    @ConditionalOnMissingBean(MdocFormatter.class)
    public MdocFormatter mdocFormatter(ObjectMapper objectMapper, MdocProperties properties, Environment environment,
                                       ObjectProvider<TrustAnchorRegistry> trustAnchors) {
        return new MdocFormatter(objectMapper, resolve(properties, Binder.get(environment)),
                dscPolicy(trustAnchors.getIfAvailable()));
    }

    /**
     * The DSC policy, and the one startup line that says whether its trust-anchor rules apply (decision log
     * 2026-11-13, refining D16): with no {@code mdoc-iaca} anchor configured, mDocs keep signing as they did before M-06.
     */
    static MdocDscPolicy dscPolicy(TrustAnchorRegistry registry) {
        MdocDscPolicy policy = new MdocDscPolicy(registry);
        if (policy.enforced()) {
            log.info("mso_mdoc DSC policy enforced on every surface: Document Signers must be issued by one of the IACAs {}",
                    registry.entries(TrustAnchorRegistry.MDOC_IACA).stream().map(TrustAnchorRegistry.Anchor::id).toList());
        } else {
            // INFO, not WARN: most deployments issue no mso_mdoc at all, and for them this is the expected state
            log.info("mso_mdoc DSC policy is not enforced: no IACA trust anchor is configured"
                    + " (certify.pki.trust-anchors.mdoc-iaca, or an x509-file iaca); mDocs are signed without checking"
                    + " the Document Signer against an IACA");
        }
        return policy;
    }

    /**
     * Applies the {@code mosip.certify.mdoc.*} aliases where the {@code certify.format.mdoc.*} key is unset and logs,
     * once, which key decided the validity span and the digest algorithm.
     */
    static MdocProperties resolve(MdocProperties bound, Binder binder) {
        Integer legacyYears = binder.bind(LEGACY_VALIDITY_YEARS, Integer.class).orElse(null);
        String legacyDigest = binder.bind(LEGACY_DIGEST_ALGORITHM, String.class).orElse(null);
        MdocProperties resolved = bound.withLegacyFallback(legacyYears, legacyDigest);
        String validitySource = bound.msoValidity() != null ? "certify.format.mdoc.mso-validity"
                : bound.validityPeriodYears() != null ? "certify.format.mdoc.validity-period-years (deprecated)"
                : legacyYears != null ? LEGACY_VALIDITY_YEARS + " (deprecated alias)"
                : "default P90D";
        String digestSource = bound.digestAlgorithmConfigured() ? "certify.format.mdoc.digest-algorithm"
                : legacyDigest != null ? LEGACY_DIGEST_ALGORITHM + " (deprecated alias)"
                : "default " + MdocProperties.DEFAULT_DIGEST_ALGORITHM;
        log.info("mso_mdoc formatter: MSO validity {} from {}; digest algorithm {} from {}",
                resolved.validity(), validitySource, resolved.digestAlgorithm(), digestSource);
        return resolved;
    }
}
