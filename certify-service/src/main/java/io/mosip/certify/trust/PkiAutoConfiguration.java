package io.mosip.certify.trust;

import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.keyprovider.x509file.X509FileAutoConfiguration;
import io.mosip.certify.keyprovider.x509file.X509FileKeyProviders;
import io.mosip.certify.keyprovider.x509file.X509FileProperties;
import io.mosip.certify.signing.TrustAnchorRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * The trust-anchor registry of M-06 through Spring Boot auto-configuration (CLAUDE.md rule 10): the
 * {@code certify.pki.trust-anchors.mdoc-iaca} files plus, when the x509-file provider is enabled, the IACAs it holds.
 * The registry is always registered; with no anchor it is empty, the mDoc DSC policy's trust-anchor rules do not apply
 * and nothing is published. In dev mode the last cRLNumber of each IACA's CRL is kept next to the x509-file keystore
 * ({@link CrlNumberStore#nextTo}), so CRL numbers keep increasing across restarts.
 */
@AutoConfiguration(after = X509FileAutoConfiguration.class)
@EnableConfigurationProperties(PkiProperties.class)
public class PkiAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(TrustAnchorRegistry.class)
    public FileTrustAnchorRegistry trustAnchorRegistry(PkiProperties properties, ObjectProvider<X509FileProperties> x509File,
                                                       ObjectProvider<JcaKeyProvider> jcaProviders,
                                                       ObjectProvider<MeterRegistry> meterRegistry) {
        // the x509-file provider is a JcaKeyProvider bean; asking for that type alone leaves keymanager uncreated here
        Optional<X509FileProperties> settings = Optional.ofNullable(x509File.getIfAvailable());
        Optional<JcaKeyProvider> provider = settings.flatMap(x509 -> jcaProviders.orderedStream()
                .filter(candidate -> candidate.id().equals(x509.id())).findFirst());
        List<X509Certificate> iacas = provider.map(X509FileKeyProviders::iacaCertificates).orElse(List.of());
        // dev mode holds the IACA key in the keystore, so it can issue the CRL its distribution point names (M-08)
        boolean devMode = provider.isPresent() && settings.get().devMode();
        FileTrustAnchorRegistry.DevCrlIssuer devCrls = provider.filter(p -> devMode)
                .<FileTrustAnchorRegistry.DevCrlIssuer>map(p -> p::issueEmptyCrl)
                .orElse(FileTrustAnchorRegistry.DevCrlIssuer.NONE);
        CrlNumberStore crlNumbers = devMode && settings.get().path() != null
                ? CrlNumberStore.file(CrlNumberStore.nextTo(settings.get().path())) : CrlNumberStore.inMemory();
        FileTrustAnchorRegistry registry = new FileTrustAnchorRegistry(properties, iacas, devCrls, crlNumbers, Clock.systemUTC());
        registry.bindMetrics(meterRegistry.getIfAvailable());
        registry.scheduleRefresh(properties.trustAnchors().crlRefreshInterval());
        return registry;
    }
}
