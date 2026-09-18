package io.mosip.certify.keyprovider.keymanager;

import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Owns everything Spring needs to run kernel-keymanager inside Certify: the component scan of the kernel packages
 * (the same list {@code CertifyServiceApplication} carried until P1-02), the JPA repositories and entities for
 * {@code key_alias}, {@code key_store} and {@code key_policy_def}, the {@link KeymanagerKeyProvider} bean and the
 * startup key provisioning. It is a Spring Boot auto-configuration (META-INF/spring/...AutoConfiguration.imports),
 * so any application with this module on the classpath gets keymanager wired, while test slices such as
 * {@code @WebMvcTest} and {@code @DataJpaTest} leave it out as they do every auto-configuration. Nothing else in
 * Certify names {@code io.mosip.kernel}.
 */
@AutoConfiguration(after = {HibernateJpaAutoConfiguration.class, JpaRepositoriesAutoConfiguration.class})
@EnableConfigurationProperties(KeymanagerProviderProperties.class)
@ComponentScan(basePackages = {
        "io.mosip.kernel.crypto",
        "io.mosip.kernel.keymanager.hsm",
        "io.mosip.kernel.cryptomanager",
        "io.mosip.kernel.keymanagerservice.validator",
        "io.mosip.kernel.keymanager",
        "io.mosip.kernel.cryptomanager.util",
        "io.mosip.kernel.keymanagerservice.helper",
        "io.mosip.kernel.keymanagerservice.repository",
        "io.mosip.kernel.keymanagerservice.service",
        "io.mosip.kernel.keymanagerservice.util",
        "io.mosip.kernel.keygenerator.bouncycastle",
        "io.mosip.kernel.signature.service",
        "io.mosip.kernel.signature.util",
        "io.mosip.kernel.signature.builder",
        "io.mosip.kernel.signature.*",
        "io.mosip.kernel.pdfgenerator.*",
        "io.mosip.kernel.partnercertservice.service",
        "io.mosip.kernel.keymanagerservice.entity",
        "io.mosip.kernel.partnercertservice.helper"
})
@EnableJpaRepositories(basePackages = "io.mosip.kernel.keymanagerservice.repository")
@EntityScan(basePackages = "io.mosip.kernel.keymanagerservice.entity")
public class KeymanagerKeyProviderConfiguration {

    // The three mosip.certify.* keys below are today's settings read where they were read before (AppConfig,
    // JwksServiceImpl); they keep their SpEL map form until the alias layer of 14-configuration.md replaces them.
    /** Today's {@code mosip.certify.signature-algo.key-alias-mapper} (JOSE name to {@code [appId, refId]} pairs) for the legacy listeners that still pick keys by it. */
    @Bean("legacyKeyAliasMapper")
    public Map<String, List<List<String>>> legacyKeyAliasMapper(@Value("#{${mosip.certify.signature-algo.key-alias-mapper:{}}}") Map<String, List<List<String>>> keyAliasMapper) {
        return keyAliasMapper == null ? Map.of() : keyAliasMapper;
    }

    @Bean
    public KeymanagerKeyProvider keymanagerKeyProvider(KeymanagerService keymanagerService, SignatureServicev2 signatureService,
                                                       KeymanagerProviderProperties properties,
                                                       @Value("#{${mosip.certify.signature-algo.key-alias-mapper:{}}}") Map<String, List<List<String>>> keyAliasMapper) {
        List<KeymanagerAlias> known = new ArrayList<>();
        known.add(new KeymanagerAlias(KeymanagerKeyInitializer.CERTIFY_SERVICE_APP_ID, ""));
        if (keyAliasMapper != null) {
            keyAliasMapper.values().forEach(pairs -> pairs.forEach(pair -> {
                KeymanagerAlias alias = new KeymanagerAlias(pair.get(0), pair.size() > 1 ? pair.get(1) : "");
                if (!known.contains(alias)) {
                    known.add(alias);
                }
            }));
        }
        return new KeymanagerKeyProvider(keymanagerService, signatureService, known, Clock.systemUTC(), properties.certificateCacheTtl());
    }

    @Bean
    public KeymanagerKeyInitializer keymanagerKeyInitializer(KeymanagerService keymanagerService, KeymanagerKeyProvider keyProvider,
                                                             @Value("${mosip.certify.cache.security.secretkey.reference-id:}") String cacheSecretKeyRefId,
                                                             @Value("${mosip.certify.plugin-mode:}") String pluginMode,
                                                             @Value("#{${mosip.certify.signature-algo.key-alias-mapper:{}}}") Map<String, List<List<String>>> keyAliasMapper) {
        return new KeymanagerKeyInitializer(keymanagerService, keyProvider, cacheSecretKeyRefId, pluginMode, keyAliasMapper);
    }
}
