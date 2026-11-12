package io.mosip.certify.datasource.file;

import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Registers one {@link FileCredentialDataSource} bean per entry of {@code certify.datasource.file.sources}
 * (docs/design/20-mdl-issuer.md M-10). The wiring goes through Spring Boot auto-configuration and not a component scan
 * (CLAUDE.md rule 10), and with no entry it registers nothing, so the feature is off unless an operator configures a
 * file.
 */
@AutoConfiguration
@EnableConfigurationProperties(FileDataSourceProperties.class)
@Import(FileDataSourceAutoConfiguration.SourcesRegistrar.class)
public class FileDataSourceAutoConfiguration {

    /**
     * A bean definition cannot be declared per map entry statically, so the registrar binds the typed properties itself
     * and registers one definition whose supplier loads and validates that file when the bean is created, which is at
     * startup for a singleton.
     */
    static final class SourcesRegistrar implements ImportBeanDefinitionRegistrar, EnvironmentAware {

        private Environment environment;

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
            FileDataSourceProperties properties = Binder.get(environment)
                    .bindOrCreate(FileDataSourceProperties.PREFIX, FileDataSourceProperties.class);
            properties.sources().forEach((id, source) -> {
                GenericBeanDefinition definition = new GenericBeanDefinition();
                definition.setBeanClass(FileCredentialDataSource.class);
                definition.setInstanceSupplier(() -> new FileCredentialDataSource(id, source));
                registry.registerBeanDefinition(beanName(id), definition);
            });
        }

        static String beanName(String id) {
            return "fileCredentialDataSource." + id;
        }
    }
}
