package io.mosip.certify.pki;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * certify-pki is a library an offline CLI and the issuance runtime both use, so it must not drag in a container, a web
 * stack, persistence, templating, JSON-LD or the MOSIP keymanager (docs/design/20-mdl-issuer.md M-04). The rule is not
 * frozen: the module starts clean and must stay clean.
 */
@AnalyzeClasses(packages = "io.mosip.certify.pki", importOptions = ImportOption.DoNotIncludeTests.class)
class PkiArchitectureTest {

    @ArchTest
    static final ArchRule pki_has_no_framework_dependencies = noClasses()
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..",
                    "jakarta.servlet..",
                    "jakarta.persistence..",
                    "org.apache.velocity..",
                    "com.danubetech..",
                    "foundation.identity..",
                    "io.mosip.kernel..")
            .as("certify-pki depends on no Spring, web, JPA, Velocity, JSON-LD or keymanager types")
            .allowEmptyShould(true);

    /**
     * BouncyCastle is used as an explicit provider instance; installing it globally would change the host JVM for every
     * other library in the process, so neither {@code addProvider} nor {@code insertProviderAt} may appear.
     */
    @ArchTest
    static final ArchRule pki_registers_no_global_provider = noClasses()
            .should().callMethod(java.security.Security.class, "addProvider", java.security.Provider.class)
            .orShould().callMethod(java.security.Security.class, "insertProviderAt",
                    java.security.Provider.class, int.class)
            .as("certify-pki installs no global JCA provider")
            .allowEmptyShould(true);
}
