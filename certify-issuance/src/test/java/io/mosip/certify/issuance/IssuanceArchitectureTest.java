package io.mosip.certify.issuance;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/** The core and the SPI stay framework-free so the CLI, adapters and tests can embed them (05-target-architecture.md). */
class IssuanceArchitectureTest {

    private static final JavaClasses CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("io.mosip.certify.spi", "io.mosip.certify.issuance", "io.mosip.certify.signing");

    @Test
    void coreDoesNotDependOnFrameworks() {
        noClasses().that().resideInAnyPackage("io.mosip.certify.spi..", "io.mosip.certify.issuance..", "io.mosip.certify.signing..")
                .should().dependOnClassesThat().resideInAnyPackage(
                        "org.springframework..", "jakarta.servlet..", "jakarta.persistence..", "org.apache.velocity..",
                        "io.mosip.kernel..", "io.mosip.certify.core..", "io.mosip.certify.services..")
                .because("the issuance core must run in the CLI and in tests without Spring, JPA, Velocity or keymanager")
                .check(CLASSES);
    }
}
