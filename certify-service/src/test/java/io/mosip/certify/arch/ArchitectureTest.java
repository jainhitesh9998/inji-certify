package io.mosip.certify.arch;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.freeze.FreezingArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Dependency-direction rules of the target architecture (docs/design/05-target-architecture.md).
 *
 * Every rule is frozen: the violations that exist today are recorded under
 * src/test/resources/archunit/store and tolerated; any new violation fails the build.
 * A work package that removes violations must also shrink the store (delete the lines it fixed,
 * or re-run with -Darchunit.freeze.refreeze=true and review the diff).
 */
@AnalyzeClasses(packages = "io.mosip.certify", importOptions = ImportOption.DoNotIncludeTests.class)
public class ArchitectureTest {

    private static final String[] FRAMEWORK_PACKAGES_FORBIDDEN_IN_CORE = {
            "org.springframework.web..",
            "jakarta.servlet..",
            "jakarta.persistence..",
            "org.apache.velocity..",
            "com.danubetech..",
            "foundation.identity..",
            "io.mosip.kernel.."
    };

    /** certify-core must stay free of web, persistence, templating, JSON-LD and keymanager types. */
    @ArchTest
    static final ArchRule core_has_no_framework_dependencies = FreezingArchRule.freeze(
            noClasses().that().resideInAPackage("io.mosip.certify.core..")
                    .should().dependOnClassesThat().resideInAnyPackage(FRAMEWORK_PACKAGES_FORBIDDEN_IN_CORE)
                    .as("certify-core depends on no web, JPA, Velocity, danubetech or keymanager types")
                    .allowEmptyShould(true));

    /** The signing library must be usable from a CLI: no Spring Web, no JPA, no Velocity. */
    @ArchTest
    static final ArchRule signing_has_no_web_or_persistence = FreezingArchRule.freeze(
            noClasses().that().resideInAPackage("io.mosip.certify.signing..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "org.springframework.web..", "jakarta.servlet..", "jakarta.persistence..", "org.apache.velocity..")
                    .as("certify-signing depends on no web, JPA or Velocity types")
                    .allowEmptyShould(true));

    /** MOSIP keymanager is reached only through its key-provider module. */
    @ArchTest
    static final ArchRule keymanager_only_in_its_provider = FreezingArchRule.freeze(
            noClasses().that().resideOutsideOfPackage("io.mosip.certify.keyprovider.keymanager..")
                    .should().dependOnClassesThat().resideInAPackage("io.mosip.kernel..")
                    .as("io.mosip.kernel is referenced only from certify-keyprovider-keymanager")
                    .allowEmptyShould(true));

    /**
     * Format identifiers are decided inside formatter modules, not switched on elsewhere.
     * Note: VCFormats holds compile-time String constants, which javac inlines, so bytecode carries no
     * dependency on the class and this rule sees only non-inlined uses today. It becomes effective when
     * VCFormats is replaced by the formatter registry in Phase 1; it is kept here so the store already exists.
     */
    @ArchTest
    static final ArchRule format_constants_only_in_formatters = FreezingArchRule.freeze(
            noClasses().that().resideOutsideOfPackages(
                            "io.mosip.certify.spi..", "io.mosip.certify.format..", "io.mosip.certify.credential..",
                            "io.mosip.certify.core.constants..")
                    .should().dependOnClassesThat().haveFullyQualifiedName("io.mosip.certify.core.constants.VCFormats")
                    .as("VCFormats is referenced only from certify-spi and formatter modules")
                    .allowEmptyShould(true));

    /** Protocol adapters talk to services, never to repositories. */
    @ArchTest
    static final ArchRule controllers_do_not_touch_repositories = FreezingArchRule.freeze(
            noClasses().that().resideInAPackage("io.mosip.certify.controller..")
                    .should().dependOnClassesThat().resideInAnyPackage("io.mosip.certify.repository..", "io.mosip.certify.entity..")
                    .as("controllers do not depend on repositories or entities")
                    .allowEmptyShould(true));

    /** The template engine is a rendering component; configuration lookup belongs to the registry. */
    @ArchTest
    static final ArchRule template_engine_does_not_read_repositories = FreezingArchRule.freeze(
            noClasses().that().resideInAPackage("io.mosip.certify.vcformatters..")
                    .should().dependOnClassesThat().resideInAPackage("io.mosip.certify.repository..")
                    .as("template engines do not read repositories")
                    .allowEmptyShould(true));
}
