package io.mosip.certify.offer;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@code certify.offer-page.demo-subjects} is validated when it is bound (F-15): the operator's list is served to
 * anyone who opens the offer page, so a bad entry must stop startup with a message naming it rather than show a wrong
 * option, and the id is sent back as {@code request.subject}, so it may not carry spaces, slashes or markup.
 */
class OfferPageDemoSubjectsBindingTest {

    private static final String P = "certify.offer-page.demo-subjects";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class);

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(OfferPageProperties.class)
    static class PropertiesConfiguration {
    }

    /** Every message of the startup failure's cause chain, so the reason survives however the binder wraps it. */
    private static String failure(ApplicationContextRunner runner, String... properties) {
        String[] answer = new String[1];
        runner.withPropertyValues(properties).run(context -> {
            Throwable failure = context.getStartupFailure();
            assertNotNull(failure, () -> "the configuration must be refused: " + List.of(properties));
            StringBuilder messages = new StringBuilder();
            for (Throwable t = failure; t != null; t = t.getCause()) {
                messages.append(t.getMessage()).append(" | ");
            }
            answer[0] = messages.toString();
        });
        return answer[0];
    }

    private String refused(String expected, String... properties) {
        String messages = failure(runner, properties);
        assertTrue(messages.contains(expected), expected + " not in: " + messages);
        return messages;
    }

    @Test
    void aBlankIdIsRefused() {
        refused(P + "[0].id is required", P + "[0].id=");
        refused(P + "[1].id is required", P + "[0].id=mdl-demo-1", P + "[1].id=");
    }

    @Test
    void anIdThatCouldBeMarkupIsRefused() {
        assertTrue(refused(P + "[0].id", P + "[0].id=<script>alert(1)</script>").contains("<script>alert(1)</script>"),
                "the message quotes the refused id");
    }

    @Test
    void anIdWithASpaceOrASlashIsRefused() {
        refused(P + "[0].id 'mdl demo 1' must be", P + "[0].id=mdl demo 1");
        refused(P + "[0].id 'mdl/demo' must be", P + "[0].id=mdl/demo");
    }

    @Test
    void a129CharacterIdIsRefused() {
        String id = "a".repeat(129);
        refused(P + "[0].id is 129 characters long", P + "[0].id=" + id);
    }

    @Test
    void a128CharacterIdIsAccepted() {
        String id = "a".repeat(128);
        bound(P + "[0].id=" + id).demoSubjects().forEach(subject -> assertEquals(id, subject.id()));
    }

    @Test
    void a129CharacterLabelIsRefused() {
        String label = "a".repeat(129);
        refused(P + "[0].label is 129 characters long", P + "[0].id=mdl-demo-1", P + "[0].label=" + label);
    }

    @Test
    void aDuplicateIdIsRefused() {
        String messages = refused(P + "[1].id 'mdl-demo-1' repeats an earlier subject id",
                P + "[0].id=mdl-demo-1", P + "[1].id=mdl-demo-1");
        assertTrue(messages.contains(P + "[1].id"), "the message names the offending entry: " + messages);
    }

    @Test
    void fiftyOneSubjectsAreRefused() {
        List<String> properties = new ArrayList<>();
        for (int i = 0; i < OfferPageProperties.MAX_DEMO_SUBJECTS + 1; i++) {
            properties.add(P + "[" + i + "].id=mdl-demo-" + i);
        }
        String messages = failure(runner, properties.toArray(String[]::new));
        assertTrue(messages.contains("lists 51 subjects; at most 50 are allowed"), messages);
    }

    @Test
    void fiftySubjectsAreAccepted() {
        String[] properties = new String[OfferPageProperties.MAX_DEMO_SUBJECTS];
        for (int i = 0; i < properties.length; i++) {
            properties[i] = P + "[" + i + "].id=mdl-demo-" + i;
        }
        assertEquals(OfferPageProperties.MAX_DEMO_SUBJECTS, bound(properties).demoSubjects().size());
    }

    @Test
    void aLabelIsDisplayTextSoMarkupAndQuotesAreAllowed() {
        // allowed by configuration and served verbatim; the page assigns it with textContent, so it is never parsed
        OfferPageProperties properties = bound(P + "[0].id=mdl-demo-1",
                P + "[0].label=<b>Asha \"Demo\"</b><script>alert(1)</script>");
        assertEquals("<b>Asha \"Demo\"</b><script>alert(1)</script>", properties.demoSubjects().get(0).label());
        assertEquals("<b>Asha \"Demo\"</b><script>alert(1)</script>", properties.demoSubjects().get(0).labelOrId());
    }

    @Test
    void aMissingOrBlankLabelFallsBackToTheId() {
        OfferPageProperties properties = bound(P + "[0].id=mdl-demo-1", P + "[1].id=mdl-demo-2", P + "[1].label= ");
        assertEquals("mdl-demo-1", properties.demoSubjects().get(0).labelOrId());
        assertEquals("mdl-demo-2", properties.demoSubjects().get(1).labelOrId());
    }

    @Test
    void anEmptyConfigurationListAppliesToEveryConfiguration() {
        OfferPageProperties properties = bound(P + "[0].id=mdl-demo-1", P + "[0].credential-configuration-ids=");
        assertTrue(properties.demoSubjects().get(0).credentialConfigurationIds().isEmpty(),
                "an empty value is 'every configuration', not one blank configuration id");
    }

    @Test
    void unsetSubjectsAreAnEmptyListNotNull() {
        OfferPageProperties properties = bound();
        assertNotNull(properties.demoSubjects());
        assertTrue(properties.demoSubjects().isEmpty());
        assertFalse(properties.enabled(), "the page is still off unless it is switched on");
    }

    /**
     * The compose stack's demo wiring ({@code config/certify-mdl.properties}) is the one deployment that relies on the
     * dropdown: a typo there would stop the public demo at startup, so the shipped block is bound as it is written.
     */
    @Test
    void theComposeDemoWiringBindsAndNamesOnlyTheHoldersNames() throws IOException {
        Path file = Path.of("..", "docker-compose", "docker-compose-injistack", "config", "certify-mdl.properties");
        assumeTrue(Files.isRegularFile(file), "the compose configuration is part of this checkout");
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file)) {
            properties.load(reader);
        }
        List<String> values = new ArrayList<>();
        properties.stringPropertyNames().stream()
                .filter(name -> name.startsWith(P + "["))
                .sorted()
                .forEach(name -> values.add(name + "=" + properties.getProperty(name)));
        OfferPageProperties bound = bound(values.toArray(String[]::new));
        assertEquals(List.of("mdl-demo-1", "mdl-demo-2", "mdl-demo-3"),
                bound.demoSubjects().stream().map(OfferPageProperties.DemoSubject::id).toList());
        assertEquals(List.of("Asha Demo", "Ravi Demo", "Meera Test"),
                bound.demoSubjects().stream().map(OfferPageProperties.DemoSubject::labelOrId).toList());
        bound.demoSubjects().forEach(subject -> assertEquals(List.of("org.iso.18013.5.1.mDL"),
                subject.credentialConfigurationIds(), "the demo subjects are mDLs"));
    }

    private OfferPageProperties bound(String... properties) {
        List<Object> answer = new ArrayList<>();
        runner.withPropertyValues(properties).run(context -> {
            assertTrue(context.getStartupFailure() == null,
                    () -> "unexpected refusal: " + context.getStartupFailure());
            answer.add(context.getBean(OfferPageProperties.class));
        });
        return (OfferPageProperties) answer.get(0);
    }
}
