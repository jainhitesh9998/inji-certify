package io.mosip.certify.datasource.file;

import io.mosip.certify.spi.CredentialDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The auto-configuration registers one {@link CredentialDataSource} per configured file, and none without one (M-10). */
class FileDataSourceAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(FileDataSourceAutoConfiguration.class));

    @TempDir
    Path dir;

    private Path write(String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.writeString(file, content);
        return file;
    }

    @Test
    void registersNothingWhenNoSourceIsConfigured() {
        runner.run(context -> {
            assertNull(context.getStartupFailure(), () -> "unconfigured must be safe: " + context.getStartupFailure());
            assertTrue(context.getBeansOfType(CredentialDataSource.class).isEmpty());
            assertTrue(context.getBean(FileDataSourceProperties.class).sources().isEmpty());
        });
    }

    @Test
    void aSourceWithoutAPathFailsStartupWithTheKeyNamed() {
        runner.withPropertyValues("certify.datasource.file.sources.broken.key-claim=sub")
                .run(context -> {
                    assertNotNull(context.getStartupFailure(), "path is @NotNull: binding must refuse an entry without one");
                    StringBuilder messages = new StringBuilder();
                    for (Throwable t = context.getStartupFailure(); t != null; t = t.getCause()) {
                        messages.append(t.getMessage()).append(" | ");
                    }
                    assertTrue(messages.toString().contains("path"), messages.toString());
                });
    }

    @Test
    void registersOneDataSourcePerConfiguredFile() throws IOException {
        Path portraits = dir.resolve("img");
        Files.createDirectories(portraits);
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, 0x01, 0x02, (byte) 0xFF, (byte) 0xD9};
        Files.write(portraits.resolve("face.jpg"), jpeg);
        Path mdl = write("holders.json", """
                {"mdl-demo-1": {"given_name": "Asha", "portrait": "img/face.jpg"}}
                """);
        Path farmer = write("farmers.json", """
                {"2154189532": {"farmerName": "Demo Farmer"}}
                """);

        runner.withPropertyValues(
                        "certify.datasource.file.sources.mdl-demo.path=" + mdl,
                        "certify.datasource.file.sources.mdl-demo.binary-fields=portrait",
                        "certify.datasource.file.sources.farmer.path=" + farmer,
                        "certify.datasource.file.sources.farmer.key-claim=sub")
                .run(context -> {
                    assertNull(context.getStartupFailure(), () -> String.valueOf(context.getStartupFailure()));
                    Map<String, CredentialDataSource> beans = context.getBeansOfType(CredentialDataSource.class);
                    assertEquals(Set.of("mdl-demo", "farmer"),
                            beans.values().stream().map(CredentialDataSource::id).collect(Collectors.toSet()));

                    FileDataSourceProperties properties = context.getBean(FileDataSourceProperties.class);
                    assertEquals("sub", properties.sources().get("mdl-demo").keyClaim(), "the default key claim");
                    assertEquals(List.of("portrait"), properties.sources().get("mdl-demo").binaryFields());
                    assertEquals(List.of(), properties.sources().get("farmer").binaryFields());

                    CredentialDataSource demo = beans.get(FileDataSourceAutoConfiguration.SourcesRegistrar.beanName("mdl-demo"));
                    assertNotNull(demo);
                    assertEquals("Asha", demo.fetch(FileCredentialDataSourceTest.subject("mdl-demo-1"), null).get("given_name"));
                    assertEquals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(jpeg),
                            demo.fetch(FileCredentialDataSourceTest.subject("mdl-demo-1"), null).get("portrait"));
                });
    }

    @Test
    void aConfiguredFileThatCannotBeLoadedFailsTheContextWithTheFileNamed() {
        Path absent = dir.resolve("absent.json");
        runner.withPropertyValues("certify.datasource.file.sources.broken.path=" + absent)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    StringBuilder messages = new StringBuilder();
                    for (Throwable t = context.getStartupFailure(); t != null; t = t.getCause()) {
                        messages.append(t.getMessage()).append(" | ");
                    }
                    assertTrue(messages.toString().contains("absent.json"), messages.toString());
                });
    }

    @Test
    void theModuleIsWiredThroughSpringBootAutoConfiguration() throws IOException {
        try (InputStream imports = FileDataSourceAutoConfiguration.class.getResourceAsStream(
                "/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")) {
            assertNotNull(imports, "the imports file must ship in certify-service");
            List<String> classes = new String(imports.readAllBytes(), StandardCharsets.UTF_8).lines().map(String::trim).toList();
            assertTrue(classes.contains(FileDataSourceAutoConfiguration.class.getName()), classes.toString());
        }
    }
}
